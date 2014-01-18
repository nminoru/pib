/*
 * pib_easy_sw.c - Easy switch (Pseudo IBA switch to connect all ports of local host only)
 *
 * Copyright (c) 2013,2014 Minoru NAKAMURA <nminoru@nminoru.jp>
 *
 * This code is licenced under the GPL version 2 or BSD license.
 */
#include <linux/module.h>
#include <linux/init.h>
#include <linux/vmalloc.h>
#include <linux/kthread.h>
#include <net/sock.h> /* for struct sock */

#include <rdma/ib_mad.h>
#include <rdma/ib_smi.h>
#include <rdma/ib_sa.h>

#include "pib.h"
#include "pib_mad.h"


static int kthread_routine(void *data);

static int create_socket(struct pib_easy_sw *sw);
static void release_socket(struct pib_easy_sw *sw);
static void sock_data_ready_callback(struct sock *sk, int bytes);
static int process_incoming_message(struct pib_easy_sw *sw);
static int process_smp(struct ib_smp *smp, struct pib_easy_sw *sw, u8 in_port_num);
static int process_smp_get_method(struct ib_smp *smp, struct pib_easy_sw *sw, u8 in_port_num);
static int process_smp_set_method(struct ib_smp *smp, struct pib_easy_sw *sw, u8 in_port_num);
static int subn_get_nodedescription(struct ib_smp *smp, struct pib_easy_sw *sw, u8 in_port_num);
static int subn_get_nodeinfo(struct ib_smp *smp, struct pib_easy_sw *sw, u8 in_port_num);
static int subn_get_switchinfo(struct ib_smp *smp, struct pib_easy_sw *sw, u8 in_port_num);
static int subn_set_switchinfo(struct ib_smp *smp, struct pib_easy_sw *sw, u8 in_port_num);
static int subn_get_guidinfo(struct ib_smp *smp, struct pib_easy_sw *sw, u8 in_port_num);
static int subn_set_guidinfo(struct ib_smp *smp, struct pib_easy_sw *sw, u8 in_port_num);
static int subn_get_portinfo(struct ib_smp *smp, struct pib_easy_sw *sw, u8 in_port_num);
static int subn_set_portinfo(struct ib_smp *smp, struct pib_easy_sw *sw, u8 in_port_num);
static int subn_get_pkey_table(struct ib_smp *smp, struct pib_easy_sw *sw, u8 in_port_num);
static int subn_set_pkey_table(struct ib_smp *smp, struct pib_easy_sw *sw, u8 in_port_num);
static int subn_get_sl_to_vl_table(struct ib_smp *smp, struct pib_easy_sw *sw, u8 in_port_num);
static int subn_set_sl_to_vl_table(struct ib_smp *smp, struct pib_easy_sw *sw, u8 in_port_num);
static int subn_get_vl_arb_table(struct ib_smp *smp, struct pib_easy_sw *sw, u8 in_port_num);
static int subn_set_vl_arb_table(struct ib_smp *smp, struct pib_easy_sw *sw, u8 in_port_num);
static int subn_get_linear_forward_table(struct ib_smp *smp, struct pib_easy_sw *sw, u8 in_port_num);
static int subn_set_linear_forward_table(struct ib_smp *smp, struct pib_easy_sw *sw, u8 in_port_num);
static int subn_get_random_forward_table(struct ib_smp *smp, struct pib_easy_sw *sw, u8 in_port_num);
static int subn_set_random_forward_table(struct ib_smp *smp, struct pib_easy_sw *sw, u8 in_port_num);
static int subn_get_mcast_forward_table(struct ib_smp *smp, struct pib_easy_sw *sw, u8 in_port_num);
static int subn_set_mcast_forward_table(struct ib_smp *smp, struct pib_easy_sw *sw, u8 in_port_num);
static u8  get_sw_port_num(const struct sockaddr *sockaddr);


static int reply(struct ib_smp *smp)
{
	smp->method = IB_MGMT_METHOD_GET_RESP;

	if (smp->mgmt_class == IB_MGMT_CLASS_SUBN_DIRECTED_ROUTE)
		smp->status |= IB_SMP_DIRECTION;

	return IB_MAD_RESULT_SUCCESS | IB_MAD_RESULT_REPLY;
}


static int reply_failure(struct ib_smp *smp)
{
	smp->method = IB_MGMT_METHOD_GET_RESP;

	if (smp->mgmt_class == IB_MGMT_CLASS_SUBN_DIRECTED_ROUTE)
		smp->status |= IB_SMP_DIRECTION;

	return IB_MAD_RESULT_FAILURE | IB_MAD_RESULT_REPLY;
}


int pib_create_switch(struct pib_easy_sw *sw)
{
	int ret = 0;
	u8 port_num;
	struct task_struct *task;

	spin_lock_init(&sw->lock);
	init_completion(&sw->completion);

	sw->port_cnt = pib_num_hca * pib_phys_port_cnt + 1 /* port 0 */; /* @todo これ物理ポート数じゃない */

	sw->ports = vzalloc(sizeof(struct pib_port) * sw->port_cnt);
	if (!sw->ports)
		goto err_vmalloc_ports;

	for (port_num = 0 ; port_num < sw->port_cnt ; port_num++) {
		int j;
		struct ib_port_attr ib_port_attr = {
			.state           = IB_PORT_INIT,
			.max_mtu         = IB_MTU_4096,
			.active_mtu      = IB_MTU_256,
			.gid_tbl_len     = PIB_GID_PER_PORT,
			.port_cap_flags  = PIB_PORT_CAP_FLAGS,
			.max_msg_sz      = 0x40000000,
			.bad_pkey_cntr   = 0U,
			.qkey_viol_cntr  = 128,
			.pkey_tbl_len    = PIB_PKEY_TABLE_LEN,
			.lid             = 0U,
			.sm_lid          = 0U,
			.lmc             = 0U,
			.max_vl_num      = 4U,
			.sm_sl           = 0U,
			.subnet_timeout  = 0U,
			.init_type_reply = 0U,
			.active_width    = IB_WIDTH_12X,
			.active_speed    = IB_SPEED_QDR,
			.phys_state      = PIB_PHYS_PORT_POLLING,
		};
		
		sw->ports[port_num].port_num	 = port_num;
		sw->ports[port_num].ib_port_attr = ib_port_attr;
		sw->ports[port_num].gid[0].global.subnet_prefix =
			/* default GID prefix */
			cpu_to_be64(0xFE80000000000000ULL);
		/* the same guid for all ports on a switch */
		sw->ports[port_num].gid[0].global.interface_id  =
			cpu_to_be64(hca_guid_base | 0x0100ULL);

		sw->ports[port_num].link_width_enabled = PIB_LINK_WIDTH_SUPPORTED;
		sw->ports[port_num].link_speed_enabled = PIB_LINK_SPEED_SUPPORTED;

		for (j=0 ; j < PIB_PKEY_PER_BLOCK ; j++)
			sw->ports[port_num].pkey_table[j] = cpu_to_be16(IB_DEFAULT_PKEY_FULL);
	}

	sw->buffer = vmalloc(PIB_PACKET_BUFFER);
	if (!sw->buffer)
		goto err_vmalloc_buffer;

	sw->ucast_fwd_table = vzalloc(PIB_MCAST_LID_BASE);
	if (!sw->ucast_fwd_table)
		goto err_vmalloc_ucast_fwd_table;

	sw->mcast_fwd_table = vzalloc(sizeof(struct pib_port_bits) * (PIB_MAX_LID - PIB_MCAST_LID_BASE));
	if (!sw->mcast_fwd_table)
		goto err_vmalloc_mcast_fwd_table;

	ret = create_socket(sw);
	if (ret < 0)
		goto err_sock;

	task = kthread_create(kthread_routine, sw, "pib_sw");
	if (IS_ERR(task))
		goto err_task;

	sw->task = task;

	wake_up_process(task);

	pr_info("pib: add internal switch (ports=%u)\n", sw->port_cnt - 1);

	return 0;

err_task:
	ret = PTR_ERR(task);

	release_socket(sw);
err_sock:

	vfree(sw->mcast_fwd_table);
err_vmalloc_mcast_fwd_table:

	vfree(sw->ucast_fwd_table);
err_vmalloc_ucast_fwd_table:

	vfree(sw->buffer);
err_vmalloc_buffer:

	vfree(sw->ports);

err_vmalloc_ports:

	return ret;
}


void pib_release_switch(struct pib_easy_sw *sw)
{
	pr_info("pib: remove internal switch\n");

	complete(&sw->completion);
	/* flush_kthread_worker(worker); */
	kthread_stop(sw->task);

	release_socket(sw);

	vfree(sw->mcast_fwd_table);
	vfree(sw->ucast_fwd_table);
	vfree(sw->buffer);
	vfree(sw->ports);
}


static int create_socket(struct pib_easy_sw *sw)
{
	int ret, addrlen;
	struct socket *socket;
	struct sockaddr_in sockaddr_in;
	struct sockaddr_in *sockaddr_in_p;

	ret = sock_create_kern(AF_INET, SOCK_DGRAM, IPPROTO_UDP, &socket);
	if (ret < 0)
		return ret;

	/* sk_change_net(sock->sk, net); */

	lock_sock(socket->sk);
	socket->sk->sk_user_data  = sw;
	socket->sk->sk_data_ready = sock_data_ready_callback;
#if 0
	/* @todo set socet buffer size */
	socket->sk->sk_userlocks |= (SOCK_RCVBUF_LOCK | SOCK_SNDBUF_LOCK);
	socket->sk->sk_rcvbuf     = max_t(u32, val * 2, SOCK_MIN_RCVBUF);
	socket->sk->sk_sndbuf     = max_t(u32, val * 2, SOCK_MIN_SNDBUF);
#endif
	release_sock(socket->sk);

	memset(&sockaddr_in, 0, sizeof(sockaddr_in));

	sockaddr_in.sin_family      = AF_INET;
	sockaddr_in.sin_addr.s_addr = htonl(INADDR_ANY);

	ret = kernel_bind(socket, (struct sockaddr *)&sockaddr_in, sizeof(sockaddr_in));
	if (ret < 0) {
		pr_err("pib: kernel_bind: ret=%d\n", ret);
		goto err_sock;
	}

	/* get the port number that is automatically allocated by kernel_bind() */

	addrlen = sizeof(sockaddr_in);
	ret = kernel_getsockname(socket,(struct sockaddr *)&sockaddr_in, &addrlen);
	if (ret < 0) {
		pr_err("pib: kernel_getsockname: ret=%d\n", ret);
		goto err_sock;
	}

	sw->socket = socket;

	/* register lid_table */
	sockaddr_in_p  = kzalloc(sizeof(struct sockaddr_in), GFP_KERNEL);

	sockaddr_in_p->sin_family	= AF_INET;
	sockaddr_in_p->sin_addr.s_addr	= htonl(INADDR_LOOPBACK);
	sockaddr_in_p->sin_port		= sockaddr_in.sin_port;

	sw->sockaddr			= (struct sockaddr *)sockaddr_in_p;

	return 0;

err_sock:
	sock_release(socket);

	return ret;
}


static void release_socket(struct pib_easy_sw *sw)
{
	if (sw->sockaddr) {
		kfree(sw->sockaddr);
		sw->sockaddr = NULL;
	}

	if (sw->socket) {
		sock_release(sw->socket);
		sw->socket = NULL;
	}
}


static int kthread_routine(void *data)
{
	struct pib_easy_sw *sw;

	sw = (struct pib_easy_sw *)data;

	BUG_ON(!sw);

	while (!kthread_should_stop()) {
		wait_for_completion_interruptible(&sw->completion);
		init_completion(&sw->completion);

		if (test_and_clear_bit(PIB_THREAD_READY_TO_RECV, &sw->flags)) {
			int ret;
			do {
				ret = process_incoming_message(sw);
			} while (ret == 0);
		}
	}

	return 0;
}


static void sock_data_ready_callback(struct sock *sk, int bytes)
{
	struct pib_easy_sw* sw = (struct pib_easy_sw*)sk->sk_user_data;

	set_bit(PIB_THREAD_READY_TO_RECV, &sw->flags);
	complete(&sw->completion);
}


static int process_incoming_message(struct pib_easy_sw *sw)
{
	int ret, recvmsg_size, self_consumed;
	u8 in_sw_port_num, out_sw_port_num;
	u8 dest_port_num;
	u32 dest_qp_num;
	u16 dlid;
	struct msghdr msghdr = {.msg_flags = MSG_DONTWAIT | MSG_NOSIGNAL};
	struct sockaddr_in6 sockaddr_in6;
	struct kvec iov;
	struct pib_dev *dev;
	struct pib_packet_base_hdr *base_hdr;
	struct pib_packet_mad *mad_packet;
	struct pib_packet_smp *smp_packet;

	msghdr.msg_name    = &sockaddr_in6;
	msghdr.msg_namelen = sizeof(sockaddr_in6);
	iov.iov_base	   = sw->buffer;
	iov.iov_len	   = PIB_PACKET_BUFFER;

	ret = kernel_recvmsg(sw->socket, &msghdr,
			     &iov, 1, iov.iov_len, msghdr.msg_flags);

	if (ret < 0) {
		if (ret == -EINTR)
			set_bit(PIB_THREAD_READY_TO_RECV, &sw->flags);
		return ret;
	} else if (ret == 0)
		return -EAGAIN;

	in_sw_port_num = get_sw_port_num((const struct sockaddr*)&sockaddr_in6);
	if (in_sw_port_num == 0) {
		pr_err("pib: easy switch: Can't match the sockaddr of incoming packet\n");
		goto silently_drop;
	}

	recvmsg_size = ret;

	base_hdr = (struct pib_packet_base_hdr *)sw->buffer;
	if (recvmsg_size < sizeof(*base_hdr))
		goto silently_drop;

	dest_qp_num = be32_to_cpu(base_hdr->bth.destQP);
	if (dest_qp_num & ~PIB_QPN_MASK) {
		pib_debug("pib: easy switch: drop packet: dest_qp_num=0x%06x\n", dest_qp_num);
		goto silently_drop;
	}

	dlid = be16_to_cpu(base_hdr->lrh.dlid);

	if ((dest_qp_num == PIB_QP0) || (dest_qp_num == PIB_QP1))
		goto proccess_mad;

	if ((dlid != 0) &&
	    (base_hdr->lrh.dlid != IB_LID_PERMISSIVE) &&
	    (dlid != pib_easy_sw.ports[0].ib_port_attr.lid)) {
		/* Easy switch 宛のパケットではない */
		if ((dest_qp_num == IB_MULTICAST_QPN) || (PIB_MCAST_LID_BASE <= dlid))
			goto relay_mcast;
		else
			goto relay_ucast;
	}

	/* MAD 以外の easy switch 宛のパケット */
	pr_err("pib: easy switch: drop packet: dlid=0x%04x, dest_qp_num=0x%06x\n", dlid, dest_qp_num);
	goto silently_drop;

proccess_mad:
	mad_packet = (struct pib_packet_mad *)sw->buffer;
	if (recvmsg_size < sizeof(*mad_packet))
	    goto silently_drop;

	switch (mad_packet->mad.mad_hdr.mgmt_class) {

	case IB_MGMT_CLASS_SUBN_DIRECTED_ROUTE:
		smp_packet = (struct pib_packet_smp *)sw->buffer;

		if ((smp_packet->smp.dr_slid != IB_LID_PERMISSIVE) ||
		    (smp_packet->smp.dr_dlid != IB_LID_PERMISSIVE)) {
			/* DR SLID と DR DLID が指定には未対応 */
			pr_crit("pib: pib_easy_sw: SUBN_DIRECTED_ROUTE dr_slid=0x%04x, dr_dlid=0x%04x\n",
				smp_packet->smp.dr_slid,
				smp_packet->smp.dr_dlid);
			BUG();
		}

		break;

	case IB_MGMT_CLASS_SUBN_LID_ROUTED:
	default:
		pr_crit("pib: pib_easy_sw: mgmt_class = %u\n",
			mad_packet->mad.mad_hdr.mgmt_class);
		BUG();
		break;
	}

	self_consumed = 0;

	if ((smp_packet->smp.status & IB_SMP_DIRECTION) == 0) {
		/* Outgoing SMP */
		if (smp_packet->smp.hop_ptr == smp_packet->smp.hop_cnt) {
			if (smp_packet->smp.dr_dlid == IB_LID_PERMISSIVE) {
				smp_packet->smp.hop_ptr--;
				ret = process_smp(&smp_packet->smp, sw, in_sw_port_num);
				out_sw_port_num = in_sw_port_num;
				self_consumed = 1;
			} else {
				pr_crit("pib: packet.smp.dr_dlid = 0x%04x\n",
					be16_to_cpu(smp_packet->smp.dr_dlid));
				BUG();
			}
		} else if (smp_packet->smp.hop_ptr == smp_packet->smp.hop_cnt + 1) {
			smp_packet->smp.hop_ptr--;
			ret = process_smp(&smp_packet->smp, sw, in_sw_port_num);
			out_sw_port_num = in_sw_port_num;
			self_consumed = 1;
		} else {
			ret = IB_MAD_RESULT_SUCCESS;
			out_sw_port_num = smp_packet->smp.initial_path[smp_packet->smp.hop_ptr + 1];
			smp_packet->smp.hop_ptr++;
		}
	} else {
		/* Returning SMP */
		ret = IB_MAD_RESULT_SUCCESS;
		smp_packet->smp.hop_ptr--;
		out_sw_port_num = smp_packet->smp.initial_path[smp_packet->smp.hop_ptr];
		smp_packet->smp.return_path[smp_packet->smp.hop_ptr] = out_sw_port_num;
	}

	if (self_consumed) {
		smp_packet->lrh.dlid = smp_packet->lrh.slid;
		if (smp_packet->smp.dr_slid == IB_LID_PERMISSIVE)
			smp_packet->lrh.slid = IB_LID_PERMISSIVE;
	}

	if (ret & IB_MAD_RESULT_FAILURE) {
		pib_debug("pib: process_smp: failure\n");
		goto silently_drop;
	}

	BUG_ON((out_sw_port_num == 0) || (sw->port_cnt <= out_sw_port_num));

	dev = pib_devs[(out_sw_port_num - 1) / pib_phys_port_cnt];

	dest_port_num = ((out_sw_port_num - 1)  % pib_phys_port_cnt) + 1;

	down_read(&dev->rwsem);
	if (dev->ports[dest_port_num - 1].sockaddr)
		memcpy(&sockaddr_in6, dev->ports[dest_port_num - 1].sockaddr, sizeof(struct sockaddr_in)); /* @todo */
	else
		memset(&sockaddr_in6, 0, sizeof(sockaddr_in6));
	up_read(&dev->rwsem);

	msghdr.msg_name    = &sockaddr_in6;
	msghdr.msg_namelen = sizeof(sockaddr_in6);
	iov.iov_base	   = sw->buffer;
	iov.iov_len	   = recvmsg_size;

	ret = kernel_sendmsg(sw->socket, &msghdr, &iov, 1, iov.iov_len);

	return 0;

relay_ucast:
	out_sw_port_num = sw->ucast_fwd_table[dlid];

	dev = pib_devs[(out_sw_port_num - 1) / pib_phys_port_cnt];

	dest_port_num = ((out_sw_port_num - 1)  % pib_phys_port_cnt) + 1;

	down_read(&dev->rwsem);
	if (dev->ports[dest_port_num - 1].sockaddr)
		memcpy(&sockaddr_in6, dev->ports[dest_port_num - 1].sockaddr, sizeof(struct sockaddr_in)); /* @todo */
	else
		memset(&sockaddr_in6, 0, sizeof(sockaddr_in6));
	up_read(&dev->rwsem);

	msghdr.msg_name    = &sockaddr_in6;
	msghdr.msg_namelen = sizeof(sockaddr_in6);
	iov.iov_base	   = sw->buffer;
	iov.iov_len	   = recvmsg_size;

	ret = kernel_sendmsg(sw->socket, &msghdr, &iov, 1, iov.iov_len);

	return 0;

relay_mcast:
	for (out_sw_port_num = 1 ; out_sw_port_num < sw->port_cnt ; out_sw_port_num++) {
		u16 pm_block;

		/*
		 * HACK:
		 * マルチキャストグループに属していても入力ポートへは送信しないが、
		 * 同一ポートにある別 QP へ届けるためにここでは送り返す。
		 */

		/* マルチキャストグループの出力ポートではない */
		pm_block = sw->mcast_fwd_table[dlid - PIB_MCAST_LID_BASE].pm_blocks[out_sw_port_num / 16];
		if ((pm_block & (1U << (out_sw_port_num % 16))) == 0)
			continue;

		dev = pib_devs[(out_sw_port_num - 1) / pib_phys_port_cnt];

		dest_port_num = ((out_sw_port_num - 1)  % pib_phys_port_cnt) + 1;

		down_read(&dev->rwsem);
		if (dev->ports[dest_port_num - 1].sockaddr)
			memcpy(&sockaddr_in6, dev->ports[dest_port_num - 1].sockaddr, sizeof(struct sockaddr_in)); /* @todo */
		else
			memset(&sockaddr_in6, 0, sizeof(sockaddr_in6));
		up_read(&dev->rwsem);

		msghdr.msg_name    = &sockaddr_in6;
		msghdr.msg_namelen = sizeof(sockaddr_in6);
		iov.iov_base	   = sw->buffer;
		iov.iov_len	   = recvmsg_size;

		ret = kernel_sendmsg(sw->socket, &msghdr, &iov, 1, iov.iov_len);
	}

	return 0;

silently_drop:
	return 0;
}


static int process_smp(struct ib_smp *smp, struct pib_easy_sw *sw, u8 in_port_num)
{
	int ret;

	switch (smp->method) {

	case IB_MGMT_METHOD_GET:
		return process_smp_get_method(smp, sw, in_port_num);

	case IB_MGMT_METHOD_SET:
		ret = process_smp_set_method(smp, sw, in_port_num);
		if (smp->status & ~IB_SMP_DIRECTION)
			return ret;
		return process_smp_get_method(smp, sw, in_port_num);

	default:
		pr_err("pib: process_smp: %u %u", smp->method, be16_to_cpu(smp->attr_id));
		smp->status |= IB_SMP_UNSUP_METHOD;
		return reply(smp);
	}
}


static int process_smp_get_method(struct ib_smp *smp, struct pib_easy_sw *sw, u8 in_port_num)
{
	memset(smp->data, 0, sizeof(smp->data));

	switch (smp->attr_id) {

	case IB_SMP_ATTR_NODE_DESC:
		return subn_get_nodedescription(smp, sw, in_port_num);

	case IB_SMP_ATTR_NODE_INFO:
		return subn_get_nodeinfo(smp, sw, in_port_num);

	case IB_SMP_ATTR_SWITCH_INFO:
		return subn_get_switchinfo(smp, sw, in_port_num);

	case IB_SMP_ATTR_GUID_INFO:
		return subn_get_guidinfo(smp, sw, in_port_num);

	case IB_SMP_ATTR_PORT_INFO:
		return subn_get_portinfo(smp, sw, in_port_num);

	case IB_SMP_ATTR_PKEY_TABLE:
		return subn_get_pkey_table(smp, sw, in_port_num);

	case IB_SMP_ATTR_SL_TO_VL_TABLE:
		return subn_get_sl_to_vl_table(smp, sw, in_port_num);

	case IB_SMP_ATTR_VL_ARB_TABLE:
		return subn_get_vl_arb_table(smp, sw, in_port_num);

	case IB_SMP_ATTR_LINEAR_FORWARD_TABLE:
		return subn_get_linear_forward_table(smp, sw, in_port_num);

	case IB_SMP_ATTR_RANDOM_FORWARD_TABLE:
		return subn_get_random_forward_table(smp, sw, in_port_num);

	case IB_SMP_ATTR_MCAST_FORWARD_TABLE:
		return subn_get_mcast_forward_table(smp, sw, in_port_num);

	default:
		pr_err("pib: process_subn: IB_MGMT_METHOD_GET: %u", be16_to_cpu(smp->attr_id));
		smp->status |= IB_SMP_UNSUP_METH_ATTR;
		return reply(smp);
	}
}


static int process_smp_set_method(struct ib_smp *smp, struct pib_easy_sw *sw, u8 in_port_num)
{
	switch (smp->attr_id) {

	case IB_SMP_ATTR_SWITCH_INFO:
		return subn_set_switchinfo(smp, sw, in_port_num);

	case IB_SMP_ATTR_GUID_INFO:
		return subn_set_guidinfo(smp, sw, in_port_num);

	case IB_SMP_ATTR_PORT_INFO:
		return subn_set_portinfo(smp, sw, in_port_num);

	case IB_SMP_ATTR_PKEY_TABLE:
		return subn_set_pkey_table(smp, sw, in_port_num);

	case IB_SMP_ATTR_SL_TO_VL_TABLE:
		return subn_set_sl_to_vl_table(smp, sw, in_port_num);

	case IB_SMP_ATTR_VL_ARB_TABLE:
		return subn_set_vl_arb_table(smp, sw, in_port_num);

	case IB_SMP_ATTR_LINEAR_FORWARD_TABLE:
		return subn_set_linear_forward_table(smp, sw, in_port_num);

	case IB_SMP_ATTR_RANDOM_FORWARD_TABLE:
		return subn_set_random_forward_table(smp, sw, in_port_num);

	case IB_SMP_ATTR_MCAST_FORWARD_TABLE:
		return subn_set_mcast_forward_table(smp, sw, in_port_num);

	default:
		pr_err("pib: process_smp: IB_MGMT_METHOD_SET: %u", be16_to_cpu(smp->attr_id));
		smp->status |= IB_SMP_UNSUP_METH_ATTR;
		return reply(smp);
	}
}


static int subn_get_nodedescription(struct ib_smp *smp, struct pib_easy_sw *sw, u8 in_port_num)
{
	if (smp->attr_mod)
		smp->status |= IB_SMP_INVALID_FIELD;

	strncpy(smp->data, PIB_DRIVER_DESCRIPTION, 64);

	return reply(smp);
}


static int subn_get_nodeinfo(struct ib_smp *smp, struct pib_easy_sw *sw, u8 in_port_num)
{
	struct pib_mad_node_info *node_info = (struct pib_mad_node_info *)&smp->data;

	/* smp->status |= IB_SMP_INVALID_FIELD; */

	node_info->base_version		= IB_MGMT_BASE_VERSION;
	node_info->class_version	= IB_MGMT_CLASS_VERSION;
	node_info->node_type		= RDMA_NODE_IB_SWITCH;
	node_info->node_ports		= sw->port_cnt - 1;
	node_info->sys_image_guid	= cpu_to_be64(hca_guid_base | 0x0200ULL);
	node_info->node_guid		= cpu_to_be64(hca_guid_base | 0x0100ULL);
	node_info->port_guid		= cpu_to_be64(hca_guid_base | 0x0100ULL);
	node_info->partition_cap	= cpu_to_be16(1); /* @todo */
	node_info->device_id		= cpu_to_be16(PIB_DRIVER_DEVICE_ID);
	node_info->revision		= cpu_to_be32(PIB_DRIVER_REVISION);
	node_info->local_port_num	= in_port_num;
	node_info->vendor_id[0]		= 0; /* OUI */
	node_info->vendor_id[1]		= 0; /* OUI */
	node_info->vendor_id[2]		= 0; /* OUI */

	return reply(smp);
}


static int subn_get_switchinfo(struct ib_smp *smp, struct pib_easy_sw *sw, u8 in_port_num)
{
	struct pib_mad_switch_info *switch_info = (struct pib_mad_switch_info *)&smp->data;
	u8 opimized_sl_to_vl_mapping_programming;

	switch_info->linear_fdb_cap	= cpu_to_be16(768);
	switch_info->random_fdb_cap	= cpu_to_be16(3072);
	switch_info->multicast_fdb_cap	= cpu_to_be16(256); /* @todo */
	switch_info->linear_fdb_top	= cpu_to_be16(sw->linear_fdb_top);

	switch_info->default_port	= sw->default_port;
	switch_info->default_mcast_primary_port = sw->default_mcast_primary_port;
	switch_info->default_mcast_not_primary_port = sw->default_mcast_not_primary_port;

	opimized_sl_to_vl_mapping_programming = 0;

	switch_info->various1 = (sw->life_time_value << 3) | (sw->port_state_change << 2) |
		opimized_sl_to_vl_mapping_programming;

	switch_info->lids_per_port	= cpu_to_be16(1);
	switch_info->partition_enforcement_cap = cpu_to_be16(0);

	switch_info->various2		= 0;

	return reply(smp);
}


static int subn_set_switchinfo(struct ib_smp *smp, struct pib_easy_sw *sw, u8 in_port_num)
{
	struct pib_mad_switch_info *switch_info = (struct pib_mad_switch_info *)&smp->data;

	sw->linear_fdb_top	= be16_to_cpu(switch_info->linear_fdb_top);
	sw->default_port	= switch_info->default_port;
	sw->default_mcast_primary_port = switch_info->default_mcast_primary_port;
	sw->default_mcast_not_primary_port = switch_info->default_mcast_not_primary_port;

	sw->life_time_value	= (switch_info->various1 >> 3) & 0x1F;

	if ((switch_info->various1 >> 2) & 0x01)
		sw->port_state_change = 0; /* clear */ 

	return reply(smp);
}


static int subn_get_guidinfo(struct ib_smp *smp, struct pib_easy_sw *sw, u8 in_port_num)
{
	pr_err("pib: *** %s ***", __FUNCTION__);
	return reply_failure(smp);
}


static int subn_set_guidinfo(struct ib_smp *smp, struct pib_easy_sw *sw, u8 in_port_num)
{
	pr_err("pib: *** %s ***", __FUNCTION__);
	return reply_failure(smp);
}


static int subn_get_portinfo(struct ib_smp *smp, struct pib_easy_sw *sw, u8 in_port_num)
{
	struct ib_port_info *port_info = (struct ib_port_info *)&smp->data;
	u32 port_num = be32_to_cpu(smp->attr_mod);
	struct pib_port *port;

	port = &pib_easy_sw.ports[port_num];

	port_info->local_port_num = in_port_num;

	pib_subn_get_portinfo(smp, port, port_num,
			      (port_num != 0) ? PIB_PORT_SW_EXT : PIB_PORT_BASE_SP0);

	return reply(smp);
}


static int subn_set_portinfo(struct ib_smp *smp, struct pib_easy_sw *sw, u8 in_port_num)
{
	u32 port_num = be32_to_cpu(smp->attr_mod);
	struct pib_port *port;

	port = &pib_easy_sw.ports[port_num];

	pib_subn_set_portinfo(smp, port, port_num,
			      (port_num != 0) ? PIB_PORT_SW_EXT : PIB_PORT_BASE_SP0);

	if (port->ib_port_attr.state < IB_PORT_INIT) {
		sw->port_state_change    = 1;
		port->ib_port_attr.state = IB_PORT_INIT;
	}

	return reply(smp);
}


static int subn_get_pkey_table(struct ib_smp *smp, struct pib_easy_sw *sw, u8 in_port_num)
{
	int i;
	u32 attr_mod, block_index, sw_port_index;
	__be16 *pkey_table = (__be16 *)&smp->data[0];

	attr_mod      = be32_to_cpu(smp->attr_mod);

	block_index   = attr_mod         & 0xFFFF;
	sw_port_index = (attr_mod >> 16) & 0xFFFF;

	if (block_index != 0) {
		smp->status |= IB_SMP_INVALID_FIELD;
		goto bail;
	}

	if (sw->port_cnt <= sw_port_index) {
		smp->status |= IB_SMP_INVALID_FIELD;
		goto bail;
	}

	for (i=0; i<PIB_PKEY_PER_BLOCK; i++)
		pkey_table[i] = cpu_to_be16(sw->ports[sw_port_index].pkey_table[i]);

bail:
	return reply(smp);
}


static int subn_set_pkey_table(struct ib_smp *smp, struct pib_easy_sw *sw, u8 in_port_num)
{
	int i;
	u32 attr_mod, block_index, sw_port_index;
	__be16 *pkey_table = (__be16 *)&smp->data[0];

	attr_mod      = be32_to_cpu(smp->attr_mod);

	block_index   = attr_mod         & 0xFFFF;
	sw_port_index = (attr_mod >> 16) & 0xFFFF;

	if (block_index != 0) {
		smp->status |= IB_SMP_INVALID_FIELD;
		goto bail;
	}

	if (sw->port_cnt <= sw_port_index) {
		smp->status |= IB_SMP_INVALID_FIELD;
		goto bail;
	}

	for (i=0; i<PIB_PKEY_PER_BLOCK; i++)
		sw->ports[sw_port_index].pkey_table[i] = be16_to_cpu(pkey_table[i]);

bail:
	return reply(smp);
}


static int subn_get_sl_to_vl_table(struct ib_smp *smp, struct pib_easy_sw *sw, u8 in_port_num)
{
	pr_err("pib: *** %s ***", __FUNCTION__);
	return reply_failure(smp);
}


static int subn_set_sl_to_vl_table(struct ib_smp *smp, struct pib_easy_sw *sw, u8 in_port_num)
{
	pr_err("pib: *** %s ***", __FUNCTION__);
	return reply_failure(smp);
}


static int subn_get_vl_arb_table(struct ib_smp *smp, struct pib_easy_sw *sw, u8 in_port_num)
{
	pr_err("pib: *** %s ***", __FUNCTION__);
	return reply_failure(smp);
}


static int subn_set_vl_arb_table(struct ib_smp *smp, struct pib_easy_sw *sw, u8 in_port_num)
{
	pr_err("pib: *** %s ***", __FUNCTION__);
	return reply_failure(smp);
}


static int subn_get_linear_forward_table(struct ib_smp *smp, struct pib_easy_sw *sw, u8 in_port_num)
{
	u32 i, attr_mod;
	u8 *table = (u8 *)&smp->data[0];

	attr_mod = be32_to_cpu(smp->attr_mod);

	if (767 < attr_mod) {
		smp->status |= IB_SMP_INVALID_FIELD;
		goto bail;
	}
	
	for (i = 0 ; i < 64 ; i++)
		if (attr_mod * 64 + i <= sw->linear_fdb_top)
			table[i] = sw->ucast_fwd_table[attr_mod * 64 + i];

bail:
	return reply(smp);
}


static int subn_set_linear_forward_table(struct ib_smp *smp, struct pib_easy_sw *sw, u8 in_port_num)
{
	u32 i, attr_mod;
	u8 *table = (u8 *)&smp->data[0];

	attr_mod = be32_to_cpu(smp->attr_mod);

	if (767 < attr_mod) {
		smp->status |= IB_SMP_INVALID_FIELD;
		goto bail;
	}
	
	for (i = 0 ; i < 64 ; i++)
		sw->ucast_fwd_table[attr_mod * 64 + i] = table[i];

bail:
	return reply(smp);
}


static int subn_get_random_forward_table(struct ib_smp *smp, struct pib_easy_sw *sw, u8 in_port_num)
{
	pr_err("pib: *** %s ***", __FUNCTION__);
	return reply_failure(smp);
}


static int subn_set_random_forward_table(struct ib_smp *smp, struct pib_easy_sw *sw, u8 in_port_num)
{
	u32 i, attr_mod;
	__be32 *table = (__be32 *)&smp->data[0];

	attr_mod = be32_to_cpu(smp->attr_mod);

	if (3071 < attr_mod) {
		smp->status |= IB_SMP_INVALID_FIELD;
		goto bail;
	}
	
	for (i = 0 ; i < 16 ; i++) {
		u32 value = be32_to_cpu(table[i]);
		u16 dlid  = value >> 16;

		/* @todo LMC */
		
		sw->ucast_fwd_table[dlid] = (value & 0x8000U) ?
			(value & 0xFFU) : sw->default_port;
	}

bail:
	return reply(smp);
}


static int subn_get_mcast_forward_table(struct ib_smp *smp, struct pib_easy_sw *sw, u8 in_port_num)
{
	u32 attr_mod;
	u32 i, mcast_lid_offset, port_index;
	__be16 *table = (__be16 *)&smp->data[0];

	attr_mod = be32_to_cpu(smp->attr_mod);
	
	mcast_lid_offset = (attr_mod & 0xFF) * 32;
	port_index       = (attr_mod >> 28);

	for (i=0 ; i<32 ; i++)
		table[i] = cpu_to_be16(sw->mcast_fwd_table[mcast_lid_offset + i].pm_blocks[port_index]);

	return reply(smp);
}


static int subn_set_mcast_forward_table(struct ib_smp *smp, struct pib_easy_sw *sw, u8 in_port_num)
{
	u32 attr_mod;
	u32 i, mcast_lid_offset, port_index;
	__be16 *table = (__be16 *)&smp->data[0];

	attr_mod = be32_to_cpu(smp->attr_mod);
	
	mcast_lid_offset = (attr_mod & 0xFF) * 32;
	port_index       = (attr_mod >> 28);

	for (i=0 ; i<32 ; i++)
		sw->mcast_fwd_table[mcast_lid_offset + i].pm_blocks[port_index] =
			be16_to_cpu(table[i]);

	return reply(smp);
}


static u8 get_sw_port_num(const struct sockaddr *sockaddr)
{
	int i, j;
	u8 port_num = 0;
	__be16 sin_port = ((const struct sockaddr_in*)sockaddr)->sin_port;

	for (i=0 ; i<pib_num_hca ; i++) {
		struct pib_dev *dev = pib_devs[i];

		down_read(&dev->rwsem);
		for (j=0 ; j<pib_phys_port_cnt ; j++) {
			port_num++;

			if (!dev->ports[j].sockaddr)
				continue;

			if (sin_port == ((const struct sockaddr_in*)dev->ports[j].sockaddr)->sin_port) {
				up_read(&dev->rwsem);
				return port_num;
			}
		}
		up_read(&dev->rwsem);
	}

	return 0;
}
