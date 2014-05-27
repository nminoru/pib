/*
 * pib_thread.c - Kernel threads process
 *
 * Copyright (c) 2013,2014 Minoru NAKAMURA <nminoru@nminoru.jp>
 *
 * This code is licenced under the GPL version 2 or BSD license.
 */
#include <linux/module.h>
#include <linux/init.h>
#include <linux/version.h>
#include <linux/bitmap.h>
#include <linux/timer.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/errno.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/rtnetlink.h>
#include <linux/if_vlan.h>
#include <linux/random.h>
#include <linux/kthread.h>
#include <net/sock.h> /* for struct sock */
#include <rdma/ib_user_verbs.h>
#include <rdma/ib_pack.h>

#include "pib.h"
#include "pib_packet.h"
#include "pib_trace.h"


static int kthread_routine(void *data);
static void kthread_routine_iteration(struct pib_dev *dev);
static int create_socket(struct pib_dev *dev, u8 port_num);
static void release_socket(struct pib_dev *dev, u8 port_num);
static void process_on_qp_scheduler(struct pib_dev *dev);
static int process_new_send_wr(struct pib_qp *qp);
static int process_send_wr(struct pib_dev *dev, struct pib_qp *qp, struct pib_send_wqe *send_wqe);
static int receive_packet(struct pib_dev *dev, u8 port_num);
static void process_incoming_message(struct pib_dev *dev, u8 port_num, void *buffer, int packet_size);
static void process_incoming_message_per_qp(struct pib_dev *dev, u8 port_num, u16 dlid, u32 dest_qp_num, struct pib_packet_lrh *lrh, struct ib_grh *grh, struct pib_packet_bth *bth, void *buffer, int size);
static void connect_pibnetd(struct pib_dev *dev, u8 port_num);
static void disconnect_pibnetd(struct pib_dev *dev, u8 port_num);
static void send_raw_packet_to_pibnetd(struct pib_dev *dev, u8 port_num, bool disconnect);
static void process_raw_packet(struct pib_dev *dev, u8 port_num, struct pib_packet_lrh *lrh, void *buffer, int size);
static void process_on_wq_scheduler(struct pib_dev *dev);
static void process_sendmsg(struct pib_dev *dev);
static struct sockaddr *get_sockaddr_from_dlid(struct pib_dev *dev, u8 port_num, u32 src_qp_num, u16 dlid);
static void sock_data_ready_callback(struct sock *sk, int bytes);
static void timer_timeout_callback(unsigned long opaque);
static void delayed_work_timeout_callback(unsigned long data);


static int send_buffer_size = PIB_SEND_BUFFER_SIZE;
module_param_named(send_buffer_size, send_buffer_size, int, S_IRUGO);
MODULE_PARM_DESC(send_buffer_size, "Bytes of send buffer");

static int recv_buffer_size = PIB_RECV_BUFFER_SIZE;
module_param_named(recv_buffer_size, recv_buffer_size, int, S_IRUGO);
MODULE_PARM_DESC(recv_buffer_size, "Bytes of recv buffer");

static int pib_nice = PIB_DEFAULT_NICE;
module_param_named(nice, pib_nice, int, 0644);
MODULE_PARM_DESC(nice, "kthread priority (from -19 to 20)");


int pib_create_kthread(struct pib_dev *dev)
{
	int i, j, ret;
	struct task_struct *task;

	init_completion(&dev->thread.completion);
	init_timer(&dev->thread.timer);

	dev->thread.timer.function = timer_timeout_callback;
	dev->thread.timer.data     = (unsigned long)dev;

	dev->thread.send_buffer	   = vmalloc(PIB_PACKET_BUFFER);
	if (!dev->thread.send_buffer) {
		ret = -ENOMEM;
		goto err_send_vmalloc;
	}

	dev->thread.recv_buffer	   = vmalloc(PIB_PACKET_BUFFER);
	if (!dev->thread.recv_buffer) {
		ret = -ENOMEM;
		goto err_recv_vmalloc;
	}

	for (i=0 ; i < dev->ib_dev.phys_port_cnt ; i++) {
		ret = create_socket(dev, i + 1);
		if (ret < 0)
			goto err_sock;
	}

	task = kthread_create(kthread_routine, dev, "pib_%d", dev->dev_id);
	if (IS_ERR(task))
		goto err_task;

	dev->thread.task = task;

	wake_up_process(task);

	return 0;

err_task:
	ret = PTR_ERR(task);
	
err_sock:
	for (j = i-1 ; 0 <= j ; j--)
		release_socket(dev, j + 1);

	vfree(dev->thread.recv_buffer);
	dev->thread.recv_buffer = NULL;

err_recv_vmalloc:

	vfree(dev->thread.send_buffer);
	dev->thread.send_buffer = NULL;

err_send_vmalloc:

	return ret;
}


void pib_release_kthread(struct pib_dev *dev)
{
	int i;

	smp_wmb();

	del_timer_sync(&dev->thread.timer);

	if (dev->thread.task) {
		set_bit(PIB_THREAD_STOP, &dev->thread.flags);
		complete(&dev->thread.completion);
		/* flush_kthread_worker(worker); */
		kthread_stop(dev->thread.task);
		dev->thread.task = NULL;
	}

	for (i=dev->ib_dev.phys_port_cnt - 1 ; 0 <= i  ; i--)
		release_socket(dev, i + 1);

	vfree(dev->thread.recv_buffer);
	dev->thread.recv_buffer = NULL;

	vfree(dev->thread.send_buffer);
	dev->thread.send_buffer = NULL;
}


static int create_socket(struct pib_dev *dev, u8 port_num)
{
	int ret, addrlen;
	int rcvbuf_size, sndbuf_size;
	struct socket *socket;
	struct sockaddr_in sockaddr_in;
	struct sockaddr_in *sockaddr_in_p;

	ret = sock_create_kern(AF_INET, SOCK_DGRAM, IPPROTO_UDP, &socket);
	if (ret < 0)
		return ret;

	/* sk_change_net(sock->sk, net); */

	lock_sock(socket->sk);
	socket->sk->sk_user_data  = dev;
	socket->sk->sk_data_ready = sock_data_ready_callback;

	socket->sk->sk_userlocks |= (SOCK_RCVBUF_LOCK | SOCK_SNDBUF_LOCK);

	sndbuf_size = max_t(u32, send_buffer_size, SOCK_MIN_SNDBUF);
	rcvbuf_size = max_t(u32, recv_buffer_size, SOCK_MIN_RCVBUF);
	socket->sk->sk_sndbuf     = max_t(u32, socket->sk->sk_sndbuf, sndbuf_size);
	socket->sk->sk_rcvbuf     = max_t(u32, socket->sk->sk_rcvbuf, rcvbuf_size);

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

	dev->ports[port_num - 1].socket = socket;

	/* register lid_table */
	sockaddr_in_p  = kzalloc(sizeof(struct sockaddr_in), GFP_KERNEL);

	sockaddr_in_p->sin_family	= AF_INET;
	sockaddr_in_p->sin_addr.s_addr	= htonl(INADDR_LOOPBACK);
	sockaddr_in_p->sin_port		= sockaddr_in.sin_port;

	dev->ports[port_num - 1].sockaddr	= (struct sockaddr *)sockaddr_in_p;

	return 0;

err_sock:
	sock_release(socket);

	return ret;
}


static void release_socket(struct pib_dev *dev, u8 port_num)
{
	if (dev->ports[port_num - 1].sockaddr) {
		kfree(dev->ports[port_num - 1].sockaddr);
		dev->ports[port_num - 1].sockaddr = NULL;
	}

	if (dev->ports[port_num - 1].socket) {
		sock_release(dev->ports[port_num - 1].socket);
		dev->ports[port_num - 1].socket = NULL;
	}
}


static int kthread_routine(void *data)
{
	int nice = INT_MIN;
	struct pib_dev *dev;
	u8 i, phys_port_cnt;

	dev = (struct pib_dev *)data;

	BUG_ON(!dev);

	phys_port_cnt = dev->ib_dev.phys_port_cnt;

#if 0
	/* Hibernation / freezing of the SRPT kernel thread is not supported. */
	current->flags |= PF_NOFREEZE;
#endif

	if (pib_multi_host_mode)
		for (i=0 ; i < phys_port_cnt ; i++)
			connect_pibnetd(dev, i + 1);
	else
		for (i=0 ; i < phys_port_cnt ; i++)
			pib_easy_sw.ports[1 + phys_port_cnt * dev->dev_id + i].to_udp_port
				= ((const struct sockaddr_in*)dev->ports[i].sockaddr)->sin_port;

	while (!kthread_should_stop()) {
		unsigned long flags;
		unsigned long timeout = HZ;

		/* nice の設定に変更があった場合 */
		if (nice != pib_nice) {
			nice = pib_nice;
			if ((-20 <= nice) && (nice <= 19))
				set_user_nice(current, nice);
			else {
				pr_err("pib: nice parameter is out of range: %d\n", nice);
				set_user_nice(current, PIB_DEFAULT_NICE);
			}
		}

		/* 停止時間を計算。ただし1 秒以上は停止させない */
		spin_lock_irqsave(&dev->qp_sched.lock, flags);
		if (time_after(dev->qp_sched.wakeup_time, jiffies))
			timeout = dev->qp_sched.wakeup_time - jiffies;
		else
			dev->qp_sched.wakeup_time = jiffies;
		if (HZ < timeout)
			timeout = HZ;
		spin_unlock_irqrestore(&dev->qp_sched.lock, flags);

		wait_for_completion_interruptible_timeout(&dev->thread.completion, timeout);
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,13,0)
		INIT_COMPLETION(dev->thread.completion);
#else
		reinit_completion(&dev->thread.completion);
#endif

		while (dev->thread.flags) {
			cond_resched();
			kthread_routine_iteration(dev);
		}

		process_on_qp_scheduler(dev);
	}

	if (pib_multi_host_mode)
		for (i=0 ; i < phys_port_cnt ; i++)
			disconnect_pibnetd(dev, i + 1);
	else
		for (i=0 ; i < phys_port_cnt ; i++)
			pib_easy_sw.ports[1 + phys_port_cnt * dev->dev_id + i].to_udp_port
				= 0;

	return 0;
}


static void kthread_routine_iteration(struct pib_dev *dev)
{
	if (test_and_clear_bit(PIB_THREAD_STOP, &dev->thread.flags))
		return;

	if (test_and_clear_bit(PIB_THREAD_WQ_SCHEDULE, &dev->thread.flags)) {
		process_on_wq_scheduler(dev);
		return;
	}

	if (test_and_clear_bit(PIB_THREAD_READY_TO_RECV, &dev->thread.flags)) {
		int i;
		for (i=0 ; i < dev->ib_dev.phys_port_cnt ; i++) {
			while (0 < receive_packet(dev, i + 1)) {
				process_incoming_message(dev, i + 1,
							 dev->thread.recv_buffer,
							 dev->thread.recv_size);
			}
		}
		return;
	}

	if (test_and_clear_bit(PIB_THREAD_QP_SCHEDULE, &dev->thread.flags)) {
		process_on_qp_scheduler(dev);
		return;
	}
}


static void process_on_qp_scheduler(struct pib_dev *dev)
{
	int ret;
	unsigned long now;
	unsigned long flags;
	struct pib_qp *qp;
	struct pib_send_wqe *send_wqe, *next_send_wqe;

restart:
	now = jiffies;

	spin_lock_irqsave(&dev->lock, flags);

	qp = pib_util_get_first_scheduling_qp(dev);
	if (!qp) {
		spin_unlock_irqrestore(&dev->lock, flags);
		return;
	}

	/* @notice ロックの入れ子関係を一部崩している */
	spin_lock(&qp->lock);
	spin_unlock(&dev->lock);

	/* Responder: generating acknowledge packets */
	if (qp->qp_type == IB_QPT_RC)
		if (pib_generate_rc_qp_acknowledge(dev, qp) == 1)
			goto done;

	/* Requester: generating request packets */
	if ((qp->state != IB_QPS_RTS) && (qp->state != IB_QPS_SQD))
		goto done;

	/*
	 *  Waiting list の先頭の Send WQE が再送時刻に達していれば
	 *  waiting list から sending list へ戻して再送信を促す。
	 */
	if (list_empty(&qp->requester.waiting_swqe_head))
		goto first_sending_wsqe;

	send_wqe = list_first_entry(&qp->requester.waiting_swqe_head, struct pib_send_wqe, list);

	if (time_after(send_wqe->processing.local_ack_time, now))
		goto first_sending_wsqe;

	pib_trace_retry(dev, qp->ib_qp_attr.port_num, send_wqe);

	send_wqe->processing.retry_cnt--;
	send_wqe->processing.local_ack_time = now + PIB_SCHED_TIMEOUT;

	dev->perf.local_ack_timeout++;

	/* waiting list から sending list へ戻す */
	list_for_each_entry_safe_reverse(send_wqe, next_send_wqe, &qp->requester.waiting_swqe_head, list) {
		send_wqe->processing.list_type = PIB_SWQE_SENDING;
		list_del_init(&send_wqe->list);
		list_add(&send_wqe->list, &qp->requester.sending_swqe_head);
		qp->requester.nr_waiting_swqe--;
		qp->requester.nr_sending_swqe++;
	}

	/* 送信したパケット数をキャンセルする */
	list_for_each_entry(send_wqe, &qp->requester.sending_swqe_head, list) {
		send_wqe->processing.sent_packets = send_wqe->processing.ack_packets;
	}
	    
first_sending_wsqe:
	if (list_empty(&qp->requester.sending_swqe_head)) {
		/* sending list が空になったら新しい SWQE を取り出す */
		if (process_new_send_wr(qp))
			goto first_sending_wsqe;
		else
			goto done;
	}

	send_wqe = list_first_entry(&qp->requester.sending_swqe_head, struct pib_send_wqe, list);

	/*
	 *  Sending list の先頭の Send WQE がエラーだが、waiting list が
	 *  残っている場合、waiting list から空になるまで送信は再開しない。
	 */
	if (send_wqe->processing.status != IB_WC_SUCCESS)
		if (!list_empty(&qp->requester.waiting_swqe_head))
			goto done;

	/*
	 *  SEND & RDMA WRITE が連続送信の制限に引掛る場合は、一時停止
	 */
	if (PIB_MAX_CONTIG_REQUESTS < qp->requester.nr_contig_requests)
		goto done;

	/*
	 *  RNR NAK タイムアウト時刻の判定
	 */
	if (time_after(send_wqe->processing.schedule_time, now))
		goto done;

	send_wqe->processing.schedule_time = now;

	ret = process_send_wr(dev, qp, send_wqe);
			
	switch (send_wqe->processing.list_type) {

	case PIB_SWQE_FREE:
		/* list からは外されている */
		pib_util_free_send_wqe(qp, send_wqe);
		break;

	case PIB_SWQE_SENDING:
		/* no change */
		break;

	case PIB_SWQE_WAITING:
		list_del_init(&send_wqe->list);
		list_add_tail(&send_wqe->list, &qp->requester.waiting_swqe_head);
		qp->requester.nr_sending_swqe--;
		qp->requester.nr_waiting_swqe++;
		break;

	default:
		pr_emerg("pib: Error qp_type=%s in %s at %s:%u\n",
			 pib_get_qp_type(qp->qp_type), __FUNCTION__, __FILE__, __LINE__);
		BUG();
	}

done:
	pib_util_reschedule_qp(qp); /* 必要の応じてスケジューラから抜くために呼び出す */

	spin_unlock_irqrestore(&qp->lock, flags);

	if (dev->thread.ready_to_send)
		process_sendmsg(dev);

	if (dev->thread.flags & ((1U << PIB_THREAD_QP_SCHEDULE) - 1))
		return;

	spin_lock_irqsave(&dev->qp_sched.lock, flags);
	if (time_after(dev->qp_sched.wakeup_time, jiffies)) {
		spin_unlock_irqrestore(&dev->qp_sched.lock, flags);
		return;
	}
	spin_unlock_irqrestore(&dev->qp_sched.lock, flags);

	cond_resched();

	goto restart;
}


static int process_new_send_wr(struct pib_qp *qp)
{
	struct pib_send_wqe *send_wqe;
	u32 num_packets;
	unsigned long now;

	if (qp->state != IB_QPS_RTS)
		return 0;

	if (list_empty(&qp->requester.submitted_swqe_head))
		return 0;

	send_wqe = list_first_entry(&qp->requester.submitted_swqe_head, struct pib_send_wqe, list);

	/*
	 *  A work request with the fence attribute set shall block
	 *  until all prior RDMA READ and Atomic WRs have completed.
	 *  
	 */
	if (send_wqe->send_flags & IB_SEND_FENCE)
		if (0 < qp->requester.nr_rd_atomic)
			return 0;

	if (pib_is_wr_opcode_rd_atomic(send_wqe->opcode)) {
		if (qp->requester.max_rd_atomic <= qp->requester.nr_rd_atomic)
			return 0;
		qp->requester.nr_rd_atomic++;
	}

	list_del_init(&send_wqe->list);
	list_add_tail(&send_wqe->list, &qp->requester.sending_swqe_head);
	qp->requester.nr_submitted_swqe--;
	qp->requester.nr_sending_swqe++;

	send_wqe->processing.list_type = PIB_SWQE_SENDING;

	/*
	 *  Set expected PSN for SQ and etc.
	 */
	now = jiffies;

	num_packets = pib_get_num_of_packets(qp, send_wqe->total_length);

	send_wqe->processing.based_psn     = qp->requester.expected_psn;
	send_wqe->processing.expected_psn  = qp->requester.expected_psn + num_packets;

	send_wqe->processing.all_packets   = num_packets;
	send_wqe->processing.ack_packets   = 0;
	send_wqe->processing.sent_packets  = 0;

	qp->requester.expected_psn        += num_packets;

	send_wqe->processing.schedule_time = now;
	send_wqe->processing.local_ack_time = now + PIB_SCHED_TIMEOUT;

	send_wqe->processing.retry_cnt     = qp->ib_qp_attr.retry_cnt;
	send_wqe->processing.rnr_retry     = qp->ib_qp_attr.rnr_retry;

	return 1;
}


/*
 *  state は RTS
 *
 *  Lock: qp
 */
static int process_send_wr(struct pib_dev *dev, struct pib_qp *qp, struct pib_send_wqe *send_wqe)
{
	enum ib_wr_opcode opcode;
	enum ib_wc_status status;

	BUG_ON(send_wqe->processing.list_type != PIB_SWQE_SENDING);

	status = send_wqe->processing.status;
	opcode = send_wqe->opcode;

	/* 処理中にエラーになったが前方の SEND WR が処理完了するまで遅延していた */
	if (status != IB_WC_SUCCESS)
		goto completion_error;

	switch (qp->qp_type) {

	case IB_QPT_RC:
		return pib_process_rc_qp_request(dev, qp, send_wqe);

	case IB_QPT_UD:
	case IB_QPT_GSI:
	case IB_QPT_SMI:
		return pib_process_ud_qp_request(dev, qp, send_wqe);

	default:
		pr_emerg("pib: Error qp_type=%s in %s at %s:%u\n",
			 pib_get_qp_type(qp->qp_type), __FUNCTION__, __FILE__, __LINE__);
		BUG();
	}

	return -1;

completion_error:
	pib_util_insert_wc_error(qp->send_cq, qp, send_wqe->wr_id,
				 status, send_wqe->opcode);

	list_del_init(&send_wqe->list);
	qp->requester.nr_sending_swqe--;
	send_wqe->processing.list_type = PIB_SWQE_FREE;

	switch (qp->qp_type) {
	case IB_QPT_RC:
		qp->state = IB_QPS_ERR;
		pib_util_flush_qp(qp, 0);
		break;

	case IB_QPT_UD:
	case IB_QPT_GSI:
	case IB_QPT_SMI:
		qp->state = IB_QPS_SQE;
		pib_util_flush_qp(qp, 1);
		break;

	default:
		pr_emerg("pib: Error qp_type=%s in %s at %s:%u\n",
			 pib_get_qp_type(qp->qp_type), __FUNCTION__, __FILE__, __LINE__);
		BUG();
	}

	return -1;
}


static int receive_packet(struct pib_dev *dev, u8 port_num)
{
	int ret;
	struct msghdr msghdr = {.msg_flags = MSG_DONTWAIT | MSG_NOSIGNAL};
	struct kvec iov;
	struct pib_port *port;

	iov.iov_base = dev->thread.recv_buffer;
	iov.iov_len  = PIB_PACKET_BUFFER;

	port = &dev->ports[port_num - 1];

	ret = kernel_recvmsg(port->socket, &msghdr,
			     &iov, 1, iov.iov_len, msghdr.msg_flags);

	if (ret < 0) {
		if (ret == -EINTR)
			set_bit(PIB_THREAD_READY_TO_RECV, &dev->thread.flags);
		return ret;
	} else if (ret == 0)
		return -EAGAIN;

	dev->thread.recv_size = ret;
	
	return ret;
}


static void process_incoming_message(struct pib_dev *dev, u8 port_num, void *buffer, int packet_size)
{
	int size, header_size;
	struct pib_port *port;
	struct pib_packet_lrh *lrh;
	struct ib_grh         *grh;
	struct pib_packet_bth *bth;
	u32 dest_qp_num;
	u16 slid, dlid;

	size = packet_size;

	port = &dev->ports[port_num - 1];

	if (size < sizeof(union pib_packet_footer)) {
		pib_debug("pib: no packet footer(size=%u)\n", size);
		goto silently_drop;
	}

	size -= sizeof(union pib_packet_footer);

	port->perf.rcv_packets++;
	port->perf.rcv_data += packet_size;

	header_size = pib_parse_packet_header(buffer, size, &lrh, &grh, &bth);
	if (header_size < 0) {
		pib_debug("pib: wrong drop packet(size=%u)\n", size);
		goto silently_drop;
	}

	buffer += header_size;
	size   -= header_size;

	if ((lrh->sl_rsv_lnh & 0x3) == 0)
		goto raw_packet;

	/* Payload */
	size -= pib_packet_bth_get_padcnt(bth); /* Pad Count */
	if (size < 0) {
		pib_debug("pib: drop packet: too small packet except LRH & BTH (size=%u)\n", size);
		goto silently_drop;
	}

	/* Emit ICRC */
	size -= 4;
	if (size < 0) {
		pib_debug("pib: drop packet: too small packet except ICRC (size=%u)\n", size);
		goto silently_drop;
	}

	slid	    = be16_to_cpu(lrh->slid);	
	dlid        = be16_to_cpu(lrh->dlid);
	dest_qp_num = be32_to_cpu(bth->destQP) & PIB_QPN_MASK;

	switch (port->ib_port_attr.state) {
	case IB_PORT_INIT:
	case IB_PORT_ARMED:
		/* The link layer can only receive SMP. */
		if (dest_qp_num != PIB_QP0)
			goto silently_drop;
		break;
	case IB_PORT_ACTIVE:
		/* The link layer can transmit all packet types. */
		break;
	default:
		/* The physical link is not up or error */
		goto silently_drop;
	}

	pib_trace_recv(dev, port_num,
		       bth->OpCode, be32_to_cpu(bth->psn) & PIB_PSN_MASK, packet_size,
		       slid, dlid, dest_qp_num);

	if ((dest_qp_num == PIB_QP0) || (dlid < PIB_MCAST_LID_BASE)) {
		/* Unicast */
		process_incoming_message_per_qp(dev, port_num, dlid, dest_qp_num,
						lrh, grh, bth, buffer, size);
	} else {
		/* Multicast */
		int i, max;
		struct pib_packet_deth *deth;
		u16 port_lid, slid;
		u32 src_qp_num;
		struct pib_mcast_link *mcast_link;
		u32 qp_nums[PIB_MCAST_QP_ATTACH];
		unsigned long flags;

		if ((bth->OpCode != IB_OPCODE_UD_SEND_ONLY) && 
		    (bth->OpCode != IB_OPCODE_UD_SEND_ONLY_WITH_IMMEDIATE)) {
			pib_debug("pib: drop packet: \n");
			goto silently_drop;
		}

		if (size < sizeof(struct pib_packet_deth))
			goto silently_drop;

		deth = (struct pib_packet_deth*)buffer;

		src_qp_num = be32_to_cpu(deth->srcQP) & PIB_QPN_MASK;

		spin_lock_irqsave(&dev->lock, flags);
		i=0;
		list_for_each_entry(mcast_link, &dev->mcast_table[dlid - PIB_MCAST_LID_BASE], lid_list) {
			qp_nums[i] = mcast_link->qp_num;
			i++;
		}
		spin_unlock_irqrestore(&dev->lock, flags);

		max = i;

		port_lid = port->ib_port_attr.lid;
		slid     = be16_to_cpu(lrh->slid);

		/* 
		 * マルチキャストパケットを届ける QP は複数かもしれない。
		 * ただし送信した QP 自身は受け取らない。
		 */
		for (i=0 ; i<max ; i++) {
			if ((port_lid == slid) && (src_qp_num == qp_nums[i]))
				continue;

			pib_debug("pib: MC packet qp_num=0x%06x\n", qp_nums[i]);
			process_incoming_message_per_qp(dev, port_num, dlid, qp_nums[i],
							lrh, grh, bth, buffer, size);

			cond_resched();
		}
	}

silently_drop:
	return;

raw_packet:
	process_raw_packet(dev, port_num, lrh, buffer, size);
}


int pib_parse_packet_header(void *buffer, int size, struct pib_packet_lrh **lrh_p, struct ib_grh **grh_p, struct pib_packet_bth **bth_p)
{
	int ret = 0;
	struct pib_packet_lrh *lrh;
	struct ib_grh         *grh = NULL;
	struct pib_packet_bth *bth;
	u8 lnh;

	/* Analyze Local Route Hedaer */
	lrh = (struct pib_packet_lrh *)buffer;

	if (size < sizeof(*lrh))
		return -1;

	/* check packet length */
	if (pib_packet_lrh_get_pktlen(lrh) * 4 != size)
		return -1;

	buffer += sizeof(*lrh);
	size   -= sizeof(*lrh);
	ret    += sizeof(*lrh); 

	/* check Link Version */
	if ((lrh->vl_lver & 0xF) != 0)
		return -2;

	/* check Transport &  Next Header */
	lnh = (lrh->sl_rsv_lnh & 0x3);

	if (lnh == 0x2)
		/* IBA local */
		goto skip_grh;
	else if (lnh == 0) {
		/* Raw packt */
		*lrh_p = lrh;
		return ret;
	} else if (lnh != 0x3)
		return -3;

	/* IBA global */
	grh = (struct ib_grh *)buffer;

	if (size < sizeof(*grh))
		return -1;

	buffer += sizeof(*grh);
	size   -= sizeof(*grh);
	ret    += sizeof(*grh); 

skip_grh:
	/* Base Transport Header */
	bth = (struct pib_packet_bth *)buffer;

	if (size < sizeof(*bth))
		return -1;

	ret    += sizeof(*bth);

	*lrh_p = lrh;
	*grh_p = grh;
	*bth_p = bth;

	return ret;
}


static void process_incoming_message_per_qp(struct pib_dev *dev, u8 port_num, u16 dlid, u32 dest_qp_num, struct pib_packet_lrh *lrh, struct ib_grh *grh, struct pib_packet_bth *bth, void *buffer, int size)
{
	struct pib_port *port;
	unsigned long flags;
	struct pib_qp *qp;

	port = &dev->ports[port_num - 1];

	spin_lock_irqsave(&dev->lock, flags);

	switch (dest_qp_num) {

	case PIB_QP0:
	case PIB_QP1:
		qp = port->qp_info[dest_qp_num];
		break;

	case IB_MULTICAST_QPN:
		BUG();
		break;

	default:
		qp = pib_util_find_qp(dev, dest_qp_num);
		break;
	}

	if (qp == NULL) {
		port->ib_port_attr.qkey_viol_cntr++;
		spin_unlock_irqrestore(&dev->lock, flags);
		pib_debug("pib: drop packet: not found qp (qpn=0x%06x)\n", dest_qp_num);
		goto silently_drop;
	}

	/* LRH: check port LID and DLID of incoming packet */
	if ((dest_qp_num == PIB_QP0) && pib_is_permissive_lid(dlid))
		;
	else if (!pib_is_unicast_lid(dlid))
		;
	else if (dlid != port->ib_port_attr.lid) {
		spin_unlock_irqrestore(&dev->lock, flags);
		pib_debug("pib: drop packet: differ packet's dlid from port lid (0x%04x, 0x%04x)\n",
			  dlid, dev->ports[port_num - 1].ib_port_attr.lid);
		goto silently_drop;
	}

	/* Check P_Key */ 
	if (dest_qp_num == PIB_QP0) {
		/* C9-41: In the destination QP is QP0, the P_Key shall not
		   be checkd. */
	} else if (dest_qp_num == PIB_QP1) {
		/* C9-42: In the destination QP is QP1, the P_Key shall be
		   compared to the set of P_Keys associated with the port. */
		int i;
		for (i=0 ; i<PIB_PKEY_TABLE_LEN ; i++) {
			__be16 pkey = port->pkey_table[i];
			if (pkey == bth->pkey)
				goto pass_pkey_checking;
		}
		port->ib_port_attr.bad_pkey_cntr++;
		goto silently_drop;
	} else {
		/* C9-43: */
		__be16 pkey = port->pkey_table[qp->ib_qp_attr.pkey_index];
		if (pkey != bth->pkey) {
			port->ib_port_attr.bad_pkey_cntr++;
			goto silently_drop;			
		}
	}
pass_pkey_checking:

	/* @notice ロックの入れ子関係を一部崩している */
	spin_lock(&qp->lock);
	spin_unlock(&dev->lock);

	switch (qp->qp_type) {

	case IB_QPT_RC:
		pib_receive_rc_qp_incoming_message(dev, port_num, qp, lrh, grh, bth, buffer, size);
		break;

	case IB_QPT_UD:
	case IB_QPT_GSI:
	case IB_QPT_SMI:
		pib_receive_ud_qp_incoming_message(dev, port_num, qp, lrh, grh, bth, buffer, size);
		break;

	default:
		pr_emerg("pib: Error qp_type=%s in %s at %s:%u\n",
			 pib_get_qp_type(qp->qp_type), __FUNCTION__, __FILE__, __LINE__);
		BUG();
	}

	pib_util_reschedule_qp(qp);	

	spin_unlock_irqrestore(&qp->lock, flags);

	if (dev->thread.ready_to_send)
		process_sendmsg(dev);

silently_drop:

	return;
}


/******************************************************************************/
/* Raw Packet                                                                 */
/******************************************************************************/

static void connect_pibnetd(struct pib_dev *dev, u8 port_num)
{
	struct pib_port *port;

	port = &dev->ports[port_num-1];
	send_raw_packet_to_pibnetd(dev, port_num, false);
	pib_queue_delayed_work(dev, &port->link.work, 60 * HZ);
}


static void disconnect_pibnetd(struct pib_dev *dev, u8 port_num)
{
	struct pib_port *port;

	port = &dev->ports[port_num-1];

	send_raw_packet_to_pibnetd(dev, port_num, true);

	port->is_connected = false;
	port->ib_port_attr.phys_state = PIB_PHYS_PORT_POLLING;
	port->ib_port_attr.state      = IB_PORT_DOWN;
}


static void send_raw_packet_to_pibnetd(struct pib_dev *dev, u8 port_num, bool disconnect)
{
	void *buffer;
	struct pib_packet_lrh *lrh;
	struct pib_packet_link *link;

	buffer = dev->thread.send_buffer;

	lrh    = buffer;

	memset(lrh, 0, sizeof(*lrh));

	lrh->dlid = cpu_to_be16(PIB_LID_PERMISSIVE);
	lrh->slid = cpu_to_be16(PIB_LID_PERMISSIVE);

	buffer += sizeof(*lrh);

	link   = buffer;
	link->cmd = cpu_to_be32(disconnect ? PIB_LINK_CMD_DISCONNECT : PIB_LINK_CMD_CONNECT);

	buffer += sizeof(*link);

	pib_packet_lrh_set_pktlen(lrh, (buffer - dev->thread.send_buffer) / 4);

	dev->thread.port_num	  = port_num;
	dev->thread.src_qp_num	  = PIB_LINK_QP;
	dev->thread.slid	  = PIB_LID_PERMISSIVE;
	dev->thread.dlid	  = PIB_LID_PERMISSIVE;
	dev->thread.ready_to_send = 1;

	process_sendmsg(dev);
}


static void process_raw_packet(struct pib_dev *dev, u8 port_num, struct pib_packet_lrh *lrh, void *buffer, int size)
{
	struct pib_packet_link *link;
	struct pib_port *port;

	port = &dev->ports[port_num-1];

	if (size == sizeof(*link)) {
		link = buffer;
		switch (be32_to_cpu(link->cmd)) {
		case PIB_LINK_CMD_CONNECT_ACK:
			/* @tod lock */
			port->is_connected = true;
			port->ib_port_attr.phys_state = PIB_PHYS_PORT_LINK_UP;
			port->ib_port_attr.state      = IB_PORT_INIT;
			break;
		case PIB_LINK_CMD_DISCONNECT_ACK:
		case PIB_LINK_SHUTDOWN:
			port->is_connected = false;
			port->ib_port_attr.phys_state = PIB_PHYS_PORT_POLLING;
			port->ib_port_attr.state      = IB_PORT_DOWN;
			break;
		default:
			break;
		}
	}
}


void pib_netd_comm_handler(struct pib_work_struct *work)
{
	struct pib_dev *dev = work->dev;
	struct pib_port *port = work->data;

	BUG_ON(!spin_is_locked(&dev->lock));

	if (port->ib_port_attr.state == IB_PORT_DOWN)
		/* 再設定 */
		connect_pibnetd(dev, port->port_num);
}


/******************************************************************************/
/*                                                                            */
/******************************************************************************/

void pib_util_reschedule_qp(struct pib_qp *qp)
{
	struct pib_dev *dev;
	unsigned long flags;
	unsigned long now, schedule_time;
	struct pib_send_wqe *send_wqe;
	struct rb_node **link;
	struct rb_node *parent = NULL;
	struct rb_node *rb_node;

	dev = to_pdev(qp->ib_qp.device);

	/************************************************************/
	/* Red/Black tree からの取り外し                            */
	/************************************************************/

	spin_lock_irqsave(&dev->qp_sched.lock, flags);
	if (qp->sched.on) {
		qp->sched.on = 0;
		rb_erase(&qp->sched.rb_node, &dev->qp_sched.rb_root);
	}
	spin_unlock_irqrestore(&dev->qp_sched.lock, flags);

	/************************************************************/
	/* 再計算                                                   */
	/************************************************************/
	now = jiffies;
	schedule_time = now + PIB_SCHED_TIMEOUT;

	if ((qp->qp_type == IB_QPT_RC) && pib_is_recv_ok(qp->state))
		if (!list_empty(&qp->responder.ack_head) &&
		    (qp->responder.nr_contig_read_acks < PIB_MAX_CONTIG_READ_ACKS)) {
			schedule_time = now;
			goto skip;
		}

	if ((qp->state != IB_QPS_RTS) && (qp->state != IB_QPS_SQD))
		return;

	if (!list_empty(&qp->requester.waiting_swqe_head)) {
		send_wqe = list_first_entry(&qp->requester.waiting_swqe_head, struct pib_send_wqe, list);

		if (time_before(send_wqe->processing.local_ack_time, schedule_time))
			schedule_time = send_wqe->processing.local_ack_time;
	}

	if (!list_empty(&qp->requester.sending_swqe_head)) {
		send_wqe = list_first_entry(&qp->requester.sending_swqe_head, struct pib_send_wqe, list);

		if (send_wqe->processing.status != IB_WC_SUCCESS)
			if (!list_empty(&qp->requester.waiting_swqe_head))
				goto skip;

		if (PIB_MAX_CONTIG_REQUESTS < qp->requester.nr_contig_requests)
			goto skip;

		if (time_before(send_wqe->processing.schedule_time, schedule_time))
			schedule_time = send_wqe->processing.schedule_time;
	}

	if ((qp->state == IB_QPS_RTS) && !list_empty(&qp->requester.submitted_swqe_head)) {
		send_wqe = list_first_entry(&qp->requester.submitted_swqe_head, struct pib_send_wqe, list);

		if (pib_is_wr_opcode_rd_atomic(send_wqe->opcode))
			if (qp->requester.max_rd_atomic <= qp->requester.nr_rd_atomic)
				goto skip;

		schedule_time = now;
	}

skip:
	if (schedule_time == now + PIB_SCHED_TIMEOUT)
		return;

	qp->sched.time = schedule_time;
	qp->sched.tid  = dev->qp_sched.master_tid++;

	/************************************************************/
	/* Red/Black tree への登録                                  */
	/************************************************************/
	spin_lock_irqsave(&dev->qp_sched.lock, flags);
	link = &dev->qp_sched.rb_root.rb_node;
	while (*link) {
		int cond;
		struct pib_qp *qp_tmp;

		parent = *link;
		qp_tmp = rb_entry(parent, struct pib_qp, sched.rb_node);

		if (qp_tmp->sched.time != schedule_time)
			cond = time_after(qp_tmp->sched.time, schedule_time);
		else
			cond = ((long)(qp_tmp->sched.tid - qp->sched.tid) > 0);

		if (cond)
			link = &parent->rb_left;
		else
			link = &parent->rb_right;
	}
	rb_link_node(&qp->sched.rb_node, parent, link);
	rb_insert_color(&qp->sched.rb_node, &dev->qp_sched.rb_root);
	qp->sched.on = 1;

	/* calculate the most early time  */
	rb_node = rb_first(&dev->qp_sched.rb_root);
	BUG_ON(rb_node == NULL);
	qp = rb_entry(rb_node, struct pib_qp, sched.rb_node);
	dev->qp_sched.wakeup_time = qp->sched.time;

	spin_unlock_irqrestore(&dev->qp_sched.lock, flags);

	if (time_before_eq(dev->qp_sched.wakeup_time, now))
		set_bit(PIB_THREAD_QP_SCHEDULE, &dev->thread.flags);
}


struct pib_qp *pib_util_get_first_scheduling_qp(struct pib_dev *dev)
{
	unsigned long flags;
	struct rb_node *rb_node;
	struct pib_qp *qp = NULL;

	spin_lock_irqsave(&dev->qp_sched.lock, flags);

	rb_node = rb_first(&dev->qp_sched.rb_root);

	if (rb_node == NULL)
		goto done;

	qp = rb_entry(rb_node, struct pib_qp, sched.rb_node);
done:

	spin_unlock_irqrestore(&dev->qp_sched.lock, flags);

	return qp;
}

/******************************************************************************/
/*                                                                            */
/******************************************************************************/

static void process_on_wq_scheduler(struct pib_dev *dev)
{
	unsigned long flags;
	struct pib_work_struct *work;

retry:
	spin_lock_irqsave(&dev->lock, flags);
	spin_lock(&dev->wq_sched.lock);

	if (list_empty(&dev->wq_sched.head)) {
		spin_unlock(&dev->wq_sched.lock);
		spin_unlock_irqrestore(&dev->lock, flags);
		return;
	}
	spin_unlock(&dev->wq_sched.lock);
	
	work = list_first_entry(&dev->wq_sched.head, struct pib_work_struct, entry);
	list_del_init(&work->entry);

	work->func(work);

	spin_unlock_irqrestore(&dev->lock, flags);

	goto retry;
}


void pib_queue_work(struct pib_dev *dev, struct pib_work_struct *work)
{
	unsigned long flags;

	spin_lock_irqsave(&dev->wq_sched.lock, flags);
	list_add_tail(&work->entry, &dev->wq_sched.head);
	spin_unlock_irqrestore(&dev->wq_sched.lock, flags);

	set_bit(PIB_THREAD_WQ_SCHEDULE, &dev->thread.flags);
	complete(&dev->thread.completion);
}


void pib_queue_delayed_work(struct pib_dev *dev, struct pib_work_struct *work, unsigned long delay)
{
	unsigned long flags;

	spin_lock_irqsave(&dev->wq_sched.lock, flags);
	list_add_tail(&work->entry, &dev->wq_sched.timer_head);
	work->on_timer = true;
	work->timer.function	= delayed_work_timeout_callback;
	work->timer.data	= (unsigned long)work;
	work->timer.expires	= jiffies + delay;
	add_timer(&work->timer);
	spin_unlock_irqrestore(&dev->wq_sched.lock, flags);
}


void pib_cancel_work(struct pib_dev *dev, struct pib_work_struct *work)
{
	unsigned long flags;

	spin_lock_irqsave(&dev->wq_sched.lock, flags);
	list_del_init(&work->entry);
	spin_unlock_irqrestore(&dev->wq_sched.lock, flags);
}


void pib_stop_delayed_queue(struct pib_dev *dev)
{
	unsigned long flags;
	struct pib_work_struct *work, *next_work;

	spin_lock_irqsave(&dev->wq_sched.lock, flags);
	list_for_each_entry_safe(work, next_work, &dev->wq_sched.timer_head, entry) {
		list_del_init(&work->entry);
		list_add_tail(&work->entry, &dev->wq_sched.head);
		del_timer_sync(&work->timer);
		work->on_timer = false;
	}
	spin_unlock_irqrestore(&dev->wq_sched.lock, flags);
}


/******************************************************************************/
/*                                                                            */
/******************************************************************************/
static void process_sendmsg(struct pib_dev *dev)
{
	int ret;
	u8 port_num;
	u32 src_qp_num;
	u16 slid;
	u16 dlid;
	struct sockaddr *sockaddr;
	struct msghdr	msghdr;
	struct kvec	iov;
	struct pib_port *port;
	union pib_packet_footer *footer;
	size_t msg_size;

	port_num   = dev->thread.port_num;
	src_qp_num = dev->thread.src_qp_num;
	slid       = dev->thread.slid;
	dlid       = dev->thread.dlid;

	port = &dev->ports[port_num - 1];

	/* QP0 と LINK_QP 以外は SLID または DLID が 0 のパケットは投げない */
	if ((src_qp_num != PIB_QP0) && (src_qp_num != PIB_LINK_QP))
		if ((slid == 0) || (dlid == 0))
			goto done;

	switch (port->ib_port_attr.state) {
	case IB_PORT_DOWN:
		if (src_qp_num != PIB_LINK_QP)
			return;
		break;
	case IB_PORT_INIT:
	case IB_PORT_ARMED:
		/* The link layer can only transmit and receive SMP. */
		if ((src_qp_num != PIB_QP0) && (src_qp_num != PIB_LINK_QP))
			return;
		break;
	case IB_PORT_ACTIVE:
		/* The link layer can transmit and receive all packet types. */
		break;
	default:
		/* The physical link is not up or error */
		return;
	}

	/* 送信サイズを確定 */
	msg_size = pib_packet_lrh_get_pktlen(dev->thread.send_buffer) * 4;

	if ((0 == msg_size) || (PIB_PACKET_BUFFER < msg_size)) {
		pr_err("pib: wrong length = %zu\n", msg_size);
		return;
	}

	/* フッターとして VCRC が入る領域に Port GUID を入れる */
	footer = dev->thread.send_buffer + msg_size;
	footer->pib.port_guid = port->gid[0].global.interface_id;

	msg_size += sizeof(*footer);

	pib_trace_send(dev, port_num, msg_size);

	sockaddr = get_sockaddr_from_dlid(dev, port_num, src_qp_num, dlid);
	if (!sockaddr) {
		pr_err("pib: Not found the destination address in ld_table (dlid=%u)", dlid);
		goto done;
	}

	memset(&msghdr, 0, sizeof(msghdr));

	msghdr.msg_name    = sockaddr;
	msghdr.msg_namelen = (sockaddr->sa_family == AF_INET6) ?
		sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);

	iov.iov_base = dev->thread.send_buffer;
	iov.iov_len  = msg_size;

	ret = kernel_sendmsg(port->socket, &msghdr, &iov, 1, iov.iov_len);

	if (ret < 0) {
		if ((ret == -EINTR) || (ret == -EAGAIN))
			goto done;
		pr_err("pib: kernel_sendmsg (errno=%d)\n", ret);
		goto done;
	}

	port->perf.xmit_packets++;
	port->perf.xmit_data += msg_size;

	if (pib_is_unicast_lid(dlid))
		goto done;

	/*
	 * マルチキャストの場合、同じ HCA に同一の multicast group の受け取りを
	 * する別の QP がある可能性があるので、loopback にも受信させる。
	 */
	sockaddr           = port->sockaddr;
	msghdr.msg_name    = sockaddr;
	msghdr.msg_namelen = (sockaddr->sa_family == AF_INET6) ?
		sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);

	ret = kernel_sendmsg(port->socket, &msghdr, &iov, 1, iov.iov_len);

done:
	dev->thread.trace_id	  = 0;
	dev->thread.ready_to_send = 0;
}


static struct sockaddr *
get_sockaddr_from_dlid(struct pib_dev *dev, u8 port_num, u32 src_qp_num, u16 dlid)
{
	unsigned long flags;
	struct sockaddr *sockaddr = NULL;

	if (pib_multi_host_mode)
		return pib_netd_sockaddr;

	if (src_qp_num != PIB_QP0) {
		if (dlid == 0)
			sockaddr = dev->ports[port_num - 1].sockaddr;
		else if (dlid == dev->ports[port_num - 1].ib_port_attr.lid)
			/* loopback */
			sockaddr = dev->ports[port_num - 1].sockaddr;
		else if (dlid < PIB_MCAST_LID_BASE)
			/* unicast */
			sockaddr = pib_lid_table[dlid];
	}

	if (sockaddr)
		return sockaddr;

	/* multicast packets or packets to switch */
	spin_lock_irqsave(&pib_easy_sw.lock, flags);
	sockaddr = pib_easy_sw.sockaddr;
	spin_unlock_irqrestore(&pib_easy_sw.lock, flags);

	return sockaddr;
}


/******************************************************************************/
/*                                                                            */
/******************************************************************************/

static void sock_data_ready_callback(struct sock *sk, int bytes)
{
	struct pib_dev* dev  = (struct pib_dev*)sk->sk_user_data;

	set_bit(PIB_THREAD_READY_TO_RECV, &dev->thread.flags);
	complete(&dev->thread.completion);
}


static void timer_timeout_callback(unsigned long opaque)
{
	struct pib_dev* dev  = (struct pib_dev*)opaque;
	
	set_bit(PIB_THREAD_QP_SCHEDULE, &dev->thread.flags);
	complete(&dev->thread.completion);
}


static void delayed_work_timeout_callback(unsigned long data)
{
	struct pib_work_struct *work = (struct pib_work_struct*)data;
	struct pib_dev *dev = work->dev;
	unsigned long flags;

	spin_lock_irqsave(&dev->wq_sched.lock, flags);
	work->on_timer = false;
	list_del_init(&work->entry);
	list_add_tail(&work->entry, &dev->wq_sched.head);
	spin_unlock_irqrestore(&dev->wq_sched.lock, flags);

	set_bit(PIB_THREAD_WQ_SCHEDULE, &dev->thread.flags);
	complete(&dev->thread.completion);
}
