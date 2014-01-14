/*
 * Copyright (c) 2013 Minoru NAKAMURA <nminoru@nminoru.jp>
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


static int kthread_routine(void *data);
static int create_socket(struct pib_ib_dev *dev, int port_index);
static void release_socket(struct pib_ib_dev *dev, int port_index);
static void process_on_scheduler(struct pib_ib_dev *dev);
static int  process_new_send_wr(struct pib_ib_qp *qp);
static int process_send_wr(struct pib_ib_dev *dev, struct pib_ib_qp *qp, struct pib_ib_send_wqe *send_wqe);
static int process_incoming_message(struct pib_ib_dev *dev, int port_index);
static void process_sendmsg(struct pib_ib_dev *dev);
static void sock_data_ready_callback(struct sock *sk, int bytes);
static void timer_timeout_callback(unsigned long opaque);


int pib_create_kthread(struct pib_ib_dev *dev)
{
	int i, j, ret;
	struct task_struct *task;

	init_completion(&dev->thread.completion);
	init_timer(&dev->thread.timer);

	dev->thread.timer.function = timer_timeout_callback;
	dev->thread.timer.data     = (unsigned long)dev;

	dev->thread.buffer         = vmalloc(PIB_IB_PACKET_BUFFER);
	if (!dev->thread.buffer) {
		ret = -ENOMEM;
		goto err_vmalloc;
	}

	for (i=0 ; i < dev->ib_dev.phys_port_cnt ; i++) {
		ret = create_socket(dev, i);
		if (ret < 0)
			goto err_sock;
	}

	task = kthread_create(kthread_routine, dev, "pib_%d", dev->ib_dev_id);
	if (IS_ERR(task))
		goto err_task;

	dev->thread.task = task;

	wake_up_process(task);

	return 0;

err_task:
	ret = PTR_ERR(task);
	
err_sock:
	for (j = i-1 ; 0 <= j ; j--)
		release_socket(dev, j);

	vfree(dev->thread.buffer);

err_vmalloc:

	return ret;
}


void pib_release_kthread(struct pib_ib_dev *dev)
{
	int i;

	smp_wmb();

	del_timer_sync(&dev->thread.timer);

	if (dev->thread.task) {
		complete(&dev->thread.completion);
		/* flush_kthread_worker(worker); */
		kthread_stop(dev->thread.task);
		dev->thread.task = NULL;
	}

	for (i=dev->ib_dev.phys_port_cnt - 1 ; 0 <= i  ; i--)
		release_socket(dev, i);

	vfree(dev->thread.buffer);
}


static int create_socket(struct pib_ib_dev *dev, int port_index)
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
	socket->sk->sk_user_data  = dev;
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

#if 0
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 11, 0)
	pib_debug("kernel_getsockname: %pISpc\n",
		  (const struct sockaddr*)&sockaddr_in);
#else
	pib_debug("kernel_getsockname: %08x:%u\n",
		  ntohl(sockaddr_in.sin_addr.s_addr),
		  ntohs(sockaddr_in.sin_port));
#endif
#endif

	dev->ports[port_index].socket = socket;

	/* register lid_table */
	sockaddr_in_p  = kzalloc(sizeof(struct sockaddr_in), GFP_KERNEL);

	sockaddr_in_p->sin_family	= AF_INET;
	sockaddr_in_p->sin_addr.s_addr	= htonl(INADDR_LOOPBACK);
	sockaddr_in_p->sin_port		= sockaddr_in.sin_port;

	dev->ports[port_index].sockaddr	= (struct sockaddr *)sockaddr_in_p;

	return 0;

err_sock:
	sock_release(socket);

	return ret;
}


static void release_socket(struct pib_ib_dev *dev, int port_index)
{
#ifndef PIB_USE_EASY_SWITCH
	int i;
#endif

	if (dev->ports[port_index].sockaddr) {
		kfree(dev->ports[port_index].sockaddr);
		dev->ports[port_index].sockaddr = NULL;
	}

#ifndef PIB_USE_EASY_SWITCH
	for (i=0 ; i<PIB_IB_MAX_LID ; i++) {
		if (dev->ports[port_index].lid_table[i]) {
			kfree(dev->ports[port_index].lid_table[i]);
			dev->ports[port_index].lid_table[i] = NULL;
		}
	}
#endif

	if (dev->ports[port_index].socket) {
		sock_release(dev->ports[port_index].socket);
		dev->ports[port_index].socket = NULL;
	}
}


static int kthread_routine(void *data)
{
	struct pib_ib_dev *dev;
	
	dev = (struct pib_ib_dev *)data;

	BUG_ON(!dev);

#if 0
	/* Hibernation / freezing of the SRPT kernel thread is not supported. */
	current->flags |= PF_NOFREEZE;
#endif

	while (!kthread_should_stop()) {
		unsigned long flags;
		unsigned long timeout = HZ;

		/* 停止時間を計算。ただし1 秒以上は停止させない */
		spin_lock_irqsave(&dev->schedule.lock, flags);
		if (time_after(dev->schedule.wakeup_time, jiffies))
			timeout = dev->schedule.wakeup_time - jiffies;
		else
			dev->schedule.wakeup_time = jiffies;
		if (HZ < timeout)
			timeout = HZ;
		spin_unlock_irqrestore(&dev->schedule.lock, flags);

		wait_for_completion_interruptible_timeout(&dev->thread.completion, timeout);
		init_completion(&dev->thread.completion);

		while (dev->thread.flags) {
			cond_resched();

			if (test_and_clear_bit(PIB_THREAD_READY_TO_RECV, &dev->thread.flags)) {
				int i, ret;
				for (i=0 ; i < dev->ib_dev.phys_port_cnt ; i++) {
					do {
						ret = process_incoming_message(dev, i);
					} while (ret == 0);
				}
			}

			if (test_and_clear_bit(PIB_THREAD_SCHEDULE, &dev->thread.flags))
				process_on_scheduler(dev);
		}
	}

	return 0;
}


static void process_on_scheduler(struct pib_ib_dev *dev)
{
	int ret;
	unsigned long now;
	unsigned long flags;
	struct pib_ib_qp *qp;
	struct pib_ib_send_wqe *send_wqe, *next_send_wqe;

restart:
	now = jiffies;

	down_write(&dev->rwsem);

	qp = pib_util_get_first_scheduling_qp(dev);
	if (!qp) {
		up_write(&dev->rwsem);
		return;
	}

	down(&qp->sem);

	up_write(&dev->rwsem);

	/* Responder: generating acknowledge packets */
	if (qp->qp_type == IB_QPT_RC)
		if (pib_generate_rc_qp_acknowledge(dev, qp) == 1)
			goto done;

	/* Requester: generating request packets */
	if ((qp->state != IB_QPS_RTS) && (qp->state != IB_QPS_SQD))
		goto done;

	/*
	 *  Waiting listE の先頭の Send WQE が再送時刻に達していれば
	 *  waiting list から sending list へ戻して再送信を促す。
	 */
	if (list_empty(&qp->requester.waiting_swqe_head))
		goto first_sending_wsqe;

	send_wqe = list_first_entry(&qp->requester.waiting_swqe_head, struct pib_ib_send_wqe, list);

	if (time_after(send_wqe->processing.local_ack_time, now))
		goto first_sending_wsqe;

	send_wqe->processing.retry_cnt--;
	send_wqe->processing.local_ack_time = now + PIB_SCHED_TIMEOUT;

	/* waiting list から sending list へ戻す */
	list_for_each_entry_safe_reverse(send_wqe, next_send_wqe, &qp->requester.waiting_swqe_head, list) {
		send_wqe->processing.list_type = PIB_SWQE_SENDING;
		list_del_init(&send_wqe->list);
		list_add_tail(&send_wqe->list, &qp->requester.sending_swqe_head);
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

	send_wqe = list_first_entry(&qp->requester.sending_swqe_head, struct pib_ib_send_wqe, list);

	/*
	 *  Sending list の先頭の Send WQE がエラーだが、waiting list が
	 *  残っている場合、waiting list から空になるまで送信は再開しない。
	 */
	if (send_wqe->processing.status != IB_WC_SUCCESS)
		if (!list_empty(&qp->requester.waiting_swqe_head))
			goto done;

	/*
	 *  IB_SEND_FENCE フラグがある場合、先行する RDMA READ & Atomic 操作の
	 *  完了を待つ。
	 */
	if (send_wqe->send_flags & IB_SEND_FENCE)
		if (0 < qp->requester.nr_rd_atomic)
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
		qp->requester.nr_sending_swqe--;
		list_add_tail(&send_wqe->list, &qp->requester.waiting_swqe_head);
		qp->requester.nr_waiting_swqe++;
		break;

	default:
		pr_emerg("pib: Error qp_type=%s in %s at %s:%u\n",
			 pib_get_qp_type(qp->qp_type), __FUNCTION__, __FILE__, __LINE__);
		BUG();
	}

done:
	pib_util_reschedule_qp(qp); /* 必要の応じてスケジューラから抜くために呼び出す */

	up(&qp->sem);

	if (dev->thread.ready_to_send)
		process_sendmsg(dev);

	if (dev->thread.flags & PIB_THREAD_READY_TO_RECV)
		return;

	spin_lock_irqsave(&dev->schedule.lock, flags);
	if (time_after(dev->schedule.wakeup_time, jiffies)) {
		spin_unlock_irqrestore(&dev->schedule.lock, flags);
		return;
	}
	spin_unlock_irqrestore(&dev->schedule.lock, flags);

	cond_resched();

	goto restart;
}


static int process_new_send_wr(struct pib_ib_qp *qp)
{
	struct pib_ib_send_wqe *send_wqe;
	u32 num_packets;
	unsigned long now;

	if (qp->state != IB_QPS_RTS)
		return 0;

	if (list_empty(&qp->requester.submitted_swqe_head))
		return 0;

	send_wqe = list_first_entry(&qp->requester.submitted_swqe_head, struct pib_ib_send_wqe, list);

	if (pib_is_wr_opcode_rd_atomic(send_wqe->opcode)) {
		if (qp->ib_qp_attr.max_rd_atomic <= qp->requester.nr_rd_atomic)
			return 0;
		qp->requester.nr_rd_atomic++;
	}

	list_del_init(&send_wqe->list);
	qp->requester.nr_submitted_swqe--;

	list_add_tail(&send_wqe->list, &qp->requester.sending_swqe_head);
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
static int process_send_wr(struct pib_ib_dev *dev, struct pib_ib_qp *qp, struct pib_ib_send_wqe *send_wqe)
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


static int process_incoming_message(struct pib_ib_dev *dev, int port_index)
{
	int ret;
	struct msghdr msghdr = {.msg_flags = MSG_DONTWAIT | MSG_NOSIGNAL};
	struct kvec iov;
	void *buffer;
	struct pib_packet_lrh *lrh;
	struct pib_packet_bth *bth;
	u32 dest_qpn;
	struct pib_ib_qp *qp;
	const u8 port_num = port_index + 1;

	buffer = dev->thread.buffer;

	iov.iov_base = buffer;
	iov.iov_len  = PIB_IB_PACKET_BUFFER;

	ret = kernel_recvmsg(dev->ports[port_index].socket, &msghdr,
			     &iov, 1, iov.iov_len, msghdr.msg_flags);

	if (ret < 0) {
		if (ret == -EINTR)
			set_bit(PIB_THREAD_READY_TO_RECV, &dev->thread.flags);
		return ret;
	} else if (ret == 0)
		return -EAGAIN;

	/* Analyze Local Route Hedaer */
	if (ret < sizeof(struct pib_packet_lrh))
		goto silently_drop;

	lrh = (struct pib_packet_lrh*)buffer;

	/* check packet length */
	if (pib_packet_lrh_get_pktlen(lrh) * 4 != ret)
		goto silently_drop;

	buffer += sizeof(*lrh);
	ret    -= sizeof(*lrh);

	/* 0x2: Transport: IBA, Next Header: BTH */
	if ((lrh->sl_rsv_lnh & 0x3) != 1)
		goto silently_drop;

	/* Analyze Base Transport Header */
	if (ret < sizeof(struct pib_packet_bth))
		goto silently_drop;

	bth = (struct pib_packet_bth *)buffer;

	buffer += sizeof(*bth);
	ret    -= sizeof(*bth);

	/* Payload */
	ret -= pib_packet_bth_get_padcnt(bth); /* Pad Count */
	if (ret < 0)
		goto silently_drop; /* @todo ERROR */

	if ((lrh->vl_lver & 0xF) != 0) /* Link Version */
		goto silently_drop;

	dest_qpn = be32_to_cpu(bth->destQP) & PIB_IB_QPN_MASK;

	down_read(&dev->rwsem);

	if ((dest_qpn == PIB_IB_QP0) || (dest_qpn == PIB_IB_QP1))
		qp = dev->ports[port_index].qp_info[dest_qpn];
	else
		qp = pib_util_find_qp(dev, dest_qpn);

	if (qp == NULL) {
		up_read(&dev->rwsem);
		goto silently_drop;
	}

	/* LRH: check port LID and DLID of incoming packet */
	if (((dest_qpn == PIB_IB_QP0) && (lrh->dlid == IB_LID_PERMISSIVE)))
		;
	else if (be16_to_cpu(lrh->dlid) != dev->ports[port_index].ib_port_attr.lid) {
		up_read(&dev->rwsem);
		goto silently_drop;
	}

	down(&qp->sem);
	up_read(&dev->rwsem); /* @notice */

	switch (qp->qp_type) {

	case IB_QPT_RC:
		pib_receive_rc_qp_incoming_message(dev, port_num, qp, buffer, ret, lrh, bth);
		break;

	case IB_QPT_UD:
	case IB_QPT_GSI:
	case IB_QPT_SMI:
		pib_receive_ud_qp_SEND_request(dev, port_num, qp, buffer, ret, lrh, bth);
		break;

	default:
		pr_emerg("pib: Error qp_type=%s in %s at %s:%u\n",
			 pib_get_qp_type(qp->qp_type), __FUNCTION__, __FILE__, __LINE__);
		BUG();
	}

	pib_util_reschedule_qp(qp);	

	up(&qp->sem);

	if (dev->thread.ready_to_send)
		process_sendmsg(dev);

silently_drop:
	return 0;
}


/******************************************************************************/
/*                                                                            */
/******************************************************************************/

void pib_util_reschedule_qp(struct pib_ib_qp *qp)
{
	struct pib_ib_dev *dev;
	unsigned long flags;
	unsigned long now, schedule_time;
	struct pib_ib_send_wqe *send_wqe;
	struct rb_node **link;
	struct rb_node *parent = NULL;
	struct rb_node *rb_node;

	dev = to_pdev(qp->ib_qp.device);

	/************************************************************/
	/* Red/Black tree からの取り外し                            */
	/************************************************************/

	spin_lock_irqsave(&dev->schedule.lock, flags);
	if (qp->schedule.on) {
		qp->schedule.on = 0;
		rb_erase(&qp->schedule.rb_node, &dev->schedule.rb_root);
	}
	spin_unlock_irqrestore(&dev->schedule.lock, flags);

	/************************************************************/
	/* 再計算                                                   */
	/************************************************************/
	now = jiffies;
	schedule_time = now + PIB_SCHED_TIMEOUT;

	if ((qp->qp_type == IB_QPT_RC) && pib_is_recv_ok(qp->state))
		if (!list_empty(&qp->responder.ack_head)) {
			schedule_time = now;
			goto skip;
		}

	if ((qp->state != IB_QPS_RTS) && (qp->state != IB_QPS_SQD))
		return;

	if (!list_empty(&qp->requester.waiting_swqe_head)) {
		send_wqe = list_first_entry(&qp->requester.waiting_swqe_head, struct pib_ib_send_wqe, list);

		if (time_before(send_wqe->processing.local_ack_time, schedule_time))
			schedule_time = send_wqe->processing.local_ack_time;
	}

	if (!list_empty(&qp->requester.sending_swqe_head)) {
		send_wqe = list_first_entry(&qp->requester.sending_swqe_head, struct pib_ib_send_wqe, list);

		if (send_wqe->processing.status != IB_WC_SUCCESS)
			if (!list_empty(&qp->requester.waiting_swqe_head))
				goto skip;

		if (send_wqe->send_flags & IB_SEND_FENCE)
			if (0 < qp->requester.nr_rd_atomic)
				goto skip;

		if (time_before(send_wqe->processing.schedule_time, schedule_time))
			schedule_time = send_wqe->processing.schedule_time;
	}

	if ((qp->state == IB_QPS_RTS) && !list_empty(&qp->requester.submitted_swqe_head)) {
		send_wqe = list_first_entry(&qp->requester.submitted_swqe_head, struct pib_ib_send_wqe, list);

		if (pib_is_wr_opcode_rd_atomic(send_wqe->opcode))
			if (qp->ib_qp_attr.max_rd_atomic <= qp->requester.nr_rd_atomic)
				goto skip;

		schedule_time = now;
	}

skip:
	if (schedule_time == now + PIB_SCHED_TIMEOUT)
		return;

	qp->schedule.time = schedule_time;
	qp->schedule.tid  = dev->schedule.master_tid;

	/************************************************************/
	/* Red/Black tree への登録                                  */
	/************************************************************/
	spin_lock_irqsave(&dev->schedule.lock, flags);
	link = &dev->schedule.rb_root.rb_node;
	while (*link) {
		int cond;
		struct pib_ib_qp *qp_tmp;

		parent = *link;
		qp_tmp = rb_entry(parent, struct pib_ib_qp, schedule.rb_node);

		if (qp_tmp->schedule.time != schedule_time)
			cond = time_after(qp_tmp->schedule.time, schedule_time);
		else
			cond = ((long)(qp_tmp->schedule.tid - qp->schedule.tid) > 0);

		if (cond)
			link = &parent->rb_left;
		else
			link = &parent->rb_right;
	}
	rb_link_node(&qp->schedule.rb_node, parent, link);
	rb_insert_color(&qp->schedule.rb_node, &dev->schedule.rb_root);
	qp->schedule.on = 1;

	/* calculate the most early time  */
	rb_node = rb_first(&dev->schedule.rb_root);
	BUG_ON(rb_node == NULL);
	qp = rb_entry(rb_node, struct pib_ib_qp, schedule.rb_node);
	dev->schedule.wakeup_time = qp->schedule.time;

	spin_unlock_irqrestore(&dev->schedule.lock, flags);

	if (time_before_eq(dev->schedule.wakeup_time, now))
		set_bit(PIB_THREAD_SCHEDULE, &dev->thread.flags);
}


struct pib_ib_qp *pib_util_get_first_scheduling_qp(struct pib_ib_dev *dev)
{
	unsigned long flags;
	struct rb_node *rb_node;
	struct pib_ib_qp *qp = NULL;

	spin_lock_irqsave(&dev->schedule.lock, flags);

	rb_node = rb_first(&dev->schedule.rb_root);

	if (rb_node == NULL)
		goto done;

	qp = rb_entry(rb_node, struct pib_ib_qp, schedule.rb_node);
done:

	spin_unlock_irqrestore(&dev->schedule.lock, flags);

	return qp;
}


/******************************************************************************/
/*                                                                            */
/******************************************************************************/
static void process_sendmsg(struct pib_ib_dev *dev)
{
	int ret;
	struct msghdr	msghdr;
	struct kvec	iov;

	BUG_ON(dev->thread.sockaddr == NULL);
	BUG_ON(dev->thread.msg_size == 0);

	memset(&msghdr, 0, sizeof(msghdr));

	msghdr.msg_name    = dev->thread.sockaddr;
	msghdr.msg_namelen = (dev->thread.sockaddr->sa_family == AF_INET6) ?
		sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);	

	iov.iov_base = dev->thread.buffer;
	iov.iov_len  = dev->thread.msg_size;

	ret = kernel_sendmsg(dev->ports[dev->thread.port_num - 1].socket,
			     &msghdr, &iov, 1, iov.iov_len);

	dev->thread.sockaddr = NULL;
	dev->thread.msg_size = 0;
	dev->thread.ready_to_send = 0;
}


/******************************************************************************/
/*                                                                            */
/******************************************************************************/

static void sock_data_ready_callback(struct sock *sk, int bytes)
{
	struct pib_ib_dev* dev  = (struct pib_ib_dev*)sk->sk_user_data;

	set_bit(PIB_THREAD_READY_TO_RECV, &dev->thread.flags);
	complete(&dev->thread.completion);
}


static void timer_timeout_callback(unsigned long opaque)
{
	struct pib_ib_dev* dev  = (struct pib_ib_dev*)opaque;
	
	set_bit(PIB_THREAD_SCHEDULE, &dev->thread.flags);
	complete(&dev->thread.completion);
}
