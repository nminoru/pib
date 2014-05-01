/*
 * pib_qp.c - Queue Pair(QP) functions
 *
 * Copyright (c) 2013,2014 Minoru NAKAMURA <nminoru@nminoru.jp>
 *
 * This code is licenced under the GPL version 2 or BSD license.
 */
#include <linux/module.h>
#include <linux/init.h>
#include <rdma/ib_pack.h>

#include "pib.h"
#include "pib_trace.h"


static bool qp_init_attr_is_ok(const struct pib_dev *dev, const struct ib_qp_init_attr *init_attr);
static bool qp_cap_is_ok(const struct pib_dev *dev, const struct ib_qp_cap *cap, int use_srq);
static void dealloc_free_wqe(struct pib_qp *qp);
static bool modify_qp_is_ok(const struct pib_dev *dev, const struct pib_qp *qp, enum ib_qp_state cur_state, const struct ib_qp_attr *attr, int attr_mask);
static void get_ready_to_send(struct pib_dev *dev, struct pib_qp *qp);
static int reset_qp(struct pib_qp *qp);
static void reset_qp_attr(struct pib_qp *qp);
static int copy_inline_data(struct pib_qp *qp, struct pib_send_wqe *send_wqe, u64 total_length);


struct pib_qp *pib_util_find_qp(struct pib_dev *dev, int qp_num)
{
	struct rb_node *node = dev->qp_table.rb_node;

	while (node) {
		int ret;
		struct pib_qp *qp;

		qp  = rb_entry(node, struct pib_qp, rb_node);

		ret = (int)qp->ib_qp.qp_num - qp_num;

		if (ret > 0)
			node = node->rb_left;
		else if (ret < 0)
			node = node->rb_right;
		else
			return qp;
	}

	return NULL;
}


static void insert_qp(struct pib_dev *dev, struct pib_qp *qp)
{
	int qp_num;
	struct rb_node **link = &dev->qp_table.rb_node;
	struct rb_node *parent = NULL;

	qp_num = qp->ib_qp.qp_num;

	while (*link) {
		struct pib_qp *qp_tmp;

		parent = *link;
		qp_tmp = rb_entry(parent, struct pib_qp, rb_node);

		if (qp_tmp->ib_qp.qp_num > qp_num)
			link = &parent->rb_left;
		else
			link = &parent->rb_right;
	}

	rb_link_node(&qp->rb_node, parent, link);
	rb_insert_color(&qp->rb_node, &dev->qp_table);
}


static int get_send_wr_num(const struct pib_qp *qp)
{
	return qp->requester.nr_submitted_swqe +
		qp->requester.nr_sending_swqe +
		qp->requester.nr_waiting_swqe;
}


void pib_util_flush_qp(struct pib_qp *qp, int send_only)
{
	struct pib_send_wqe *send_wqe, *next_send_wqe;
	struct pib_recv_wqe *recv_wqe, *next_recv_wqe;
	struct pib_ack *ack, *ack_next;

	BUG_ON(!spin_is_locked(&qp->lock));

	list_for_each_entry_safe(send_wqe, next_send_wqe, &qp->requester.waiting_swqe_head, list) {
		pib_util_insert_wc_error(qp->send_cq, qp, send_wqe->wr_id,
					 IB_WC_WR_FLUSH_ERR, send_wqe->opcode);
		list_del_init(&send_wqe->list);
		pib_util_free_send_wqe(qp, send_wqe);
	}
	qp->requester.nr_waiting_swqe = 0;

	list_for_each_entry_safe(send_wqe, next_send_wqe, &qp->requester.sending_swqe_head, list) {
		pib_util_insert_wc_error(qp->send_cq, qp, send_wqe->wr_id,
					 IB_WC_WR_FLUSH_ERR, send_wqe->opcode);
		list_del_init(&send_wqe->list);
		pib_util_free_send_wqe(qp, send_wqe);
	}
	qp->requester.nr_sending_swqe = 0;

	list_for_each_entry_safe(send_wqe, next_send_wqe, &qp->requester.submitted_swqe_head, list) {
		pib_util_insert_wc_error(qp->send_cq, qp, send_wqe->wr_id,
					 IB_WC_WR_FLUSH_ERR, send_wqe->opcode);
		list_del_init(&send_wqe->list);
		pib_util_free_send_wqe(qp, send_wqe);
	}
	qp->requester.nr_submitted_swqe = 0;

	qp->requester.nr_rd_atomic = 0;

	if (send_only)
		return;

	list_for_each_entry_safe(recv_wqe, next_recv_wqe, &qp->responder.recv_wqe_head, list) {
		pib_util_insert_wc_error(qp->recv_cq, qp, recv_wqe->wr_id,
					 IB_WC_WR_FLUSH_ERR, IB_WC_RECV);
		list_del_init(&recv_wqe->list);
		pib_util_free_recv_wqe(qp, recv_wqe);
	}
	qp->responder.nr_recv_wqe = 0;

	list_for_each_entry_safe_reverse(ack, ack_next, &qp->responder.ack_head, list) {
		list_del_init(&ack->list);
		kmem_cache_free(pib_ack_cachep, ack);
	}
	qp->responder.nr_rd_atomic = 0;
	
	/* Last WQE Reached event */
	if (qp->ib_qp_init_attr.srq && qp->push_rcqe && !qp->issue_last_wqe_reached) {
		pib_util_insert_async_qp_event(qp, IB_EVENT_QP_LAST_WQE_REACHED);
		qp->issue_last_wqe_reached = 1;
	}

	pib_util_reschedule_qp(qp);

	qp->requester.nr_contig_requests = 0;
	qp->requester.nr_contig_read_acks = 0;
	qp->responder.nr_contig_read_acks = 0;
}


static int reset_qp(struct pib_qp *qp)
{
	int count; /* Completion を挙げるべきなのに報告されなかった WQE 数 */
	int signal_all_wr;
	struct pib_send_wqe *send_wqe, *next_send_wqe;
	struct pib_recv_wqe *recv_wqe, *next_recv_wqe;
	struct pib_ack *ack, *ack_next;
	
	count = 0;
	signal_all_wr = qp->ib_qp_init_attr.sq_sig_type == IB_SIGNAL_ALL_WR;

	list_for_each_entry_safe(send_wqe, next_send_wqe, &qp->requester.waiting_swqe_head, list) {
		if (signal_all_wr || (send_wqe->send_flags & IB_SEND_SIGNALED))
			count++;
		list_del_init(&send_wqe->list);
		pib_util_free_send_wqe(qp, send_wqe);
	}
	qp->requester.nr_waiting_swqe = 0;

	list_for_each_entry_safe(send_wqe, next_send_wqe, &qp->requester.sending_swqe_head, list) {
		if (signal_all_wr || (send_wqe->send_flags & IB_SEND_SIGNALED))
			count++;
		list_del_init(&send_wqe->list);
		pib_util_free_send_wqe(qp, send_wqe);
	}
	qp->requester.nr_sending_swqe = 0;

	list_for_each_entry_safe(send_wqe, next_send_wqe, &qp->requester.submitted_swqe_head, list) {
		if (signal_all_wr || (send_wqe->send_flags & IB_SEND_SIGNALED))
			count++;
		list_del_init(&send_wqe->list);
		pib_util_free_send_wqe(qp, send_wqe);
	}
	qp->requester.nr_submitted_swqe = 0;

	qp->requester.nr_rd_atomic = 0;

	list_for_each_entry_safe(recv_wqe, next_recv_wqe, &qp->responder.recv_wqe_head, list) {
		list_del_init(&recv_wqe->list);
		pib_util_free_recv_wqe(qp, recv_wqe);
		count++;
	}
	qp->responder.nr_recv_wqe = 0;

	list_for_each_entry_safe_reverse(ack, ack_next, &qp->responder.ack_head, list) {
		list_del_init(&ack->list);
		kmem_cache_free(pib_ack_cachep, ack);
	}
	qp->responder.nr_rd_atomic = 0;

	count += pib_util_remove_cq(qp->send_cq, qp);
	if (qp->send_cq != qp->recv_cq)
		count += pib_util_remove_cq(qp->recv_cq, qp);

	reset_qp_attr(qp);

	pib_util_reschedule_qp(qp);

	qp->requester.nr_contig_requests = 0;
	qp->requester.nr_contig_read_acks = 0;
	qp->responder.nr_contig_read_acks = 0;

	return count;
}


static void reset_qp_attr(struct pib_qp *qp)
{
	qp->local_ack_timeout      = pib_get_local_ack_time(qp->ib_qp_attr.timeout);

	qp->requester.psn	   = 0;
	qp->requester.expected_psn = 0;
	qp->requester.nr_rd_atomic = 0;

	qp->responder.psn	   = 0;
	qp->responder.last_OpCode  = (qp->qp_type == IB_QPT_RC) ?
		IB_OPCODE_RC_SEND_ONLY : IB_OPCODE_UD_SEND_ONLY; /* dummy opcode */
	qp->responder.offset       = 0;
	qp->responder.nr_rd_atomic = 0;

	memset(&qp->responder.slots, 0, sizeof(qp->responder.slots));

	qp->push_rcqe              = 0;
	qp->issue_comm_est         = 0;
	qp->issue_sq_drained       = 0;
	qp->issue_last_wqe_reached = 0;
}


struct ib_qp *pib_create_qp(struct ib_pd *ibpd,
			    struct ib_qp_init_attr *init_attr,
			    struct ib_udata *udata)
{
	int i;
	bool is_register_qp_table = false;
	struct pib_dev *dev;
	struct pib_qp *qp;
	unsigned long flags;
	u32 qp_num;

	if (!ibpd || !init_attr)
		return ERR_PTR(-EINVAL);

	dev = to_pdev(ibpd->device);

	if (!qp_init_attr_is_ok(dev, init_attr))
		return ERR_PTR(-EINVAL);

	if (init_attr->srq)
		if (ibpd != init_attr->srq->pd)
			return ERR_PTR(-EINVAL);

	qp = kmem_cache_zalloc(pib_qp_cachep, GFP_KERNEL);
	if (!qp)
		return ERR_PTR(-ENOMEM);

	INIT_LIST_HEAD(&qp->list);
	getnstimeofday(&qp->creation_time);

	qp->ib_qp_init_attr = *init_attr;
	qp->ib_qp_attr.cap  = init_attr->cap;

	qp->state           = IB_QPS_RESET;

	qp->qp_type         = init_attr->qp_type;

	qp->send_cq         = to_pcq(init_attr->send_cq);
	qp->recv_cq         = to_pcq(init_attr->recv_cq);

	spin_lock_init(&qp->lock);

	INIT_LIST_HEAD(&qp->requester.submitted_swqe_head);
	INIT_LIST_HEAD(&qp->requester.sending_swqe_head);
	INIT_LIST_HEAD(&qp->requester.waiting_swqe_head);
	INIT_LIST_HEAD(&qp->requester.free_swqe_head);

	INIT_LIST_HEAD(&qp->responder.recv_wqe_head);
	INIT_LIST_HEAD(&qp->responder.ack_head);
	INIT_LIST_HEAD(&qp->responder.free_rwqe_head);

	INIT_LIST_HEAD(&qp->mcast_head);

	reset_qp_attr(qp);

	switch (qp->qp_type) {

	case IB_QPT_SMI:
		qp_num = PIB_QP0;
		goto special_qp;

	case IB_QPT_GSI:
		qp_num = PIB_QP1;
		goto special_qp;

	special_qp:
		qp->ib_qp.qp_num = qp_num;

		spin_lock_irqsave(&dev->lock, flags);
		if (dev->ports[init_attr->port_num - 1].qp_info[qp_num])
			pr_err("pib: try to create QP%u again\n", qp_num);
		else 
			dev->ports[init_attr->port_num - 1].qp_info[qp_num] = qp;
		list_add_tail(&qp->list, &dev->qp_head);
		spin_unlock_irqrestore(&dev->lock, flags);
		break;

	case IB_QPT_RC:
	case IB_QPT_UD:
		if (pib_get_behavior(PIB_BEHAVIOR_QPN_REALLOCATION))
			dev->last_qp_num = PIB_QP1 + 1;

		spin_lock_irqsave(&dev->lock, flags);
		qp_num = pib_alloc_obj_num(dev, PIB_BITMAP_QP_START, PIB_MAX_QP, &dev->last_qp_num);
		if (qp_num == (u32)-1) {
			spin_unlock_irqrestore(&dev->lock, flags);
			goto err_alloc_qp_num;
		}
		dev->nr_qp++;
		list_add_tail(&qp->list, &dev->qp_head);
		pib_util_find_qp(dev, qp_num);
		qp->ib_qp.qp_num = qp_num;
		dev->last_qp_num = qp_num;
		insert_qp(dev, qp);
		spin_unlock_irqrestore(&dev->lock, flags);

		is_register_qp_table = true;
		break;

	default:
		pr_err("pib: pib_create_qp: unknown QP type %s(%d)\n",
		       pib_get_qp_type(init_attr->qp_type), init_attr->qp_type);
		kmem_cache_free(pib_qp_cachep, qp);
		return ERR_PTR(-ENOSYS);
	}

	/* allocate inline data area */
	if (init_attr->cap.max_inline_data > 0) {
		qp->requester.inline_data_buffer = vzalloc(
			init_attr->cap.max_inline_data * init_attr->cap.max_send_wr);
		if (!qp->requester.inline_data_buffer)
			goto err_alloc_inlin_data_buffer;
	}

	/* allocate Send WQEs and Recv WQEs */

	for (i=0 ; i<init_attr->cap.max_send_wr ; i++) {
		struct pib_send_wqe *send_wqe;

		send_wqe = kmem_cache_zalloc(pib_send_wqe_cachep, GFP_KERNEL);
		if (!send_wqe)
			goto err_alloc_wqe;

		INIT_LIST_HEAD(&send_wqe->list);
		list_add_tail(&send_wqe->list, &qp->requester.free_swqe_head);

		if (init_attr->cap.max_inline_data > 0)
			send_wqe->inline_data_buffer = 
				qp->requester.inline_data_buffer + (init_attr->cap.max_inline_data * i);

		send_wqe->trace_id = i + 1;
	}

	for (i=0 ; i<init_attr->cap.max_recv_wr ; i++) {
		struct pib_recv_wqe *recv_wqe;

		recv_wqe = kmem_cache_zalloc(pib_recv_wqe_cachep, GFP_KERNEL);
		if (!recv_wqe)
			goto err_alloc_wqe;

		INIT_LIST_HEAD(&recv_wqe->list);
		list_add_tail(&recv_wqe->list, &qp->responder.free_rwqe_head);
	}

	pib_trace_api(dev, IB_USER_VERBS_CMD_CREATE_QP, qp->ib_qp.qp_num);

	return &qp->ib_qp;

err_alloc_wqe:
	dealloc_free_wqe(qp);

	if (qp->requester.inline_data_buffer)
		vfree(qp->requester.inline_data_buffer);

err_alloc_inlin_data_buffer:
	if (is_register_qp_table) {
		spin_lock_irqsave(&dev->lock, flags);
		rb_erase(&qp->rb_node, &dev->qp_table);
		spin_unlock_irqrestore(&dev->lock, flags);
	}

	list_del(&qp->list);

	if ((qp_num != PIB_QP0) && (qp_num != PIB_QP1)) {
		spin_lock_irqsave(&dev->lock, flags);
		dev->nr_qp--;
		pib_dealloc_obj_num(dev, PIB_BITMAP_QP_START, qp_num);
		spin_unlock_irqrestore(&dev->lock, flags);
	}

err_alloc_qp_num:
	kmem_cache_free(pib_qp_cachep, qp);

	return ERR_PTR(-ENOMEM);
}


static bool qp_init_attr_is_ok(const struct pib_dev *dev, const struct ib_qp_init_attr *init_attr)
{
	switch (init_attr->qp_type) {

	case IB_QPT_SMI:
	case IB_QPT_GSI:
	case IB_QPT_RC:
	case IB_QPT_UD:
		break;

	default:
		return false;
	}

	if (!init_attr->send_cq || !init_attr->recv_cq)
		return false;

	if (!qp_cap_is_ok(dev, &init_attr->cap, (init_attr->srq != NULL)))
		return false;

	return true;
}


static bool qp_cap_is_ok(const struct pib_dev *dev, const struct ib_qp_cap *cap, int use_srq)
{
	if ((cap->max_send_wr < 1) || (dev->ib_dev_attr.max_qp_wr < cap->max_send_wr)) {
		pib_debug("pib: wrong max_send_wr=%u in qp_cap_is_ok\n", cap->max_send_wr);
		return false;
	}

	if ((cap->max_send_sge < 1) || (dev->ib_dev_attr.max_sge < cap->max_send_sge)) {
		pib_debug("pib: wrong max_send_sge=%u in qp_cap_is_ok\n", cap->max_send_sge);
		return false;
	}

	if (use_srq) {
		if (cap->max_recv_wr != 0) {
			pib_debug("pib: wrong max_recv_wr=%u in qp_cap_is_ok\n", cap->max_recv_wr);
			return false;
		}
		
		if (cap->max_recv_sge != 0) {
			pib_debug("pib: wrong max_recv_sge=%u in qp_cap_is_ok\n", cap->max_recv_sge);
			return false;
		}
	} else {
		if ((cap->max_recv_wr < 1) || (dev->ib_dev_attr.max_qp_wr < cap->max_recv_wr)) {
			pib_debug("pib: wrong max_recv_wr=%u in qp_cap_is_ok\n", cap->max_recv_wr);
			return false;
		}
		
		if ((cap->max_recv_sge < 1) || (dev->ib_dev_attr.max_sge < cap->max_recv_sge)) {
			pib_debug("pib: wrong max_recv_sge=%u in qp_cap_is_ok\n", cap->max_recv_sge);
			return false;
		}
	}

	if (PIB_MAX_INLINE < cap->max_inline_data) {
		pib_debug("pib: too large max_inline_data=%u in qp_cap_is_ok\n", cap->max_inline_data);
		return false;
	}

	return true;
}


int pib_destroy_qp(struct ib_qp *ibqp)
{
	int qp_num;
	struct pib_qp *qp;
	struct pib_dev *dev;
	unsigned long flags;

	if (!ibqp)
		return -EINVAL;

	/* @todo ここより先で他のスレッドが qp を実行できないことをどう保証するか？ */

	qp_num = ibqp->qp_num;

	qp = to_pqp(ibqp);
	dev = to_pdev(ibqp->device);

	pib_trace_api(dev, IB_USER_VERBS_CMD_DESTROY_QP, qp->ib_qp.qp_num);

	pib_detach_all_mcast(dev, qp);

	spin_lock_irqsave(&dev->lock, flags);
	spin_lock(&qp->lock);

	reset_qp(qp);
	dealloc_free_wqe(qp);

	spin_unlock(&qp->lock);

	if (qp->requester.inline_data_buffer)
		vfree(qp->requester.inline_data_buffer);

	if ((qp_num == PIB_QP0) || (qp_num == PIB_QP1))
		dev->ports[qp->ib_qp_init_attr.port_num - 1].qp_info[qp_num] = NULL;
	else
		rb_erase(&qp->rb_node, &dev->qp_table);

	list_del(&qp->list);

	if ((qp_num != PIB_QP0) && (qp_num != PIB_QP1)) {
		dev->nr_qp--;
		pib_dealloc_obj_num(dev, PIB_BITMAP_QP_START, qp_num);
	}

	spin_unlock_irqrestore(&dev->lock, flags);

	kmem_cache_free(pib_qp_cachep, qp);

	return 0;
}


static void dealloc_free_wqe(struct pib_qp *qp)
{
	while (!list_empty(&qp->requester.free_swqe_head)) {
		struct pib_send_wqe *send_wqe;
		send_wqe = list_first_entry(&qp->requester.free_swqe_head, struct pib_send_wqe, list);
		list_del_init(&send_wqe->list);
		kmem_cache_free(pib_send_wqe_cachep, send_wqe);
	}

	while (!list_empty(&qp->responder.free_rwqe_head)) {
		struct pib_recv_wqe *recv_wqe;
		recv_wqe = list_first_entry(&qp->responder.free_rwqe_head, struct pib_recv_wqe, list);
		list_del_init(&recv_wqe->list);
		kmem_cache_free(pib_recv_wqe_cachep, recv_wqe);
	}
}


int pib_modify_qp(struct ib_qp *ibqp, struct ib_qp_attr *attr,
		  int attr_mask, struct ib_udata *udata)
{
	int ret = 0;
	int pending_send_wr = 0;
	int issue_sq_drained = 0;
	struct pib_qp *qp;
	struct pib_dev *dev;
	unsigned long flags;
	enum ib_qp_state cur_state, new_state;

	if (!ibqp || !attr)
		return -EINVAL;

	qp = to_pqp(ibqp);
	dev = to_pdev(ibqp->device);

	pib_trace_api(dev, IB_USER_VERBS_CMD_MODIFY_QP, qp->ib_qp.qp_num);

	spin_lock_irqsave(&qp->lock, flags);

	cur_state = (attr_mask & IB_QP_CUR_STATE) ? attr->cur_qp_state : qp->state;
	new_state = (attr_mask & IB_QP_STATE) ? attr->qp_state : cur_state;

	issue_sq_drained = list_empty(&qp->requester.sending_swqe_head) &&
		list_empty(&qp->requester.waiting_swqe_head);

	if ((cur_state == IB_QPS_SQD) &&
	    ((new_state == IB_QPS_SQD) || (new_state == IB_QPS_RTS)))
		if (!issue_sq_drained) {
			ret = -EBUSY;
			goto done;
		}

	/* @todo IB_QP_CAP は常にエラーになる */
	if (!ib_modify_qp_is_ok(cur_state, new_state, ibqp->qp_type, attr_mask)) {
		ret = -EINVAL;
		goto done;
	}

	if (!modify_qp_is_ok(dev, qp, cur_state, attr, attr_mask)) {
		ret = -EINVAL;
		goto done;
	}

	if (attr_mask & IB_QP_PATH_MTU)
		qp->ib_qp_attr.path_mtu    = attr->path_mtu;

	if (attr_mask & IB_QP_QKEY)
		qp->ib_qp_attr.qkey        = attr->qkey;

	if (attr_mask & IB_QP_RQ_PSN)
		qp->responder.psn          = attr->rq_psn & PIB_PSN_MASK;

	if (attr_mask & IB_QP_SQ_PSN) {
		qp->requester.psn          = attr->sq_psn & PIB_PSN_MASK;
		qp->requester.expected_psn = attr->sq_psn & PIB_PSN_MASK;
	}

	if (attr_mask & IB_QP_DEST_QPN)
		qp->ib_qp_attr.dest_qp_num = attr->dest_qp_num;

	if (attr_mask & IB_QP_ACCESS_FLAGS)
		qp->ib_qp_attr.qp_access_flags = attr->qp_access_flags;
	
	if (attr_mask & IB_QP_CAP) {
		/* @todo ここで増減を */

		qp->ib_qp_attr.cap.max_send_wr  = attr->cap.max_send_wr;
		qp->ib_qp_attr.cap.max_send_sge = attr->cap.max_send_sge;
		if (qp->ib_qp_init_attr.recv_cq) {
			qp->ib_qp_attr.cap.max_recv_wr  = attr->cap.max_recv_wr;
			qp->ib_qp_attr.cap.max_recv_sge = attr->cap.max_recv_sge;
		}
		qp->ib_qp_attr.cap.max_inline_data = attr->cap.max_inline_data;
	}

	if (attr_mask & IB_QP_AV)
		qp->ib_qp_attr.ah_attr     = attr->ah_attr;

	if (attr_mask & IB_QP_PKEY_INDEX)
		qp->ib_qp_attr.pkey_index  = attr->pkey_index;

	if (attr_mask & IB_QP_EN_SQD_ASYNC_NOTIFY)
		qp->ib_qp_attr.en_sqd_async_notify = attr->en_sqd_async_notify;

	if (attr_mask & IB_QP_MAX_QP_RD_ATOMIC)
		qp->ib_qp_attr.max_rd_atomic = qp->requester.max_rd_atomic = attr->max_rd_atomic;

	if (attr_mask & IB_QP_MAX_DEST_RD_ATOMIC)
		qp->ib_qp_attr.max_dest_rd_atomic = attr->max_dest_rd_atomic;

	if (attr_mask & IB_QP_MIN_RNR_TIMER)
		qp->ib_qp_attr.min_rnr_timer = attr->min_rnr_timer;

	if (attr_mask & IB_QP_PORT) {
		qp->ib_qp_attr.port_num    = attr->port_num;

		switch (qp->qp_type) {
		case IB_QPT_UD:
		case IB_QPT_SMI:
		case IB_QPT_GSI:
			qp->ib_qp_attr.path_mtu =
				dev->ports[attr->port_num - 1].ib_port_attr.active_mtu;
			break;
		default:
			break;
		}
	}

	if (attr_mask & IB_QP_TIMEOUT) {
		qp->ib_qp_attr.timeout     = attr->timeout; /* 解像度は local_ca_ack_delay に制限される */
		qp->local_ack_timeout      = pib_get_local_ack_time(attr->timeout);
	}

	if (attr_mask & IB_QP_RETRY_CNT)
		qp->ib_qp_attr.retry_cnt   = attr->retry_cnt;

	if (attr_mask & IB_QP_RNR_RETRY)
		qp->ib_qp_attr.rnr_retry   = attr->rnr_retry;

	if (attr_mask & IB_QP_ALT_PATH) {
		qp->ib_qp_attr.alt_ah_attr    = attr->alt_ah_attr;
		qp->ib_qp_attr.alt_pkey_index = attr->alt_pkey_index;
	}

	if (attr_mask & IB_QP_PATH_MIG_STATE) {
		qp->ib_qp_attr.path_mig_state = attr->path_mig_state;

		/* ここで入れ替える可能性もある */
		qp->ib_qp_attr.ah_attr        = qp->ib_qp_attr.alt_ah_attr;
		qp->ib_qp_attr.pkey_index     = attr->alt_pkey_index;
	}

	if (attr_mask & IB_QP_STATE) {

		if ((new_state == IB_QPS_SQE) && (qp->qp_type == IB_QPT_RC)) {
			ret = -EINVAL;
			goto done;
		}

		if ((cur_state == IB_QPS_SQD) && !qp->issue_sq_drained &&
		    ((new_state == IB_QPS_RTS) || (new_state == IB_QPS_SQD))) {
			ret = -EINVAL;
			goto done;
		}

		qp->state = new_state;

		/* side reaction when change QP state */ 
		switch (new_state) {

		case IB_QPS_RESET:
			ret = reset_qp(qp);
			if ((ret > 0) && pib_warn_manner(PIB_MANNER_LOST_WC_WHEN_QP_RESET))
				pr_info("pib: MANNER Some completions are lost when QP state is changed to reset\n");
			break;

		case IB_QPS_RTR:
			/* Allow event to retrigger if QP set to RTR more than once */
			qp->issue_comm_est = 0;
			break;

		case IB_QPS_RTS:
			pending_send_wr = get_send_wr_num(qp);
			break;

		case IB_QPS_SQE:
			pib_util_flush_qp(qp, 1);
			break;
		
		case IB_QPS_ERR:
			pib_util_flush_qp(qp, 0);
			break;

		default:
			break;
		}

		if (issue_sq_drained) {
			if (qp->ib_qp_attr.en_sqd_async_notify)
				pib_util_insert_async_qp_event(qp, IB_EVENT_SQ_DRAINED);
			qp->issue_sq_drained = 1;
		}

		if ((cur_state == IB_QPS_SQD) && (new_state != IB_QPS_SQD))
			qp->issue_sq_drained = 0;
	}

	/* 送信可能状態に */
	if (pending_send_wr)
		get_ready_to_send(dev, qp);

done:
	spin_unlock_irqrestore(&qp->lock, flags);

	return ret;
}


static bool modify_qp_is_ok(const struct pib_dev *dev, const struct pib_qp *qp, enum ib_qp_state cur_state, const struct ib_qp_attr *attr, int attr_mask)
{
	/* IB_QP_ACCESS_FLAGS */

	if (attr_mask & IB_QP_PORT) {
		if ((cur_state == IB_QPS_SQD) &&
		    !(dev->ib_dev_attr.device_cap_flags & IB_DEVICE_CHANGE_PHY_PORT)) {
			pib_debug("pib: Can't modify primary port number in SQD state w/o DEVICE_CHANGE_PHY_PORT\n");
			return false;
		}

		if (qp->qp_type == IB_QPT_SMI ||
		    qp->qp_type == IB_QPT_GSI ||
		    attr->port_num == 0 ||
		    attr->port_num > dev->ib_dev.phys_port_cnt) {
			pib_debug("pib: wrong port_num=%u in modify_qp_is_ok\n", attr->port_num);
			return false;
		}
	}

	if (attr_mask & IB_QP_AV)
		if (attr->ah_attr.dlid >= PIB_MCAST_LID_BASE) {
			pib_debug("pib: wrong dlid=0x%04x in modify_qp_is_ok\n", attr->ah_attr.dlid);
			return false;
		}

	if (attr_mask & IB_QP_PATH_MTU)
		if ((attr->path_mtu < IB_MTU_256) || (IB_MTU_4096 < attr->path_mtu)) {
			pib_debug("pib: wrong path_mtu=%u in modify_qp_is_ok\n", attr->path_mtu);
			return false;
		}
	
	if (attr_mask & IB_QP_TIMEOUT)
		if (attr->timeout & ~PIB_LOCAL_ACK_TIMEOUT_MASK) {
			pib_debug("pib: wrong timeout=%u in modify_qp_is_ok\n", attr->timeout);
			return false;
		}

	if (attr_mask & IB_QP_RETRY_CNT)
		if (attr->retry_cnt & ~7) {
			pib_debug("pib: wrong retry_cnt=%u in modify_qp_is_ok\n", attr->retry_cnt);
			return false;
		}

	if (attr_mask & IB_QP_MIN_RNR_TIMER)
		if (attr->min_rnr_timer & ~PIB_MIN_RNR_NAK_TIMER_MASK) {
			pib_debug("pib: wrong min_rnr_timer=%u in modify_qp_is_ok\n", attr->min_rnr_timer);
			return false;
		}

	if (attr_mask & IB_QP_RNR_RETRY)
		if (attr->rnr_retry & ~7) {
			pib_debug("pib: wrong rnr_retry=%u in modify_qp_is_ok\n", attr->rnr_retry);
			return false;
		}

	if (attr_mask & IB_QP_MAX_QP_RD_ATOMIC)
		if (attr->max_rd_atomic > dev->ib_dev_attr.max_qp_init_rd_atom) {
			pib_debug("pib: wrong max_rd_atomic=%u in modify_qp_is_ok\n", attr->max_rd_atomic);
			return false;
		}
	
	if (attr_mask & IB_QP_MAX_DEST_RD_ATOMIC)
		if (attr->max_dest_rd_atomic > dev->ib_dev_attr.max_qp_rd_atom) {
			pib_debug("pib: wrong max_dest_rd_atomic=%u in modify_qp_is_ok\n", attr->max_dest_rd_atomic);
			return false;
		}

	if ((attr_mask & IB_QP_RQ_PSN) && pib_warn_manner(PIB_MANNER_PSN))
		if (attr->rq_psn & ~PIB_PSN_MASK) {
			pr_info("pib: MANNER Wrong rq_psn=0x%08x in modify_qp\n", attr->rq_psn);
			if (pib_error_manner(PIB_MANNER_PSN))
				return false;
		}

	if ((attr_mask & IB_QP_SQ_PSN) && pib_warn_manner(PIB_MANNER_PSN))
		if (attr->sq_psn & ~PIB_PSN_MASK) {
			pr_info("pib: MANNER Wrong sq_psn=0x%08x in modify_qp\n", attr->sq_psn);
			if (pib_error_manner(PIB_MANNER_PSN))
				return false;
		}


	if (attr_mask & IB_QP_CAP) {
		if (!(dev->ib_dev_attr.device_cap_flags & IB_DEVICE_RESIZE_MAX_WR)) {
			pib_debug("pib: Can't modify QP capabilities w/o DEVICE_RESIZE_MAX_WR\n");
			return false;
		}

		if (!qp_cap_is_ok(dev, &attr->cap, (qp->ib_qp_init_attr.srq != NULL)))
			return false;
	}

	if (attr_mask & IB_QP_PKEY_INDEX) {
		if (PIB_PKEY_TABLE_LEN <= attr->pkey_index) {
			pib_debug("pib: wrong pkey_index=%u in modify_qp_is_ok\n", attr->pkey_index);
			return false;
		}
	}

	/* IB_QP_PATH_MIG_STATE */
	/*  */
	/* IB_QP_ALT_PATH */

	return true;
}


int pib_query_qp(struct ib_qp *ibqp, struct ib_qp_attr *qp_attr, int qp_attr_mask,
		 struct ib_qp_init_attr *qp_init_attr)
{
	struct pib_qp *qp;
	unsigned long flags;

	if (!ibqp || !qp_attr || !qp_init_attr)
		return -EINVAL;

	qp = to_pqp(ibqp);

#if 0
	if (qp->s_flags & QIB_S_SIGNAL_REQ_WR)
		init_attr->sq_sig_type = IB_SIGNAL_REQ_WR;
	else
		init_attr->sq_sig_type = IB_SIGNAL_ALL_WR;
#endif

	spin_lock_irqsave(&qp->lock, flags);

	*qp_attr              = qp->ib_qp_attr;
	*qp_init_attr         = qp->ib_qp_init_attr;

	qp_attr->qp_state     = qp->state;
	qp_attr->cur_qp_state = qp->state;

	qp_attr->sq_psn       = qp->requester.psn & PIB_PSN_MASK;
	qp_attr->rq_psn       = qp->responder.psn & PIB_PSN_MASK;

	qp_attr->sq_draining  = !(list_empty(&qp->requester.sending_swqe_head) &&
				  list_empty(&qp->requester.waiting_swqe_head));

	spin_unlock_irqrestore(&qp->lock, flags);

	return 0;
}


int pib_post_send(struct ib_qp *ibqp, struct ib_send_wr *ibwr,
		  struct ib_send_wr **bad_wr)
{
	int i, ret = 0;
	int pending_send_wr = 0;
	struct pib_qp *qp;
	struct pib_dev *dev;
	unsigned long flags;
	struct pib_send_wqe *send_wqe;
	u64 total_length = 0;
	u32 imm_data;

	if (!ibqp || !ibwr)
		return -EINVAL;

	dev = to_pdev(ibqp->device);
	qp = to_pqp(ibqp);

	pib_trace_api(dev, IB_USER_VERBS_CMD_POST_SEND, qp->ib_qp.qp_num);

	spin_lock_irqsave(&qp->lock, flags);

	if ((qp->state == IB_QPS_RESET) || (qp->state == IB_QPS_INIT)) {
		ret = -EINVAL;
		goto done;		
	}

next_wr:
	/* QP check */
	switch (qp->state) {

	case IB_QPS_RESET:
	case IB_QPS_INIT:
		pr_err("pib: call pib_post_send when QP is in RESET or INIT\n");
		ret = -EINVAL;
		goto done;

	case IB_QPS_ERR:
	case IB_QPS_SQE:
		pib_util_insert_wc_error(qp->send_cq, qp, ibwr->wr_id,
					 IB_WC_WR_FLUSH_ERR, ibwr->opcode);
		goto skip;

	case IB_QPS_RTS:
		pending_send_wr = 1;
		break;

	case IB_QPS_RTR:
	case IB_QPS_SQD:
		break;
	}

	imm_data = ibwr->ex.imm_data;

#ifdef PIB_HACK_IMM_DATA_LKEY
	for (i = ibwr->num_sge - 1 ; i >= 0 ; i--) {
		if (ibwr->sg_list[i].lkey == PIB_IMM_DATA_LKEY) {
			int j;
			imm_data = ibwr->sg_list[i].length;
			for (j = i ; j < ibwr->num_sge - 1 ; j++) {
				ibwr->sg_list[j] = ibwr->sg_list[j+1];
			} 
			ibwr->num_sge--;
			break;
		}		
	}
#endif

	if ((ibwr->num_sge < 1) || (qp->ib_qp_init_attr.cap.max_send_sge < ibwr->num_sge)) {
		ret = -EINVAL;
		goto done;
	}

	/* free swqe は max_send_wr しか用意されてないのでチェックも兼ねている */
	if (list_empty(&qp->requester.free_swqe_head)) {
		ret = -ENOMEM;
		goto done;
	}

	send_wqe = list_first_entry(&qp->requester.free_swqe_head, struct pib_send_wqe, list);

	send_wqe->wr_id      = ibwr->wr_id;
	send_wqe->opcode     = ibwr->opcode;
	send_wqe->send_flags = ibwr->send_flags;
	send_wqe->num_sge    = ibwr->num_sge;
	send_wqe->imm_data   = imm_data;
	memset(&send_wqe->processing, 0, sizeof(send_wqe->processing));
	memset(&send_wqe->wr, 0, sizeof(send_wqe->wr));

	for (i=0 ; i<ibwr->num_sge ; i++) {
		send_wqe->sge_array[i] = ibwr->sg_list[i];

		if (pib_get_behavior(PIB_BEHAVIOR_ZERO_LEN_SGE_CONSIDER_AS_MAX_LEN))
			if (ibwr->sg_list[i].length == 0)
				ibwr->sg_list[i].length = PIB_MAX_PAYLOAD_LEN;

		total_length += ibwr->sg_list[i].length;
	}

	if ((send_wqe->opcode == IB_WR_ATOMIC_CMP_AND_SWP) || (send_wqe->opcode == IB_WR_ATOMIC_FETCH_AND_ADD)) {
		/* @todo total_length は 8 バイト未満ならエラーを出すべき？ */
		total_length = 8;
	}

	if (PIB_MAX_PAYLOAD_LEN < total_length) { 
		ret = -EMSGSIZE;
		goto done;
	}

	send_wqe->total_length = (u32)total_length;

	/* inline data */
	if (send_wqe->send_flags & IB_SEND_INLINE)
		if (copy_inline_data(qp, send_wqe, total_length)) {
			ret = -EFAULT;
			goto done;
		}

	switch (qp->qp_type) {
	case IB_QPT_RC:
		switch (ibwr->opcode) {
		case IB_WR_RDMA_WRITE:
		case IB_WR_RDMA_WRITE_WITH_IMM:
			send_wqe->wr.rdma.remote_addr   = ibwr->wr.rdma.remote_addr;
			send_wqe->wr.rdma.rkey          = ibwr->wr.rdma.rkey;
			break;

		case IB_WR_RDMA_READ:
			send_wqe->wr.rdma.remote_addr   = ibwr->wr.rdma.remote_addr;
			send_wqe->wr.rdma.rkey          = ibwr->wr.rdma.rkey;
			break;

		case IB_WR_ATOMIC_CMP_AND_SWP:
		case IB_WR_ATOMIC_FETCH_AND_ADD:
			send_wqe->wr.atomic.remote_addr = ibwr->wr.atomic.remote_addr;
			send_wqe->wr.atomic.compare_add = ibwr->wr.atomic.compare_add;
			send_wqe->wr.atomic.swap        = ibwr->wr.atomic.swap;
			send_wqe->wr.atomic.rkey        = ibwr->wr.atomic.rkey;
			break;
		default:
			break;
		}		
		break;

	case IB_QPT_UD:
	case IB_QPT_SMI:
	case IB_QPT_GSI:
		switch (ibwr->opcode) {
		case IB_WR_SEND:
		case IB_WR_SEND_WITH_IMM:
			if (!pib_get_behavior(PIB_BEHAVIOR_AH_PD_VIOLATOIN_COMP_ERR))
				if (!ibwr->wr.ud.ah || qp->ib_qp.pd != ibwr->wr.ud.ah->pd) {
					ret = -EINVAL;
					goto done;
				}
			send_wqe->wr.ud.ah		= ibwr->wr.ud.ah;
			send_wqe->wr.ud.remote_qpn	= ibwr->wr.ud.remote_qpn;
			send_wqe->wr.ud.remote_qkey	= ibwr->wr.ud.remote_qkey;
			send_wqe->wr.ud.pkey_index	= ibwr->wr.ud.pkey_index;
			send_wqe->wr.ud.port_num	= ibwr->wr.ud.port_num;
			break;
		default:
			break;
		}
		break;

	default:
		break;
	}

	send_wqe->processing.list_type = PIB_SWQE_SUBMITTED;
	send_wqe->processing.status    = IB_WC_SUCCESS;

	list_del_init(&send_wqe->list); /* list_del でいい？ */
	list_add_tail(&send_wqe->list, &qp->requester.submitted_swqe_head);
	qp->requester.nr_submitted_swqe++;

skip:
	ibwr = ibwr->next;

	if (ibwr)
		goto next_wr;

done:
	if (pending_send_wr)
		get_ready_to_send(dev, qp);

	spin_unlock_irqrestore(&qp->lock, flags);

	if (ret && bad_wr)
		*bad_wr = ibwr;

	return ret;
}


static int copy_inline_data(struct pib_qp *qp, struct pib_send_wqe *send_wqe, u64 total_length)
{
	int i;
	void *buffer = send_wqe->inline_data_buffer;
	u32 offset = 0;

	if ((total_length <= 0) || (qp->ib_qp_attr.cap.max_inline_data < total_length))
		return 0;

	switch (send_wqe->opcode) {
	case IB_WR_SEND:
	case IB_WR_SEND_WITH_IMM:
	case IB_WR_RDMA_WRITE:
	case IB_WR_RDMA_WRITE_WITH_IMM:
		break;

	default:
		return 0;
	}

	for (i=0 ; i<send_wqe->num_sge ; i++) {
		if (copy_from_user(buffer + offset,
				   (const void __user *)(unsigned long)send_wqe->sge_array[i].addr,
				   send_wqe->sge_array[i].length)) {
			return -EFAULT;
		}
		offset += send_wqe->sge_array[i].length;
	}

	return 0;
}


int pib_post_recv(struct ib_qp *ibqp, struct ib_recv_wr *ibwr,
		     struct ib_recv_wr **bad_wr)
{
	int i, ret = 0;
	struct pib_dev *dev;
	struct pib_qp *qp;
	unsigned long flags;
	struct pib_recv_wqe *recv_wqe;
	u64 total_length = 0;

	if (!ibqp || !ibwr)
		return -EINVAL;

	dev = to_pdev(ibqp->device);
	qp = to_pqp(ibqp);

	pib_trace_api(dev, IB_USER_VERBS_CMD_POST_RECV, qp->ib_qp.qp_num);

	if (qp->ib_qp_init_attr.srq)
		return -EINVAL;

	spin_lock_irqsave(&qp->lock, flags);

next_wr:
	/* QP check */
	switch (qp->state) {
	case IB_QPS_RESET:
	default:
		pr_err("pib: call pib_post_recv when QP is in RESET\n");
		ret = -EINVAL;
		goto err;

	case IB_QPS_ERR:
		pib_util_insert_wc_error(qp->recv_cq, qp, ibwr->wr_id,
					 IB_WC_WR_FLUSH_ERR, IB_WC_RECV);
		ret = -EPERM; /* @todo ? */
		goto skip;

	case IB_QPS_INIT:
	case IB_QPS_RTR:
	case IB_QPS_RTS:
	case IB_QPS_SQD:
	case IB_QPS_SQE:
		/* OK */
		break;
	}

	if ((ibwr->num_sge < 1) || (qp->ib_qp_init_attr.cap.max_recv_sge < ibwr->num_sge)) {
		ret = -EINVAL;
		goto err;
	}

	if (list_empty(&qp->responder.free_rwqe_head)) {
		ret = -ENOMEM;
		goto err;
	}

	recv_wqe = list_first_entry(&qp->responder.free_rwqe_head, struct pib_recv_wqe, list);

	recv_wqe->wr_id   = ibwr->wr_id;
	recv_wqe->num_sge = ibwr->num_sge;

	for (i=0 ; i<ibwr->num_sge ; i++) {
		recv_wqe->sge_array[i] = ibwr->sg_list[i];

		if (pib_get_behavior(PIB_BEHAVIOR_ZERO_LEN_SGE_CONSIDER_AS_MAX_LEN))
			if (ibwr->sg_list[i].length == 0)
				ibwr->sg_list[i].length = PIB_MAX_PAYLOAD_LEN;

		total_length += ibwr->sg_list[i].length;
	}
	
	if (PIB_MAX_PAYLOAD_LEN < total_length)  {
		ret = -EMSGSIZE;
		goto err;
	}

	recv_wqe->total_length = (u32)total_length;

	list_del_init(&recv_wqe->list); /* list_del でいい？ */
	list_add_tail(&recv_wqe->list, &qp->responder.recv_wqe_head);
	qp->responder.nr_recv_wqe++;

skip:
	ibwr = ibwr->next;
	if (ibwr)
		goto next_wr;

err:
	spin_unlock_irqrestore(&qp->lock, flags);

	if (ret && bad_wr)
		*bad_wr = ibwr;

	return ret;
}


void pib_util_free_send_wqe(struct pib_qp *qp, struct pib_send_wqe *send_wqe)
{
	BUG_ON(!spin_is_locked(&qp->lock));

	INIT_LIST_HEAD(&send_wqe->list);

	list_add_tail(&send_wqe->list, &qp->requester.free_swqe_head);
}


void pib_util_free_recv_wqe(struct pib_qp *qp, struct pib_recv_wqe *recv_wqe)
{
	BUG_ON(!spin_is_locked(&qp->lock));

	memset(recv_wqe, 0, sizeof(*recv_wqe));
	INIT_LIST_HEAD(&recv_wqe->list);

	if (qp->ib_qp_init_attr.srq) {
		struct pib_srq *srq = to_psrq(qp->ib_qp_init_attr.srq);
		spin_lock(&srq->lock);
		/* @todo SRQ エラーをチェックすべき？ */ 
		list_add_tail(&recv_wqe->list, &srq->free_recv_wqe_head);
		spin_unlock(&srq->lock);
	} else {
		list_add_tail(&recv_wqe->list, &qp->responder.free_rwqe_head);
	}
}


static void get_ready_to_send(struct pib_dev *dev, struct pib_qp *qp)
{
	pib_util_reschedule_qp(qp);

	qp->requester.nr_contig_requests = 0;
	qp->requester.nr_contig_read_acks = 0;
	qp->responder.nr_contig_read_acks = 0;

	complete(&dev->thread.completion);
}


void pib_util_insert_async_qp_error(struct pib_qp *qp, enum ib_event_type event)
{
	struct ib_event ev;

	BUG_ON(!spin_is_locked(&qp->lock));

	if (!qp->ib_qp.event_handler)
		return;

	pib_trace_async(to_pdev(qp->ib_qp.device), event, qp->ib_qp.qp_num);

	ev.event      = event;
	ev.device     = qp->ib_qp.device;
	ev.element.qp = &qp->ib_qp;

	qp->ib_qp.event_handler(&ev, qp->ib_qp.qp_context);
}


void pib_util_insert_async_qp_event(struct pib_qp *qp, enum ib_event_type event)
{
	pib_util_insert_async_qp_error(qp, event);
}
