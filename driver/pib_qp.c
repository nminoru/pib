/*
 * Copyright (c) 2013 Minoru NAKAMURA <nminoru@nminoru.jp>
 *
 * This code is licenced under the GPL version 2 or BSD license.
 */
#include <linux/module.h>
#include <linux/init.h>

#include <rdma/ib_pack.h>

#include "pib.h"


static int qp_init_attr_is_ok(const struct pib_ib_dev *dev, const struct ib_qp_init_attr *init_attr);
static int qp_cap_is_ok(const struct pib_ib_dev *dev, const struct ib_qp_cap *cap, int use_srq);
static int modify_qp_is_ok(const struct pib_ib_dev *dev, const struct pib_ib_qp *qp, const struct ib_qp_attr *attr, int attr_mask);
static void get_ready_to_send(struct pib_ib_dev *dev, struct pib_ib_qp *qp);
static void reset_qp(struct pib_ib_qp *qp);
static void reset_qp_attr(struct pib_ib_qp *qp);


struct pib_ib_qp *pib_util_find_qp(struct pib_ib_dev *dev, int qp_num)
{
	struct rb_node *node = dev->qp_table.rb_node;

	while (node) {
		int ret;
		struct pib_ib_qp *qp;

		qp  = rb_entry(node, struct pib_ib_qp, rb_node);

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


static void insert_qp(struct pib_ib_dev *dev, struct pib_ib_qp *qp)
{
	int qp_num;
	struct rb_node **link = &dev->qp_table.rb_node;
	struct rb_node *parent = NULL;

	qp_num = qp->ib_qp.qp_num;

	while (*link) {
		struct pib_ib_qp *qp_tmp;

		parent = *link;
		qp_tmp = rb_entry(parent, struct pib_ib_qp, rb_node);

		if (qp_tmp->ib_qp.qp_num > qp_num)
			link = &parent->rb_left;
		else
			link = &parent->rb_right;
	}

	rb_link_node(&qp->rb_node, parent, link);
	rb_insert_color(&qp->rb_node, &dev->qp_table);
}


static int get_send_wr_num(const struct pib_ib_qp *qp)
{
	return qp->requester.nr_submitted_swqe +
		qp->requester.nr_sending_swqe +
		qp->requester.nr_waiting_swqe;
}


void pib_util_flush_qp(struct pib_ib_qp *qp, int send_only)
{
	struct pib_ib_send_wqe *send_wqe, *next_send_wqe;
	struct pib_ib_recv_wqe *recv_wqe, *next_recv_wqe;
	struct pib_ib_ack *ack, *ack_next;

	list_for_each_entry_safe(send_wqe, next_send_wqe, &qp->requester.waiting_swqe_head, list) {
		pib_util_insert_wc_error(qp->send_cq, qp, send_wqe->wr_id,
					 IB_WC_WR_FLUSH_ERR, send_wqe->opcode);
		list_del_init(&send_wqe->list);
		kmem_cache_free(pib_ib_send_wqe_cachep, send_wqe);
	}
	qp->requester.nr_waiting_swqe = 0;

	list_for_each_entry_safe(send_wqe, next_send_wqe, &qp->requester.sending_swqe_head, list) {
		pib_util_insert_wc_error(qp->send_cq, qp, send_wqe->wr_id,
					 IB_WC_WR_FLUSH_ERR, send_wqe->opcode);
		list_del_init(&send_wqe->list);
		kmem_cache_free(pib_ib_send_wqe_cachep, send_wqe);
	}
	qp->requester.nr_sending_swqe = 0;

	list_for_each_entry_safe(send_wqe, next_send_wqe, &qp->requester.submitted_swqe_head, list) {
		pib_util_insert_wc_error(qp->send_cq, qp, send_wqe->wr_id,
					 IB_WC_WR_FLUSH_ERR, send_wqe->opcode);
		list_del_init(&send_wqe->list);
		kmem_cache_free(pib_ib_send_wqe_cachep, send_wqe);
	}
	qp->requester.nr_submitted_swqe = 0;

	qp->requester.nr_rd_atomic = 0;

	if (send_only)
		return;

	list_for_each_entry_safe(recv_wqe, next_recv_wqe, &qp->responder.recv_wqe_head, list) {
		pib_util_insert_wc_error(qp->recv_cq, qp, recv_wqe->wr_id,
					 IB_WC_WR_FLUSH_ERR, IB_WC_RECV);
		list_del_init(&recv_wqe->list);
		kmem_cache_free(pib_ib_recv_wqe_cachep, recv_wqe);
	}
	qp->responder.nr_recv_wqe = 0;

	list_for_each_entry_safe_reverse(ack, ack_next, &qp->responder.ack_head, list) {
		list_del_init(&ack->list);
		kmem_cache_free(pib_ib_ack_cachep, ack);
	}
	qp->responder.nr_rd_atomic = 0;
	
	/* Last WQE Reached event */
	if (qp->ib_qp_init_attr.srq && qp->push_rcqe && !qp->issue_last_wqe_reached) {
		pib_util_insert_async_qp_event(qp, IB_EVENT_QP_LAST_WQE_REACHED);
		qp->issue_last_wqe_reached = 1;
	}

	pib_util_reschedule_qp(qp);
}


static void reset_qp(struct pib_ib_qp *qp)
{
	struct pib_ib_send_wqe *send_wqe, *next_send_wqe;
	struct pib_ib_recv_wqe *recv_wqe, *next_recv_wqe;
	struct pib_ib_ack *ack, *ack_next;

	list_for_each_entry_safe(send_wqe, next_send_wqe, &qp->requester.waiting_swqe_head, list) {
		list_del_init(&send_wqe->list);
		kmem_cache_free(pib_ib_send_wqe_cachep, send_wqe);
	}
	qp->requester.nr_waiting_swqe = 0;

	list_for_each_entry_safe(send_wqe, next_send_wqe, &qp->requester.sending_swqe_head, list) {
		list_del_init(&send_wqe->list);
		kmem_cache_free(pib_ib_send_wqe_cachep, send_wqe);
	}
	qp->requester.nr_sending_swqe = 0;

	list_for_each_entry_safe(send_wqe, next_send_wqe, &qp->requester.submitted_swqe_head, list) {
		list_del_init(&send_wqe->list);
		kmem_cache_free(pib_ib_send_wqe_cachep, send_wqe);
	}
	qp->requester.nr_submitted_swqe = 0;

	qp->requester.nr_rd_atomic = 0;

	list_for_each_entry_safe(recv_wqe, next_recv_wqe, &qp->responder.recv_wqe_head, list) {
		list_del_init(&recv_wqe->list);
		kmem_cache_free(pib_ib_recv_wqe_cachep, recv_wqe);
	}
	qp->responder.nr_recv_wqe = 0;

	list_for_each_entry_safe_reverse(ack, ack_next, &qp->responder.ack_head, list) {
		list_del_init(&ack->list);
		kmem_cache_free(pib_ib_ack_cachep, ack);
	}
	qp->responder.nr_rd_atomic = 0;

	pib_util_remove_cq(qp->send_cq, qp);
	if (qp->send_cq != qp->recv_cq)
		pib_util_remove_cq(qp->recv_cq, qp);

	reset_qp_attr(qp);

	pib_util_reschedule_qp(qp);
}


static void reset_qp_attr(struct pib_ib_qp *qp)
{
	qp->requester.psn	   = 0;
	qp->requester.expected_psn = 0;
	qp->requester.nr_rd_atomic = 0;

	qp->responder.psn	   = 0;
	qp->responder.last_OpCode  = IB_OPCODE_SEND_ONLY; /* dummy opcode */
	qp->responder.offset       = 0;
	qp->responder.nr_rd_atomic = 0;

	memset(&qp->responder.slots, 0, sizeof(qp->responder.slots));

	qp->push_rcqe              = 0;
	qp->issue_comm_est         = 0;
	qp->issue_sq_drained       = 0;
	qp->issue_last_wqe_reached = 0;
}


struct ib_qp *pib_ib_create_qp(struct ib_pd *ibpd,
			       struct ib_qp_init_attr *init_attr,
			       struct ib_udata *udata)
{
	struct pib_ib_dev *dev;
	struct pib_ib_qp *qp;
	u32 qp_num;

	debug_printk("pib_ib_create_qp: pd=%p, init_attr=%p, udata=%p\n", ibpd, init_attr, udata);

	if (!ibpd || !init_attr)
		return ERR_PTR(-EINVAL);

	dev = to_pdev(ibpd->device);

	if (!qp_init_attr_is_ok(dev, init_attr))
		return ERR_PTR(-EINVAL);

	if (init_attr->srq)
		if (ibpd != init_attr->srq->pd)
			return ERR_PTR(-EINVAL);

#if 1
	switch (init_attr->qp_type) {

	case IB_QPT_SMI:
	case IB_QPT_GSI:
		return ERR_PTR(-ENOSYS);

	default:
		break;
	}
#endif

	qp = kmem_cache_zalloc(pib_ib_qp_cachep, GFP_KERNEL);
	if (!qp)
		return ERR_PTR(-ENOMEM);

	qp->ib_qp_init_attr = *init_attr;
	qp->ib_qp_attr.cap  = init_attr->cap;

	qp->state           = IB_QPS_RESET;

	qp->qp_type         = init_attr->qp_type;

	qp->send_cq         = to_pcq(init_attr->send_cq);
	qp->recv_cq         = to_pcq(init_attr->recv_cq);

	sema_init(&qp->sem, 1);
	INIT_LIST_HEAD(&qp->new_send_wr_qp_list);
	INIT_LIST_HEAD(&qp->requester.submitted_swqe_head);
	INIT_LIST_HEAD(&qp->requester.sending_swqe_head);
	INIT_LIST_HEAD(&qp->requester.waiting_swqe_head);
	INIT_LIST_HEAD(&qp->responder.recv_wqe_head);
	INIT_LIST_HEAD(&qp->responder.ack_head);

	reset_qp_attr(qp);

	switch (qp->qp_type) {

	case IB_QPT_SMI:
		qp_num = PIB_IB_QP0;
		break;

	case IB_QPT_GSI:
		qp_num = PIB_IB_QP1;
		break;

	case IB_QPT_RC:
	case IB_QPT_UD:
		down_write(&dev->rwsem);
		qp_num = dev->last_qp_num;
		for (;;) {
			qp_num = (qp_num + 1) & PIB_IB_QPN_MASK;

			if ((qp_num == PIB_IB_QP0) || (qp_num == PIB_IB_QP1))
				continue;

			if (pib_util_find_qp(dev, qp_num) == NULL)
				break;
		}
		qp->ib_qp.qp_num = qp_num;
		dev->last_qp_num = qp_num;
		insert_qp(dev, qp);
		up_write(&dev->rwsem);
		break;

	default:
		debug_printk("pib_ib_create_qp: unknown QP type %s(%d)\n",
			     pib_get_qp_type(init_attr->qp_type), init_attr->qp_type);
		return ERR_PTR(-ENOSYS);
	}

	return &qp->ib_qp;
}


static int qp_init_attr_is_ok(const struct pib_ib_dev *dev, const struct ib_qp_init_attr *init_attr)
{
	switch (init_attr->qp_type) {

	case IB_QPT_SMI:
	case IB_QPT_GSI:
	case IB_QPT_RC:
	case IB_QPT_UD:
		break;

	default:
		return 0;
	}

	if (!init_attr->send_cq || !init_attr->recv_cq)
		return 0;

	if (!qp_cap_is_ok(dev, &init_attr->cap, (init_attr->srq != NULL)))
		return 0;

	return 1;
}


static int qp_cap_is_ok(const struct pib_ib_dev *dev, const struct ib_qp_cap *cap, int use_srq)
{
	if ((cap->max_send_wr < 1) || (dev->ib_dev_attr.max_qp_wr < cap->max_send_wr))
		return 0;

	if ((cap->max_send_sge < 1) || (dev->ib_dev_attr.max_sge < cap->max_send_sge))
		return 0;

	if (use_srq) {
		if (cap->max_recv_wr != 0)
			return 0;

		if (cap->max_recv_sge != 0)
			return 0;
	} else {
		if ((cap->max_recv_wr < 1) || (dev->ib_dev_attr.max_qp_wr < cap->max_recv_wr))
			return 0;
		
		if ((cap->max_recv_sge < 1) || (dev->ib_dev_attr.max_sge < cap->max_recv_sge))
			return 0;
	}

	return 1;
}


int pib_ib_destroy_qp(struct ib_qp *ibqp)
{
	struct pib_ib_qp *qp;
	struct pib_ib_dev *dev;

	debug_printk("pib_ib_destroy_qp\n");

	if (!ibqp)
		return -EINVAL;

	qp = to_pqp(ibqp);
	dev = to_pdev(ibqp->device);

	down_write(&dev->rwsem);

	down(&qp->sem);
	reset_qp(qp);
	up(&qp->sem);

	rb_erase(&qp->rb_node, &dev->qp_table);
	up_write(&dev->rwsem);

	kmem_cache_free(pib_ib_qp_cachep, qp);

	return 0;
}


int pib_ib_modify_qp(struct ib_qp *ibqp, struct ib_qp_attr *attr,
		     int attr_mask, struct ib_udata *udata)
{
	int ret;
	int pending_send_wr = 0;
	int issue_sq_drained = 0;
	struct pib_ib_qp *qp;
	struct pib_ib_dev *dev;
	enum ib_qp_state cur_state, new_state;

	if (!ibqp || !attr)
		return -EINVAL;

	qp = to_pqp(ibqp);
	dev = to_pdev(ibqp->device);

	down(&qp->sem);

	cur_state = (attr_mask & IB_QP_CUR_STATE) ? attr->cur_qp_state : qp->state;
	new_state = (attr_mask & IB_QP_STATE) ? attr->qp_state : cur_state;

	if (!ib_modify_qp_is_ok(cur_state, new_state, ibqp->qp_type, attr_mask))
		goto err_inval;

	if (!modify_qp_is_ok(to_pdev(ibqp->device), qp, attr, attr_mask))
		goto err_inval;

	if (attr_mask & IB_QP_PATH_MTU)
		qp->ib_qp_attr.path_mtu    = attr->path_mtu;

	if (attr_mask & IB_QP_QKEY)
		qp->ib_qp_attr.qkey        = attr->qkey;

	if (attr_mask & IB_QP_RQ_PSN)
		qp->responder.psn          = attr->rq_psn;

	if (attr_mask & IB_QP_SQ_PSN) {
		qp->requester.psn          = attr->sq_psn;
		qp->requester.expected_psn = attr->sq_psn;
	}

	if (attr_mask & IB_QP_DEST_QPN)
		qp->ib_qp_attr.dest_qp_num = attr->dest_qp_num;

	if (attr_mask & IB_QP_ACCESS_FLAGS)
		qp->ib_qp_attr.qp_access_flags = attr->qp_access_flags;
	
	if (attr_mask & IB_QP_CAP) {
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
		qp->ib_qp_attr.max_rd_atomic = attr->max_rd_atomic;

	if (attr_mask & IB_QP_MAX_DEST_RD_ATOMIC)
		qp->ib_qp_attr.max_dest_rd_atomic = attr->max_dest_rd_atomic;

	if (attr_mask & IB_QP_MIN_RNR_TIMER)
		qp->ib_qp_attr.min_rnr_timer = attr->min_rnr_timer;

	if (attr_mask & IB_QP_PORT) {
		qp->ib_qp_attr.port_num    = attr->port_num;

		switch (qp->qp_type) {
		case IB_QPT_UD:
			qp->ib_qp_attr.path_mtu =
				dev->ports[attr->port_num - 1].ib_port_attr.active_mtu;
			break;
		default:
			break;
		}
	}

	if (attr_mask & IB_QP_TIMEOUT)
		qp->ib_qp_attr.timeout     = attr->timeout;

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

		if ((new_state == IB_QPS_SQE) && (qp->qp_type == IB_QPT_RC))
			goto err_inval;

		if ((cur_state == IB_QPS_SQD) && !qp->issue_sq_drained &&
		    ((new_state == IB_QPS_RTS) || (new_state == IB_QPS_SQD)))
			goto err_inval;

		qp->state = new_state;

		/* side reaction when change QP state */ 
		switch (new_state) {

		case IB_QPS_RESET:
			reset_qp(qp);
			break;

		case IB_QPS_RTR:
			/* Allow event to retrigger if QP set to RTR more than once */
			qp->issue_comm_est = 0;
			break;

		case IB_QPS_RTS:
			pending_send_wr = get_send_wr_num(qp);
			break;

		case IB_QPS_SQD:
			/* @todo */
			/* en_sqd_async_notify */
			issue_sq_drained = list_empty(&qp->requester.sending_swqe_head) &&
				list_empty(&qp->requester.waiting_swqe_head);
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
			pib_util_insert_async_qp_event(qp, IB_EVENT_SQ_DRAINED);
			qp->issue_sq_drained = 1;
		}

		if ((cur_state == IB_QPS_SQD) && (new_state != IB_QPS_SQD))
			qp->issue_sq_drained = 0;
	}

	up(&qp->sem);

	/* 送信可能状態に */
	if (pending_send_wr)
		get_ready_to_send(dev, qp);

	return 0;

err_inval:
	up(&qp->sem);
	ret = -EINVAL;

	return ret;
}


static int modify_qp_is_ok(const struct pib_ib_dev *dev, const struct pib_ib_qp *qp, const struct ib_qp_attr *attr, int attr_mask)
{
	/* IB_QP_EN_SQD_ASYNC_NOTIFY */
	/*    en_sqd_async_notify */

	/* IB_QP_ACCESS_FLAGS */

	if (attr_mask & IB_QP_PORT)
		if (qp->qp_type == IB_QPT_SMI ||
		    qp->qp_type == IB_QPT_GSI ||
		    attr->port_num == 0 ||
		    attr->port_num > dev->ib_dev.phys_port_cnt)
			return 0;

	if (attr_mask & IB_QP_AV)
		if (attr->ah_attr.dlid >= PIB_IB_LID_BASE)
			return 0;

	if (attr_mask & IB_QP_PATH_MTU)
		if ((attr->path_mtu < IB_MTU_256) || (IB_MTU_4096 < attr->path_mtu))
			return 0;
	
	if (attr_mask & IB_QP_TIMEOUT)
		if (attr->timeout & ~PIB_IB_LOCAL_ACK_TIMEOUT_MASK)
			return 0;

	if (attr_mask & IB_QP_RETRY_CNT)
		if (attr->retry_cnt & ~7) /* @todo */
			return 0;

	if (attr_mask & IB_QP_MIN_RNR_TIMER)
		if (attr->min_rnr_timer & ~PIB_IB_MIN_RNR_NAK_TIMER_MASK)
			return 0;

	if (attr_mask & IB_QP_RNR_RETRY)
		if (attr->rnr_retry & ~7) /* @todo */
			return 0;

	if (attr_mask & IB_QP_MAX_QP_RD_ATOMIC)
		if (attr->max_rd_atomic > dev->ib_dev_attr.max_qp_rd_atom)
			return 0;
	
	if (attr_mask & IB_QP_MAX_DEST_RD_ATOMIC)
		if (attr->max_dest_rd_atomic > dev->ib_dev_attr.max_qp_rd_atom)
			return 0;

	if (attr_mask & IB_QP_RQ_PSN)
		if (attr->rq_psn & ~PIB_IB_PSN_MASK)
			return 0;

	if (attr_mask & IB_QP_SQ_PSN)
		if (attr->sq_psn & ~PIB_IB_PSN_MASK)
			return 0;

	if (attr_mask & IB_QP_CAP)
		if (!qp_cap_is_ok(dev, &attr->cap, (qp->ib_qp_init_attr.srq != NULL)))
			return 0;

	/* IB_QP_PATH_MIG_STATE */
	/*  */
	/* IB_QP_ALT_PATH */

	return 1;
}


int pib_ib_query_qp(struct ib_qp *ibqp, struct ib_qp_attr *qp_attr, int qp_attr_mask,
		    struct ib_qp_init_attr *qp_init_attr)
{
	struct pib_ib_qp *qp;

	if (!ibqp || !qp_attr || !qp_init_attr)
		return -EINVAL;

	qp = to_pqp(ibqp);

#if 0
	if (qp->s_flags & QIB_S_SIGNAL_REQ_WR)
		init_attr->sq_sig_type = IB_SIGNAL_REQ_WR;
	else
		init_attr->sq_sig_type = IB_SIGNAL_ALL_WR;
#endif

	down(&qp->sem);

	*qp_attr              = qp->ib_qp_attr;
	*qp_init_attr         = qp->ib_qp_init_attr;

	qp_attr->qp_state     = qp->state;
	qp_attr->cur_qp_state = qp->state;

	qp_attr->sq_psn       = qp->requester.psn & PIB_IB_PSN_MASK;
	qp_attr->rq_psn       = qp->responder.psn & PIB_IB_PSN_MASK;

	up(&qp->sem);

	return 0;
}


int pib_ib_post_send(struct ib_qp *ibqp, struct ib_send_wr *ibwr,
		     struct ib_send_wr **bad_wr)
{
	int i, ret = 0;
	int pending_send_wr = 0;
	struct pib_ib_dev *dev;
	struct pib_ib_send_wqe *send_wqe;
	struct pib_ib_qp *qp;
	enum pib_result_type res = PIB_RES_SCCUESS;
	u64 total_length = 0;
	u32 imm_data;

	if (!ibqp || !ibwr)
		return -EINVAL;

	dev = to_pdev(ibqp->device);

	qp = to_pqp(ibqp);

	if ((ibqp->qp_num == PIB_IB_QP0) || (ibqp->qp_num == PIB_IB_QP1))
		return -EINVAL;

	down(&qp->sem);

next_wr:
	imm_data = ibwr->ex.imm_data;


#ifdef PIB_HACK_IMM_DATA_LKEY
	for (i = ibwr->num_sge - 1 ; i >= 0 ; i--) {
		if (ibwr->sg_list[i].lkey == PIB_IB_IMM_DATA_LKEY) {
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

	send_wqe = kmem_cache_zalloc(pib_ib_send_wqe_cachep, GFP_KERNEL);
	if (!send_wqe) {
		ret = -ENOMEM;
		goto done;
	}

	INIT_LIST_HEAD(&send_wqe->list);

	send_wqe->wr_id      = ibwr->wr_id;
	send_wqe->opcode     = ibwr->opcode;
	send_wqe->send_flags = ibwr->send_flags;
	send_wqe->imm_data   = imm_data;
	send_wqe->num_sge    = ibwr->num_sge;

	for (i=0 ; i<ibwr->num_sge ; i++) {
		send_wqe->sge_array[i] = ibwr->sg_list[i];

		if (pib_ib_get_behavior(dev, PIB_BEHAVIOR_ZERO_LEN_SGE_CONSIDER_AS_MAX_LEN))
			if (ibwr->sg_list[i].length == 0)
				ibwr->sg_list[i].length = PIB_IB_MAX_PAYLOAD_LEN;

		total_length += ibwr->sg_list[i].length;
	}

	if ((send_wqe->opcode == IB_WR_ATOMIC_CMP_AND_SWP) || (send_wqe->opcode == IB_WR_ATOMIC_FETCH_AND_ADD)) {
		/* @todo total_length は 8 バイト未満ならエラーを出すべき？ */
		total_length = 8;
	}

	if (PIB_IB_MAX_PAYLOAD_LEN < total_length) 
		; /* @todo */

	send_wqe->total_length = (u32)total_length;

	switch (qp->qp_type) {
	case IB_QPT_RC:
		switch (ibwr->opcode) {
		case IB_WR_RDMA_WRITE:
		case IB_WR_RDMA_WRITE_WITH_IMM:
			send_wqe->wr.rdma.remote_addr   = ibwr->wr.rdma.remote_addr;
			send_wqe->wr.rdma.rkey          = ibwr->wr.rdma.rkey;
			break;

		case IB_WR_RDMA_READ:
			if (qp->ib_qp_attr.max_rd_atomic <= qp->requester.nr_rd_atomic) {
				res = PIB_RES_IMMEDIATE_RETURN;
				goto skip;
			}
			qp->requester.nr_rd_atomic++;
			send_wqe->wr.rdma.remote_addr   = ibwr->wr.rdma.remote_addr;
			send_wqe->wr.rdma.rkey          = ibwr->wr.rdma.rkey;
			break;

		case IB_WR_ATOMIC_CMP_AND_SWP:
		case IB_WR_ATOMIC_FETCH_AND_ADD:
			if (qp->ib_qp_attr.max_rd_atomic <= qp->requester.nr_rd_atomic) {
				res = PIB_RES_IMMEDIATE_RETURN;
				goto skip;
			}
			qp->requester.nr_rd_atomic++;
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
		switch (ibwr->opcode) {
		case IB_WR_SEND:
		case IB_WR_SEND_WITH_IMM:
			if (!pib_ib_get_behavior(dev, PIB_BEHAVIOR_AH_PD_VIOLATOIN_COMP_ERR))
				if (!ibwr->wr.ud.ah || qp->ib_qp.pd != ibwr->wr.ud.ah->pd) {
					res = PIB_RES_IMMEDIATE_RETURN;
					goto skip;
				}
			send_wqe->wr.ud.ah              = ibwr->wr.ud.ah;
			send_wqe->wr.ud.remote_qpn      = ibwr->wr.ud.remote_qpn;
			send_wqe->wr.ud.remote_qkey     = ibwr->wr.ud.remote_qkey;
			break;
		default:
			break;
		}
		break;
	default:
		break;
	}

	switch (qp->state) {

	case IB_QPS_RESET:
		/* @todo IB_QPS_RESET */
	default:
		res = PIB_RES_IMMEDIATE_RETURN;
		goto skip;

	case IB_QPS_ERR:
		res = PIB_RES_WR_FLUSH_ERR;
		goto skip;

	case IB_QPS_RTS:
		pending_send_wr = 1;
		break;

	case IB_QPS_SQD:
		break;
	}

	if (qp->ib_qp_init_attr.cap.max_send_wr < get_send_wr_num(qp) + 1) {
		kmem_cache_free(pib_ib_send_wqe_cachep, send_wqe);
		ret = -ENOMEM; /* @todo */
		goto done;		
	}

	send_wqe->processing.list_type = PIB_SWQE_SUBMITTED;
	send_wqe->processing.status    = IB_WC_SUCCESS;

	list_add_tail(&send_wqe->list, &qp->requester.submitted_swqe_head);
	qp->requester.nr_submitted_swqe++;

skip:
	switch (res) {

	case PIB_RES_IMMEDIATE_RETURN:
		kmem_cache_free(pib_ib_send_wqe_cachep, send_wqe);
		ret = -EINVAL;
		goto done;

	case PIB_RES_WR_FLUSH_ERR:
		kmem_cache_free(pib_ib_send_wqe_cachep, send_wqe);
		pib_util_insert_wc_error(qp->send_cq, qp, ibwr->wr_id,
					 IB_WC_WR_FLUSH_ERR, ibwr->opcode);
		break;

	default:
		break;
	}

	ibwr = ibwr->next;
	if (ibwr)
		goto next_wr;

	up(&qp->sem);

	if (pending_send_wr)
		get_ready_to_send(dev, qp);

	return 0;

done:
	up(&qp->sem);

	if (bad_wr)
		*bad_wr = ibwr;

	return ret;
}


int pib_ib_post_recv(struct ib_qp *ibqp, struct ib_recv_wr *ibwr,
		     struct ib_recv_wr **bad_wr)
{
	int i, ret;
	struct pib_ib_dev *dev;
	struct pib_ib_recv_wqe *recv_wqe;
	struct pib_ib_qp *qp;
	enum pib_result_type res = PIB_RES_SCCUESS;
	u64 total_length = 0;

	if (!ibqp || !ibwr)
		return -EINVAL;

	dev = to_pdev(ibqp->device);

	qp = to_pqp(ibqp);

	if ((qp->ib_qp.qp_num == PIB_IB_QP0) || (qp->ib_qp.qp_num == PIB_IB_QP1))
		return -EINVAL;

	if (qp->ib_qp_init_attr.srq)
		return -EINVAL;

next_wr:
	if ((ibwr->num_sge < 1) || (qp->ib_qp_init_attr.cap.max_recv_sge < ibwr->num_sge)) {
		ret = -EINVAL;
		goto err;
	}

	recv_wqe = kmem_cache_zalloc(pib_ib_recv_wqe_cachep, GFP_KERNEL);
	if (!recv_wqe) {
		ret = -ENOMEM;
		goto err;
	}

	INIT_LIST_HEAD(&recv_wqe->list);

	recv_wqe->wr_id   = ibwr->wr_id;
	recv_wqe->num_sge = ibwr->num_sge;

	for (i=0 ; i<ibwr->num_sge ; i++) {
		recv_wqe->sge_array[i] = ibwr->sg_list[i];

		if (pib_ib_get_behavior(dev, PIB_BEHAVIOR_ZERO_LEN_SGE_CONSIDER_AS_MAX_LEN))
			if (ibwr->sg_list[i].length == 0)
				ibwr->sg_list[i].length = PIB_IB_MAX_PAYLOAD_LEN;

		total_length += ibwr->sg_list[i].length;
	}
	
	if (PIB_IB_MAX_PAYLOAD_LEN < total_length) 
		; /* @todo */

	recv_wqe->total_length = (u32)total_length;

	down(&qp->sem);

	/* QP check */
	switch (qp->state) {
	case IB_QPS_RESET:
	default:
		res = PIB_RES_IMMEDIATE_RETURN;
		goto skip;

	case IB_QPS_ERR:
		res = PIB_RES_WR_FLUSH_ERR;
		goto skip;

	case IB_QPS_INIT:
	case IB_QPS_RTR:
	case IB_QPS_RTS:
	case IB_QPS_SQD:
	case IB_QPS_SQE:
		/* OK */
		break;
	}

	if (qp->ib_qp_init_attr.cap.max_recv_wr < qp->responder.nr_recv_wqe + 1) {
		up(&qp->sem);
		kmem_cache_free(pib_ib_recv_wqe_cachep, recv_wqe);
		ret = -ENOMEM; /* @todo */
		goto err;
	}

	list_add_tail(&recv_wqe->list, &qp->responder.recv_wqe_head);
	qp->responder.nr_recv_wqe++;
skip:
	up(&qp->sem);

	switch (res) {

	case PIB_RES_IMMEDIATE_RETURN:
		kmem_cache_free(pib_ib_recv_wqe_cachep, recv_wqe);
		ret = -EINVAL;
		goto err;

	case PIB_RES_WR_FLUSH_ERR:
		kmem_cache_free(pib_ib_recv_wqe_cachep, recv_wqe);

		down(&qp->sem);
		pib_util_insert_wc_error(qp->recv_cq, qp, ibwr->wr_id,
					 IB_WC_WR_FLUSH_ERR, IB_WC_RECV);
		up(&qp->sem);
		break;

	default:
		break;
	}

	ibwr = ibwr->next;
	if (ibwr)
		goto next_wr;

	return 0;

err:
	if (bad_wr)
		*bad_wr = ibwr;

	return ret;
}


static void get_ready_to_send(struct pib_ib_dev *dev, struct pib_ib_qp *qp)
{
	down_write(&dev->rwsem);
	if (!qp->has_new_send_wr) {
		list_add_tail(&qp->new_send_wr_qp_list, &dev->thread.new_send_wr_qp_head);
		qp->has_new_send_wr = 1;
	}
	up_write(&dev->rwsem);

	set_bit(PIB_THREAD_NEW_SEND_WR, &dev->thread.flags);
	complete(&dev->thread.completion);
}


void pib_util_insert_async_qp_error(struct pib_ib_qp *qp, enum ib_event_type event)
{
	struct ib_event ev;

	if (!qp->ib_qp.event_handler)
		return;

	ev.event      = event;
	ev.device     = qp->ib_qp.device;
	ev.element.qp = &qp->ib_qp;

	local_bh_disable();
	qp->ib_qp.event_handler(&ev, qp->ib_qp.qp_context);
	local_bh_enable();
}


void pib_util_insert_async_qp_event(struct pib_ib_qp *qp, enum ib_event_type event)
{
	pib_util_insert_async_qp_error(qp, event);
}
