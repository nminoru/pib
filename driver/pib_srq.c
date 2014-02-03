/*
 * Copyright (c) 2013,2014 Minoru NAKAMURA <nminoru@nminoru.jp>
 *
 * This code is licenced under the GPL version 2 or BSD license.
 */
#include <linux/module.h>
#include <linux/init.h>

#include "pib.h"


static volatile int post_srq_recv_counter; /* これは厳密でなくてもよい */


static void srq_error_handler(struct pib_work_struct *work);


static int pib_srq_attr_is_ok(const struct pib_dev *dev, const struct ib_srq_attr *attr)
{
	if ((attr->max_wr < 1)  || (dev->ib_dev_attr.max_srq_wr  < attr->max_wr))
		return 0;

	if ((attr->max_sge < 1) || (dev->ib_dev_attr.max_srq_sge < attr->max_sge))
		return 0;

	return 1;
}


struct ib_srq *pib_create_srq(struct ib_pd *ibpd,
			      struct ib_srq_init_attr *init_attr,
			      struct ib_udata *udata)
{
	int i;
	struct pib_dev *dev;
	struct pib_srq *srq;
	unsigned long flags;
	u32 srq_num;

	if (!ibpd || !init_attr)
		return ERR_PTR(-EINVAL);

	dev = to_pdev(ibpd->device);

	if (!pib_srq_attr_is_ok(dev, &init_attr->attr))
		return ERR_PTR(-EINVAL);

	srq = kmem_cache_zalloc(pib_srq_cachep, GFP_KERNEL);
	if (!srq)
		return ERR_PTR(-ENOMEM);

	INIT_LIST_HEAD(&srq->list);
	getnstimeofday(&srq->creation_time);

	spin_lock_irqsave(&dev->lock, flags);
	srq_num = pib_alloc_obj_num(dev, PIB_BITMAP_SRQ_START, PIB_MAX_SRQ, &dev->last_srq_num);
	if (srq_num == (u32)-1) {
		spin_unlock_irqrestore(&dev->lock, flags);
		goto err_alloc_srq_num;
	}
	dev->nr_srq++;
	list_add_tail(&srq->list, &dev->srq_head);
	spin_unlock_irqrestore(&dev->lock, flags);

	srq->srq_num	= srq_num;
	srq->state	= PIB_STATE_OK;

	srq->ib_srq_attr = init_attr->attr;
	srq->ib_srq_attr.srq_limit = 0; /* srq_limit isn't set when ibv_craete_srq */

	spin_lock_init(&srq->lock);
	INIT_LIST_HEAD(&srq->recv_wqe_head);
	INIT_LIST_HEAD(&srq->free_recv_wqe_head);
	PIB_INIT_WORK(&srq->work, srq, srq_error_handler);

	for (i=0 ; i<srq->ib_srq_attr.max_wr ; i++) {
		struct pib_recv_wqe *recv_wqe;

		recv_wqe = kmem_cache_zalloc(pib_recv_wqe_cachep, GFP_KERNEL);
		if (!recv_wqe)
			goto err_alloc_wqe;

		INIT_LIST_HEAD(&recv_wqe->list);
		list_add_tail(&recv_wqe->list, &srq->free_recv_wqe_head);
	}

	return &srq->ib_srq;

err_alloc_wqe:
	while (!list_empty(&srq->free_recv_wqe_head)) {
		struct pib_recv_wqe *recv_wqe;
		recv_wqe = list_first_entry(&srq->free_recv_wqe_head, struct pib_recv_wqe, list);
		list_del_init(&recv_wqe->list);
		kmem_cache_free(pib_recv_wqe_cachep, recv_wqe);
	}

	spin_lock_irqsave(&dev->lock, flags);
	list_del(&srq->list);
	dev->nr_srq--;
	pib_dealloc_obj_num(dev, PIB_BITMAP_SRQ_START, srq_num);
	spin_unlock_irqrestore(&dev->lock, flags);

err_alloc_srq_num:
	kmem_cache_free(pib_srq_cachep, srq);
	
	return ERR_PTR(-ENOMEM);
}


int pib_destroy_srq(struct ib_srq *ibsrq)
{
	struct pib_dev *dev;
	struct pib_srq *srq;
	struct pib_recv_wqe *recv_wqe, *next;
	unsigned long flags;

	if (!ibsrq)
		return 0;

	dev = to_pdev(ibsrq->device);
	srq = to_psrq(ibsrq);

	spin_lock_irqsave(&srq->lock, flags);
	list_for_each_entry_safe(recv_wqe, next, &srq->recv_wqe_head, list) {
		list_del_init(&recv_wqe->list);
		kmem_cache_free(pib_recv_wqe_cachep, recv_wqe);
	}
	list_for_each_entry_safe(recv_wqe, next, &srq->free_recv_wqe_head, list) {
		list_del_init(&recv_wqe->list);
		kmem_cache_free(pib_recv_wqe_cachep, recv_wqe);
	}
	srq->nr_recv_wqe = 0;
	spin_unlock_irqrestore(&srq->lock, flags);

	spin_lock_irqsave(&dev->lock, flags);
	list_del(&srq->list);
	dev->nr_srq--;
	pib_dealloc_obj_num(dev, PIB_BITMAP_SRQ_START, srq->srq_num);
	spin_unlock_irqrestore(&dev->lock, flags);

	kmem_cache_free(pib_srq_cachep, srq);

	return 0;
}


int pib_modify_srq(struct ib_srq *ibsrq, struct ib_srq_attr *attr,
		   enum ib_srq_attr_mask attr_mask, struct ib_udata *udata)
{
	int ret;
	struct pib_dev *dev;
	struct pib_srq *srq;
	unsigned long flags;

	if (!ibsrq || !attr)
		return -EINVAL;

	dev = to_pdev(ibsrq->device);
	srq = to_psrq(ibsrq);

	spin_lock_irqsave(&srq->lock, flags);

	if (srq->state != PIB_STATE_OK) {
		ret = -EACCES; 
		goto done;
	}

	if (attr_mask & IB_SRQ_MAX_WR) {
		struct ib_srq_attr new_attr;

		if (!(dev->ib_dev_attr.device_cap_flags & IB_DEVICE_SRQ_RESIZE)) {
			pib_debug("pib: Can't resize SRQ w/o DEVICE_SRQ_RESIZE\n");
			ret = -EINVAL;
			goto done;
		}

		new_attr = srq->ib_srq_attr;
		new_attr.max_wr  = attr->max_wr;
		new_attr.max_sge = attr->max_sge;

		if (!pib_srq_attr_is_ok(dev, &new_attr)) {
			ret = -EINVAL;
			goto done;
		}

		/* @todo ここで free_recv 増減を行う */

		srq->ib_srq_attr = new_attr;
	}

	if (attr_mask & IB_SRQ_LIMIT) {
		srq->ib_srq_attr.srq_limit = attr->srq_limit;
		srq->issue_srq_limit = 0;
	}

	ret = 0;

done:
	spin_unlock_irqrestore(&srq->lock, flags);

	return ret;
}


int pib_query_srq(struct ib_srq *ibsrq, struct ib_srq_attr *attr)
{
	int ret;
	struct pib_srq *srq;
	unsigned long flags;

	if (!ibsrq || !attr)
		return -EINVAL;

	srq = to_psrq(ibsrq);

	spin_lock_irqsave(&srq->lock, flags);

	if (srq->state != PIB_STATE_OK) {
		ret = -EACCES; 
		goto done;
	}

	*attr = srq->ib_srq_attr;

	ret = 0;

done:
	spin_unlock_irqrestore(&srq->lock, flags);

	return ret;
}


int pib_post_srq_recv(struct ib_srq *ibsrq, struct ib_recv_wr *ibwr,
		      struct ib_recv_wr **bad_wr)
{
	int i, ret = 0;
	struct pib_dev *dev;
	struct pib_recv_wqe *recv_wqe;
	struct pib_srq *srq;
	u64 total_length = 0;
	unsigned long flags;

	if (!ibsrq || !ibwr)
		return -EINVAL;

	dev = to_pdev(ibsrq->device);

	srq = to_psrq(ibsrq);

	spin_lock_irqsave(&srq->lock, flags);

	/*
	 *  No state checking
	 * 
	 *  IBA Spec. Vol.1 10.2.9.5 SRQ STATES
	 *  Even if a SRQ is in the error state, the consumer may be able to
	 *  post WR to the SRQ.
	 */

next_wr:
	if ((ibwr->num_sge < 1) || (srq->ib_srq_attr.max_sge < ibwr->num_sge)) {
		ret = -EINVAL;
		goto err;
	}

	if (list_empty(&srq->free_recv_wqe_head)) {
		ret = -ENOMEM;
		goto err;
	}

	recv_wqe = list_first_entry(&srq->free_recv_wqe_head, struct pib_recv_wqe, list);
	list_del_init(&recv_wqe->list); /* list_del でいい？ */

	recv_wqe->wr_id   = ibwr->wr_id;
	recv_wqe->num_sge = ibwr->num_sge;

	for (i=0 ; i<ibwr->num_sge ; i++) {
		recv_wqe->sge_array[i] = ibwr->sg_list[i];

		if (pib_get_behavior(PIB_BEHAVIOR_ZERO_LEN_SGE_CONSIDER_AS_MAX_LEN))
			if (ibwr->sg_list[i].length == 0)
				ibwr->sg_list[i].length = PIB_MAX_PAYLOAD_LEN;

		total_length += ibwr->sg_list[i].length;
	}

	if (PIB_MAX_PAYLOAD_LEN < total_length) {
		ret = -EMSGSIZE;
		goto err;
	} 

	recv_wqe->total_length = (u32)total_length;

	list_add_tail(&recv_wqe->list, &srq->recv_wqe_head);

	srq->nr_recv_wqe++;

	ibwr = ibwr->next;
	if (ibwr)
		goto next_wr;

err:
	spin_unlock_irqrestore(&srq->lock, flags);

	if (ret && bad_wr)
		*bad_wr = ibwr;	

	return ret;
}


struct pib_recv_wqe *
pib_util_get_srq(struct pib_srq *srq)
{
	unsigned long flags;
	struct pib_recv_wqe *recv_wqe = NULL;

	spin_lock_irqsave(&srq->lock, flags);

	if (srq->state != PIB_STATE_OK)
		goto skip;

	if (list_empty(&srq->recv_wqe_head))
		goto skip;

	recv_wqe = list_first_entry(&srq->recv_wqe_head, struct pib_recv_wqe, list);
	list_del_init(&recv_wqe->list);
	srq->nr_recv_wqe--;

	if ((srq->ib_srq_attr.srq_limit != 0) &&
	    (srq->issue_srq_limit == 0) &&
	    (srq->nr_recv_wqe < srq->ib_srq_attr.srq_limit)) {
		struct ib_event ev;

		srq->issue_srq_limit = 1;

		ev.event       = IB_EVENT_SRQ_LIMIT_REACHED;
		ev.device      = srq->ib_srq.device;
		ev.element.srq = &srq->ib_srq;

		srq->ib_srq.event_handler(&ev, srq->ib_srq.srq_context);
	}

skip:
	spin_unlock_irqrestore(&srq->lock, flags);

	return recv_wqe;
}


void pib_util_insert_async_srq_error(struct pib_dev *dev, struct pib_srq *srq)
{
	struct ib_event ev;
	struct pib_qp *qp;
	unsigned long flags;

	BUG_ON(spin_is_locked(&srq->lock));

	spin_lock_irqsave(&srq->lock, flags);

	srq->state     = PIB_STATE_ERR;

	ev.event       = IB_EVENT_SRQ_ERR;
	ev.device      = srq->ib_srq.device;
	ev.element.srq = &srq->ib_srq;
	srq->ib_srq.event_handler(&ev, srq->ib_srq.srq_context);

	spin_unlock_irqrestore(&srq->lock, flags);

	/* ここでは srq はロックしない */

	list_for_each_entry(qp, &dev->qp_head, list) {
		spin_lock(&qp->lock);
		if (srq == to_psrq(qp->ib_qp_init_attr.srq)) {
			qp->state = IB_QPS_ERR;
			pib_util_flush_qp(qp, 0);
			pib_util_insert_async_qp_error(qp, IB_EVENT_QP_FATAL);
		}
		spin_unlock(&qp->lock);
	}
}


static void srq_error_handler(struct pib_work_struct *work)
{
	struct pib_srq *srq = work->data;
	struct pib_dev *dev = to_pdev(srq->ib_srq.device);

	BUG_ON(!spin_is_locked(&dev->lock));

	/* srq はロックしない */

	pib_util_insert_async_srq_error(dev, srq);
}
