/*
 * Copyright (c) 2013,2014 Minoru NAKAMURA <nminoru@nminoru.jp>
 *
 * This code is licenced under the GPL version 2 or BSD license.
 */
#include <linux/module.h>
#include <linux/init.h>

#include "pib.h"


static int insert_wc(struct pib_cq *cq, const struct ib_wc *wc);


struct ib_cq *pib_create_cq(struct ib_device *ibdev, int entries, int vector,
			    struct ib_ucontext *context,
			    struct ib_udata *udata)
{
	int i;
	struct pib_dev *dev;
	struct pib_cq *cq;
	struct pib_cqe *cqe, *cqe_next;

	dev = to_pdev(ibdev);

	if (entries < 1 || dev->ib_dev_attr.max_cqe <= entries)
		return ERR_PTR(-EINVAL);

	if (dev->ib_dev_attr.max_cq <= dev->nr_cq)
		return ERR_PTR(-ENOMEM);

	cq = kmem_cache_zalloc(pib_cq_cachep, GFP_KERNEL);
	if (!cq)
		return ERR_PTR(-ENOMEM);

	cq->ib_cq.cqe	= entries;
	cq->nr_cqe	= 0;

	spin_lock_init(&cq->lock);

	INIT_LIST_HEAD(&cq->cqe_head);
	INIT_LIST_HEAD(&cq->free_cqe_head);

	/* allocate CQE internally */

	for (i=0 ; i<entries ; i++) {
		struct pib_cqe *cqe;

		cqe = kmem_cache_zalloc(pib_cqe_cachep, GFP_KERNEL);
		if (!cqe)
			goto err_allloc_ceq;
		
		INIT_LIST_HEAD(&cqe->list);
		list_add_tail(&cqe->list, &cq->free_cqe_head);
	}

	return &cq->ib_cq;

err_allloc_ceq:
	list_for_each_entry_safe(cqe, cqe_next, &cq->free_cqe_head, list) {
		list_del_init(&cqe->list);
		kmem_cache_free(pib_cqe_cachep, cqe);
	}

	kmem_cache_free(pib_cq_cachep, cq);

	return ERR_PTR(-ENOMEM);
}


int pib_destroy_cq(struct ib_cq *ibcq)
{
	unsigned long flags;
	struct pib_cq *cq;
	struct pib_cqe *cqe, *cqe_next;

	if (!ibcq)
		return 0;

	cq = to_pcq(ibcq);

	spin_lock_irqsave(&cq->lock, flags);
	list_for_each_entry_safe(cqe, cqe_next, &cq->cqe_head, list) {
		list_del_init(&cqe->list);
		kmem_cache_free(pib_cqe_cachep, cqe);
	}
	list_for_each_entry_safe(cqe, cqe_next, &cq->free_cqe_head, list) {
		list_del_init(&cqe->list);
		kmem_cache_free(pib_cqe_cachep, cqe);
	}
	cq->nr_cqe = 0;
	spin_unlock_irqrestore(&cq->lock, flags);

	kmem_cache_free(pib_cq_cachep, cq);

	return 0;
}


int pib_modify_cq(struct ib_cq *ibcq, u16 cq_count, u16 cq_period)
{
	pr_err("pib: pib_modify_cq\n");
	return 0;
}


int pib_resize_cq(struct ib_cq *ibcq, int entries, struct ib_udata *udata)
{
	pr_err("pib: pib_resize_cq\n");
	return 0;
}


int pib_poll_cq(struct ib_cq *ibcq, int num_entries, struct ib_wc *ibwc)
{
	int i, ret = 0;
	struct pib_cq *cq;
	unsigned long flags;

	if (!ibcq)
		return -EINVAL;

	cq = to_pcq(ibcq);

	spin_lock_irqsave(&cq->lock, flags);
	for (i=0 ; (i<num_entries) && !list_empty(&cq->cqe_head) ; i++) {
		struct pib_cqe *cqe;

		cqe = list_first_entry(&cq->cqe_head, struct pib_cqe, list);
		list_del_init(&cqe->list);
		list_add_tail(&cqe->list, &cq->free_cqe_head);

		ibwc[i] = cqe->ib_wc;

		cq->nr_cqe--;
		ret++;
	}
	spin_unlock_irqrestore(&cq->lock, flags);

	return ret;
}


int pib_req_notify_cq(struct ib_cq *ibcq, enum ib_cq_notify_flags flags)
{
	return 0;
}


/**
 *  QP を RESET に変更した場合に該当する CQ から外す
 *  @return 削除した WC 数
 */
int pib_util_remove_cq(struct pib_cq *cq, struct pib_qp *qp)
{
	int count = 0;
	unsigned long flags;
	struct pib_cqe *cqe, *cqe_next;

	BUG_ON(qp == NULL);

	spin_lock_irqsave(&cq->lock, flags);
	list_for_each_entry_safe(cqe, cqe_next, &cq->cqe_head, list) {
		if (cqe->ib_wc.qp == &qp->ib_qp) {
			cq->nr_cqe--;
			list_del_init(&cqe->list);
			list_add_tail(&cqe->list, &cq->free_cqe_head);
			count++;
		}
	}
	spin_unlock_irqrestore(&cq->lock, flags);

	return count;
}


int pib_util_insert_wc_success(struct pib_cq *cq, const struct ib_wc *wc)
{
	return insert_wc(cq, wc);
}


int pib_util_insert_wc_error(struct pib_cq *cq, struct pib_qp *qp, u64 wr_id, enum ib_wc_status status, enum ib_wc_opcode opcode)
{
	struct ib_wc wc = {
		.wr_id    = wr_id,
		.status   = status,
		.opcode   = opcode,
		.qp       = &qp->ib_qp,
	};

	return insert_wc(cq, &wc);
}


static int insert_wc(struct pib_cq *cq, const struct ib_wc *wc)
{
	unsigned long flags;
	struct pib_cqe *cqe;
#if 0
	struct ib_event ev;
#endif

	spin_lock_irqsave(&cq->lock, flags);

	if (list_empty(&cq->free_cqe_head)) {
		goto cq_overflow;
	}

	cqe = list_first_entry(&cq->free_cqe_head, struct pib_cqe, list);
	list_del_init(&cqe->list);

	cqe->ib_wc = *wc;

	if (to_pqp(wc->qp)->qp_type == IB_QPT_SMI)
		cqe->ib_wc.port_num = to_pqp(wc->qp)->ib_qp_init_attr.port_num;

	cq->nr_cqe++;

	list_add_tail(&cqe->list, &cq->cqe_head);

	/* tell completion channel */
	cq->ib_cq.comp_handler(&cq->ib_cq, cq->ib_cq.cq_context);

	spin_unlock_irqrestore(&cq->lock, flags);

	return 0;

cq_overflow:
	/* CQ overflow */

	/* @todo この実装を正せ */

#if 0
	ev.event      = IB_EVENT_CQ_ERR;
	ev.device     = cq->ib_cq.device;
	ev.element.cq = &cq->ib_cq;

	cq->ib_cq.event_handler(&ev, cq->ib_cq.cq_context);
#endif

	spin_unlock_irqrestore(&cq->lock, flags);

	return -ENOMEM;
}
