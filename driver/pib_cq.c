/*
 * Copyright (c) 2013 Minoru NAKAMURA <nminoru@nminoru.jp>
 *
 * This code is licenced under the GPL version 2 or BSD license.
 */
#include <linux/module.h>
#include <linux/init.h>

#include "pib.h"


static int insert_wc(struct pib_ib_cq *cq, const struct ib_wc *wc);


struct ib_cq *pib_ib_create_cq(struct ib_device *ibdev, int entries, int vector,
			       struct ib_ucontext *context,
			       struct ib_udata *udata)
{
	struct pib_ib_dev *dev = to_pdev(ibdev);
	struct pib_ib_cq *cq;

	if (entries < 1 || dev->ib_dev_attr.max_cqe <= entries)
		return ERR_PTR(-EINVAL);

	if (dev->ib_dev_attr.max_cq <= dev->nr_cq)
		return ERR_PTR(-ENOMEM);

	cq = kmem_cache_zalloc(pib_ib_cq_cachep, GFP_KERNEL);
	if (!cq)
		return ERR_PTR(-ENOMEM);

	cq->ib_cq.cqe = entries;

	sema_init(&cq->sem, 1);
	INIT_LIST_HEAD(&cq->cqe_head);

	return &cq->ib_cq;
}


int pib_ib_destroy_cq(struct ib_cq *ibcq)
{
	struct pib_ib_cq *cq;
	struct pib_ib_cqe *cqe, *cqe_next;

	if (!ibcq)
		return 0;

	cq = to_pcq(ibcq);

	down(&cq->sem);
	list_for_each_entry_safe(cqe, cqe_next, &cq->cqe_head, list) {
		list_del_init(&cqe->list);
		kmem_cache_free(pib_ib_cqe_cachep, cqe);
	}
	cq->nr_cqe = 0;
	up(&cq->sem);

	kmem_cache_free(pib_ib_cq_cachep, cq);

	return 0;
}


int pib_ib_modify_cq(struct ib_cq *ibcq, u16 cq_count, u16 cq_period)
{
	debug_printk("pib_ib_modify_cq\n");
	return 0;
}


int pib_ib_resize_cq(struct ib_cq *ibcq, int entries, struct ib_udata *udata)
{
	debug_printk("pib_ib_resize_cq\n");
	return 0;
}


int pib_ib_poll_cq(struct ib_cq *ibcq, int num_entries, struct ib_wc *ibwc)
{
	int i;
	struct pib_ib_cq *cq;

	if (!ibcq)
		return -EINVAL;

	cq = to_pcq(ibcq);

	down(&cq->sem);
	for (i=0 ; i<num_entries ; i++) {
		struct pib_ib_cqe *cqe;

		if (cq->nr_cqe <= 0)
			break;

		cqe = list_first_entry(&cq->cqe_head, struct pib_ib_cqe, list);
		list_del_init(&cqe->list);

		ibwc[i] = cqe->ib_wc;

		cq->nr_cqe--;

		kmem_cache_free(pib_ib_cqe_cachep, cqe);
	}
	up(&cq->sem);
	
	return i;
}


int pib_ib_req_notify_cq(struct ib_cq *ibcq, enum ib_cq_notify_flags flags)
{
	return 0;
}


/**
 *  QP を RESET に変更した場合に該当する CQ から外す
 */
void pib_util_remove_cq(struct pib_ib_cq *cq, struct pib_ib_qp *qp)
{
	struct pib_ib_cqe *cqe, *cqe_next;

	BUG_ON(qp == NULL);

	down(&cq->sem);
	list_for_each_entry_safe(cqe, cqe_next, &cq->cqe_head, list) {
		if (cqe->ib_wc.qp == &qp->ib_qp) {
			list_del_init(&cqe->list);
			kmem_cache_free(pib_ib_cqe_cachep, cqe);
		}
	}
	up(&cq->sem);
}


int pib_util_insert_wc_success(struct pib_ib_cq *cq, const struct ib_wc *wc)
{
	return insert_wc(cq, wc);
}


int pib_util_insert_wc_error(struct pib_ib_cq *cq, struct pib_ib_qp *qp, u64 wr_id, enum ib_wc_status status, enum ib_wc_opcode opcode)
{
	struct ib_wc wc = {
		.wr_id    = wr_id,
		.status   = status,
		.opcode   = opcode,
		.qp       = &qp->ib_qp,
	};

	return insert_wc(cq, &wc);
}


static int insert_wc(struct pib_ib_cq *cq, const struct ib_wc *wc)
{
	struct pib_ib_cqe *cqe;

	cqe = kmem_cache_zalloc(pib_ib_cqe_cachep, GFP_KERNEL);

	if (!cqe) {
		debug_printk("insert_wc: ENOMEM\n");
		return -ENOMEM;
	}

	cqe->ib_wc = *wc;
	INIT_LIST_HEAD(&cqe->list);

	down(&cq->sem);

	list_add_tail(&cqe->list, &cq->cqe_head);
	cq->nr_cqe++;

	if (cq->ib_cq.cqe <= cq->nr_cqe) {
		/* CQ overflow */
		struct ib_event ev;

		ev.event      = IB_EVENT_CQ_ERR;
		ev.device     = cq->ib_cq.device;
		ev.element.cq = &cq->ib_cq;

		local_bh_disable();
		cq->ib_cq.event_handler(&ev, cq->ib_cq.cq_context);
		local_bh_enable();
	}

	up(&cq->sem);

	/* tell completion channel */
	local_bh_disable();
	cq->ib_cq.comp_handler(&cq->ib_cq, cq->ib_cq.cq_context);
	local_bh_enable();

	return 0;	
}
