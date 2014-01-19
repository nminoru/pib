/*
 * Copyright (c) 2013,2014 Minoru NAKAMURA <nminoru@nminoru.jp>
 *
 * This code is licenced under the GPL version 2 or BSD license.
 */
#include <linux/module.h>
#include <linux/init.h>

#include <rdma/ib_pack.h>

#include "pib.h"


int pib_attach_mcast(struct ib_qp *ibqp, union ib_gid *gid, u16 lid)
{
	int ret, count;
	struct pib_qp *qp;
	struct pib_dev *dev;
	unsigned long flags;
	struct pib_mcast_link *mcast_link;

	pib_debug("pib: pib_attach_mcast(qp=0x%06x, lid=0x%04x)\n",
		  (int)ibqp->qp_num, lid);

	if (!ibqp)
		return -EINVAL;

	if (lid < PIB_MCAST_LID_BASE)
		return -EINVAL;

	ret = 0;

	qp = to_pqp(ibqp);
	dev = to_pdev(ibqp->device);

	spin_lock_irqsave(&dev->lock, flags);

	count = 0;

	list_for_each_entry(mcast_link, &qp->mcast_head, qp_list) {
		if (mcast_link->lid == lid)
			goto done;
		count++;
	}

	if (PIB_MCAST_QP_ATTACH < count) {
		ret = -ENOMEM;
		goto done;
	}

	mcast_link = kmem_cache_zalloc(pib_mcast_link_cachep, GFP_ATOMIC); /* @todo 割禁の外に */
	if (!mcast_link) {
		ret = -ENOMEM;
		goto done;
	}

	mcast_link->lid = lid;
	mcast_link->qp_num = qp->ib_qp.qp_num;

	INIT_LIST_HEAD(&mcast_link->qp_list);
	INIT_LIST_HEAD(&mcast_link->lid_list);

	list_add_tail(&mcast_link->qp_list, &qp->mcast_head);
	list_add_tail(&mcast_link->lid_list, &dev->mcast_table[lid - PIB_MCAST_LID_BASE]);

done:
	spin_unlock_irqrestore(&dev->lock, flags);

	return ret;
}


int pib_detach_mcast(struct ib_qp *ibqp, union ib_gid *gid, u16 lid)
{
	int ret;
	struct pib_qp *qp;
	struct pib_dev *dev;
	unsigned long flags;
	struct pib_mcast_link *mcast_link;

	pib_debug("pib: pib_detach_mcast(qp=0x%06x, lid=0x%04x)\n",
		  (int)ibqp->qp_num, lid);

	if (!ibqp)
		return -EINVAL;

	if (lid < PIB_MCAST_LID_BASE)
		return -EINVAL;

	ret = 0;

	qp = to_pqp(ibqp);
	dev = to_pdev(ibqp->device);

	spin_lock_irqsave(&dev->lock, flags);
	list_for_each_entry(mcast_link, &qp->mcast_head, qp_list) {
		if (mcast_link->lid == lid) {
			list_del(&mcast_link->qp_list);
			list_del(&mcast_link->lid_list);
			kmem_cache_free(pib_mcast_link_cachep, mcast_link);
			goto done;
		}
	}
done:
	spin_unlock_irqrestore(&dev->lock, flags);

	return 0;
}


void pib_detach_all_mcast(struct pib_dev *dev, struct pib_qp *qp)
{
	unsigned long flags;
	struct pib_mcast_link *mcast_link, *next_mcast_link;

	spin_lock_irqsave(&dev->lock, flags);
	list_for_each_entry_safe(mcast_link, next_mcast_link, &qp->mcast_head, qp_list) {
		list_del(&mcast_link->qp_list);
		list_del(&mcast_link->lid_list);
		kmem_cache_free(pib_mcast_link_cachep, mcast_link);
	}
	spin_unlock_irqrestore(&dev->lock, flags);
}
