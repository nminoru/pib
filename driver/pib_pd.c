/*
 * Copyright (c) 2013,2014 Minoru NAKAMURA <nminoru@nminoru.jp>
 *
 * This code is licenced under the GPL version 2 or BSD license.
 */
#include <linux/module.h>
#include <linux/init.h>

#include "pib.h"


struct ib_pd *
pib_alloc_pd(struct ib_device *ibdev,
	     struct ib_ucontext *ibucontext,
	     struct ib_udata *udata)
{
	struct pib_dev *dev;
	struct pib_pd *pd;
	unsigned long flags;
	u32 pd_num;

	if (!ibdev)
		return ERR_PTR(-EINVAL);

	dev = to_pdev(ibdev);

	pd = kzalloc(sizeof *pd, GFP_KERNEL);
	if (!pd)
		return ERR_PTR(-ENOMEM);

	getnstimeofday(&pd->creation_time);

	spin_lock_init(&pd->lock);

	spin_lock_irqsave(&dev->lock, flags);
	pd_num = pib_alloc_obj_num(dev, PIB_BITMAP_PD_START, PIB_MAX_PD, &dev->last_pd_num);
	if (pd_num == (u32)-1) {
		spin_unlock_irqrestore(&dev->lock, flags);
		goto err_alloc_pd_num;
	}
	dev->nr_pd++;
	spin_unlock_irqrestore(&dev->lock, flags);

	pd->pd_num = pd_num;

	pd->mr_table = vzalloc(sizeof(struct pib_mr*) * PIB_MAX_MR_PER_PD);
	if (!pd->mr_table)
		goto err_mr_table;

	return &pd->ib_pd;

err_mr_table:
	spin_lock_irqsave(&dev->lock, flags);
	dev->nr_pd--;
	pib_dealloc_obj_num(dev, PIB_BITMAP_PD_START, pd_num);
	spin_unlock_irqrestore(&dev->lock, flags);

err_alloc_pd_num:
	kfree(pd);

	return ERR_PTR(-ENOMEM);
}


int pib_dealloc_pd(struct ib_pd *ibpd)
{
	struct pib_dev *dev;
	struct pib_pd *pd;
	unsigned long flags;

	if (!ibpd)
		return 0;

	dev = to_pdev(ibpd->device);
	pd  = to_ppd(ibpd);

	spin_lock_irqsave(&pd->lock, flags);
	if (pd->nr_mr > 0)
		pr_err("pib: pib_dealloc_pd: nr_mr=%d\n", pd->nr_mr);
	spin_unlock_irqrestore(&pd->lock, flags);

	vfree(pd->mr_table);

	spin_lock_irqsave(&dev->lock, flags);
	dev->nr_pd--;
	pib_dealloc_obj_num(dev, PIB_BITMAP_PD_START, pd->pd_num);
	spin_unlock_irqrestore(&dev->lock, flags);

	kfree(pd);

	return 0;
}
