/*
 * Copyright (c) 2013 Minoru NAKAMURA <nminoru@nminoru.jp>
 *
 * This code is licenced under the GPL version 2 or BSD license.
 */
#include <linux/module.h>
#include <linux/init.h>

#include "pib.h"


struct ib_pd *
pib_ib_alloc_pd(struct ib_device *ibdev,
		struct ib_ucontext *ibucontext,
		struct ib_udata *udata)
{
	struct pib_ib_pd *pd;

	if (!ibdev)
		return ERR_PTR(-EINVAL);

	pd = kzalloc(sizeof *pd, GFP_KERNEL);
	if (!pd)
		return ERR_PTR(-ENOMEM);

	spin_lock_init(&pd->lock);

	pd->mr_table = vzalloc(sizeof(struct pib_ib_mr*) * PIB_IB_MAX_MR_PER_PD);
	if (!pd->mr_table)
		goto err_mr_table;

	return &pd->ib_pd;

err_mr_table:
	kfree(pd);

	return ERR_PTR(-ENOMEM);
}


int pib_ib_dealloc_pd(struct ib_pd *ibpd)
{
	struct pib_ib_pd *pd;
	unsigned long flags;

	if (!ibpd)
		return 0;

	pd = to_ppd(ibpd);

	spin_lock_irqsave(&pd->lock, flags);
	if (pd->nr_mr > 0)
		pr_err("pib: pib_ib_dealloc_pd: nr_mr=%d\n", pd->nr_mr);
	spin_unlock_irqrestore(&pd->lock, flags);

	vfree(pd->mr_table);

	kfree(pd);

	return 0;
}
