/*
 * Copyright (c) 2013,2014 Minoru NAKAMURA <nminoru@nminoru.jp>
 *
 * This code is licenced under the GPL version 2 or BSD license.
 */
#include <linux/module.h>
#include <linux/init.h>

#include "pib.h"


struct ib_ucontext *
pib_alloc_ucontext(struct ib_device *ibdev,
		      struct ib_udata *udata)
{
	struct pib_dev *dev;
	struct pib_ucontext *ucontext;
	u32 ucontext_num;

	if (!ibdev)
		return ERR_PTR(-EINVAL);

	dev = to_pdev(ibdev);

	ucontext = kzalloc(sizeof *ucontext, GFP_KERNEL);
	if (!ucontext)
		return ERR_PTR(-ENOMEM);

	ucontext_num = pib_find_zero_bit(dev, PIB_BITMAP_CONTEXT_START, PIB_MAX_CONTEXT, &dev->last_ucontext_num);
	if (ucontext_num == (u32)-1)
		goto err_alloc_ucontext_num;

	ucontext->ucontext_num = ucontext_num;
	
	return &ucontext->ib_ucontext;

err_alloc_ucontext_num:
	kfree(ucontext);

	return ERR_PTR(-ENOMEM);
}


int pib_dealloc_ucontext(struct ib_ucontext *ibcontext)
{
	struct pib_dev *dev;
	struct pib_ucontext *ucontext;

	if (!ibcontext)
		return 0;

	dev      = to_pdev(ibcontext->device);
	ucontext = to_pucontext(ibcontext);

	pib_clear_bit(dev, PIB_BITMAP_CONTEXT_START, ucontext->ucontext_num);

	kfree(ucontext);

	return 0;
}
