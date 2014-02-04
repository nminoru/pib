/*
 * Copyright (c) 2013,2014 Minoru NAKAMURA <nminoru@nminoru.jp>
 *
 * This code is licenced under the GPL version 2 or BSD license.
 */
#include <linux/module.h>
#include <linux/init.h>

#include "pib.h"
#include "pib_trace.h"


struct ib_ucontext *
pib_alloc_ucontext(struct ib_device *ibdev,
		      struct ib_udata *udata)
{
	unsigned long flags;
	struct pib_dev *dev;
	struct pib_ucontext *ucontext;
	u32 ucontext_num;

	if (!ibdev)
		return ERR_PTR(-EINVAL);

	dev = to_pdev(ibdev);

	ucontext = kzalloc(sizeof *ucontext, GFP_KERNEL);
	if (!ucontext)
		return ERR_PTR(-ENOMEM);

	pib_trace_api(dev, IB_USER_VERBS_CMD_GET_CONTEXT, 0);

	INIT_LIST_HEAD(&ucontext->list);
	getnstimeofday(&ucontext->creation_time);

	spin_lock_irqsave(&dev->lock, flags);
	ucontext_num = pib_alloc_obj_num(dev, PIB_BITMAP_CONTEXT_START, PIB_MAX_CONTEXT, &dev->last_ucontext_num);
	if (ucontext_num == (u32)-1) {
		spin_unlock_irqrestore(&dev->lock, flags);
		goto err_alloc_ucontext_num;
	}
	dev->nr_ucontext++;
	list_add_tail(&ucontext->list, &dev->ucontext_head);
	ucontext->ucontext_num = ucontext_num;
	spin_unlock_irqrestore(&dev->lock, flags);

	memcpy(ucontext->comm, current->comm, sizeof(current->comm));
	ucontext->pid	= current->pid;
	ucontext->tgid	= current->tgid;

	return &ucontext->ib_ucontext;

err_alloc_ucontext_num:
	kfree(ucontext);

	return ERR_PTR(-ENOMEM);
}


int pib_dealloc_ucontext(struct ib_ucontext *ibcontext)
{
	unsigned long flags;
	struct pib_dev *dev;
	struct pib_ucontext *ucontext;

	if (!ibcontext)
		return 0;

	dev      = to_pdev(ibcontext->device);
	ucontext = to_pucontext(ibcontext);

	pib_trace_api(dev, PIB_USER_VERBS_CMD_DEALLOC_CONTEXT, 0);

	spin_lock_irqsave(&dev->lock, flags);
	list_del(&ucontext->list);
	dev->nr_ucontext--;
	pib_dealloc_obj_num(dev, PIB_BITMAP_CONTEXT_START, ucontext->ucontext_num);
	spin_unlock_irqrestore(&dev->lock, flags);

	kfree(ucontext);

	return 0;
}
