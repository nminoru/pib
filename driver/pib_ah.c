/*
 * Copyright (c) 2013,2014 Minoru NAKAMURA <nminoru@nminoru.jp>
 *
 * This code is licenced under the GPL version 2 or BSD license.
 */
#include <linux/module.h>
#include <linux/init.h>

#include "pib.h"


struct ib_ah *
pib_create_ah(struct ib_pd *ibpd, struct ib_ah_attr *ah_attr)
{
	struct pib_dev *dev;
	struct pib_ah *ah;
	unsigned long flags;
	u32 ah_num;

	if (!ah_attr)
		return ERR_PTR(-EINVAL);

	dev = to_pdev(ibpd->device);

	ah = kmem_cache_zalloc(pib_ah_cachep, GFP_KERNEL);
	if (!ah)
		return ERR_PTR(-ENOMEM);

	INIT_LIST_HEAD(&ah->list);
	getnstimeofday(&ah->creation_time);

	spin_lock_irqsave(&dev->lock, flags);
	ah_num = pib_alloc_obj_num(dev, PIB_BITMAP_AH_START, PIB_MAX_AH, &dev->last_ah_num);
	if (ah_num == (u32)-1) {
		spin_unlock_irqrestore(&dev->lock, flags);
		goto err_alloc_ah_num;
	}
	dev->nr_ah++;
	list_add_tail(&ah->list, &dev->ah_head);
	ah->ah_num = ah_num;
	spin_unlock_irqrestore(&dev->lock, flags);

	ah->ib_ah_attr = *ah_attr;
	
	return &ah->ib_ah;

err_alloc_ah_num:
	kmem_cache_free(pib_ah_cachep, ah);

	return ERR_PTR(-ENOMEM);	
}


int pib_modify_ah(struct ib_ah *ibah, struct ib_ah_attr *ah_attr)
{
	struct pib_ah *ah;

	if (!ibah || !ah_attr)
		return -EINVAL;

	ah = to_pah(ibah);

	ah->ib_ah_attr = *ah_attr;

	return 0;
}


int pib_query_ah(struct ib_ah *ibah, struct ib_ah_attr *ah_attr)
{
	struct pib_ah *ah;

	if (!ibah || !ah_attr)
		return -EINVAL;

	ah = to_pah(ibah);
	
	*ah_attr = ah->ib_ah_attr;

	return 0;
}


int pib_destroy_ah(struct ib_ah *ibah)
{
	struct pib_dev *dev;
	struct pib_ah *ah;
	unsigned long flags;

	if (!ibah)
		return 0;

	dev = to_pdev(ibah->device);
	ah  = to_pah(ibah);

	spin_lock_irqsave(&dev->lock, flags);
	list_del(&ah->list);
	dev->nr_ah--;
	pib_dealloc_obj_num(dev, PIB_BITMAP_AH_START, ah->ah_num);
	spin_unlock_irqrestore(&dev->lock, flags);

	kmem_cache_free(pib_ah_cachep, ah);

	return 0;
}

