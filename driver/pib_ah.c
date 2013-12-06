/*
 * Copyright (c) 2013 Minoru NAKAMURA <nminoru@nminoru.jp>
 *
 * This code is licenced under the GPL version 2 or BSD license.
 */
#include <linux/module.h>
#include <linux/init.h>

#include "pib.h"


struct ib_ah *
pib_ib_create_ah(struct ib_pd *ibpd, struct ib_ah_attr *ah_attr)
{
	struct pib_ib_ah *ah;

	if (!ah_attr)
		return ERR_PTR(-EINVAL);

	ah = kmem_cache_zalloc(pib_ib_ah_cachep, GFP_KERNEL);
	if (!ah)
		return ERR_PTR(-ENOMEM);
	
	ah->ib_ah_attr = *ah_attr;
	
	return &ah->ib_ah;
}


int pib_ib_destroy_ah(struct ib_ah *ibah)
{
	if (!ibah)
		return 0;

	kmem_cache_free(pib_ib_ah_cachep, to_pah(ibah));

	return 0;
}

