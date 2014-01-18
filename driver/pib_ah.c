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
	struct pib_ah *ah;

	if (!ah_attr)
		return ERR_PTR(-EINVAL);

	ah = kmem_cache_zalloc(pib_ah_cachep, GFP_KERNEL);
	if (!ah)
		return ERR_PTR(-ENOMEM);
	
	ah->ib_ah_attr = *ah_attr;
	
	return &ah->ib_ah;
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
	if (!ibah)
		return 0;

	kmem_cache_free(pib_ah_cachep, to_pah(ibah));

	return 0;
}

