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
	struct pib_ucontext *ucontext;

	ucontext = kzalloc(sizeof *ucontext, GFP_KERNEL);
	if (!ucontext)
		return ERR_PTR(-ENOMEM);

	return &ucontext->ib_ucontext;
}


int pib_dealloc_ucontext(struct ib_ucontext *ibcontext)
{
	struct pib_ucontext *ucontext = to_pucontext(ibcontext);

	kfree(ucontext);

	return 0;
}
