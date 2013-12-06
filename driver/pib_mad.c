/*
 * Copyright (c) 2013 Minoru NAKAMURA <nminoru@nminoru.jp>
 *
 * This code is licenced under the GPL version 2 or BSD license.
 */
#include <linux/module.h>
#include <linux/init.h>

#include <rdma/ib_mad.h>
#include <rdma/ib_smi.h>
#include <rdma/ib_sa.h>
#include <rdma/ib_cache.h>
#include <rdma/ib_pma.h>

#include "pib.h"


int pib_ib_process_mad(struct ib_device *ibdev, int mad_flags,	u8 port_num,
		       struct ib_wc *in_wc, struct ib_grh *in_grh,
		       struct ib_mad *in_mad, struct ib_mad *out_mad)
{
	debug_printk("pib_ib_process_mad\n");
	return 0;
}
