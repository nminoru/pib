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


static void print_mad(const char *direct, struct ib_mad_hdr *hdr)
{
	debug_printk("%s: base_version   %u\n",   direct, hdr->base_version);
	debug_printk("%s: mgmt_class     %u\n",   direct, hdr->mgmt_class);
	debug_printk("%s: class_version  %u\n",   direct, hdr->class_version);
	debug_printk("%s: method         %u\n",   direct, hdr->method);
	debug_printk("%s: status         %u\n",   direct, be16_to_cpu(hdr->status));
	debug_printk("%s: class_specific %u\n",   direct, be16_to_cpu(hdr->class_specific));
	debug_printk("%s: tid            %llu\n", direct, be64_to_cpu(hdr->tid));
	debug_printk("%s: attr_id        %u\n",   direct, be16_to_cpu(hdr->attr_id));
	debug_printk("%s: resv           %u\n",   direct, be16_to_cpu(hdr->resv));
	debug_printk("%s: attr_mod       %u\n",   direct, be32_to_cpu(hdr->attr_mod));
}


int pib_ib_process_mad(struct ib_device *ibdev, int mad_flags,	u8 port_num,
		       struct ib_wc *in_wc, struct ib_grh *in_grh,
		       struct ib_mad *in_mad, struct ib_mad *out_mad)
{
	debug_printk("pib_ib_process_mad: mad_flags=%x, port_num=%u\n", mad_flags, port_num);

	if (in_mad)
		print_mad("IN", &in_mad->mad_hdr);

	if (out_mad)
		print_mad("OUT", &out_mad->mad_hdr);

	return 0;
}


int pib_process_smi_qp_request(struct pib_ib_dev *dev, struct pib_ib_qp *qp, struct pib_ib_send_wqe *send_wqe)
{
	debug_printk("pib_process_smi_qp_request\n");

	list_del_init(&send_wqe->list);
	qp->requester.nr_sending_swqe--;
	send_wqe->processing.list_type = PIB_SWQE_FREE;

	return 0;
}


int pib_process_gsi_qp_request(struct pib_ib_dev *dev, struct pib_ib_qp *qp, struct pib_ib_send_wqe *send_wqe)
{
	debug_printk("pib_process_gsi_qp_request\n");

	list_del_init(&send_wqe->list);
	qp->requester.nr_sending_swqe--;
	send_wqe->processing.list_type = PIB_SWQE_FREE;

	return 0;
}
