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
#include "pib_mad.h"


static int process_subn(struct ib_device *ibdev, int mad_flags, u8 in_port_num,
			struct ib_wc *in_wc, struct ib_grh *in_grh,
			struct ib_mad *in_mad, struct ib_mad *out_mad);
static int process_subn_get_method(struct ib_smp *smp, struct pib_ib_dev *dev, u8 in_port_num);
static int process_subn_set_method(struct ib_smp *smp, struct pib_ib_dev *dev, u8 in_port_num);
static int subn_get_nodedescription(struct ib_smp *smp, struct pib_ib_dev *dev, u8 in_port_num);
static int subn_get_nodeinfo(struct ib_smp *smp, struct pib_ib_dev *dev, u8 in_port_num);
static int subn_get_guidinfo(struct ib_smp *smp, struct pib_ib_dev *dev, u8 in_port_num);
static int subn_set_guidinfo(struct ib_smp *smp, struct pib_ib_dev *dev, u8 in_port_num);
static int subn_get_portinfo(struct ib_smp *smp, struct pib_ib_dev *dev, u8 in_port_num);
static int subn_set_portinfo(struct ib_smp *smp, struct pib_ib_dev *dev, u8 in_port_num);
static int subn_get_pkey_table(struct ib_smp *smp, struct pib_ib_dev *dev, u8 in_port_num);
static int subn_set_pkey_table(struct ib_smp *smp, struct pib_ib_dev *dev, u8 in_port_num);
static int subn_get_sl_to_vl_table(struct ib_smp *smp, struct pib_ib_dev *dev, u8 in_port_num);
static int subn_set_sl_to_vl_table(struct ib_smp *smp, struct pib_ib_dev *dev, u8 in_port_num);
static int subn_get_vl_arb_table(struct ib_smp *smp, struct pib_ib_dev *dev, u8 in_port_num);
static int subn_set_vl_arb_table(struct ib_smp *smp, struct pib_ib_dev *dev, u8 in_port_num);

static int process_subn_adm(struct ib_device *ibdev, int mad_flags, u8 in_port_num,
			    struct ib_wc *in_wc, struct ib_grh *in_grh,
			    struct ib_mad *in_mad, struct ib_mad *out_mad);


static int reply(struct ib_smp *smp)
{
	smp->method = IB_MGMT_METHOD_GET_RESP;

	if (smp->mgmt_class == IB_MGMT_CLASS_SUBN_DIRECTED_ROUTE)
		smp->status |= IB_SMP_DIRECTION;

	return IB_MAD_RESULT_SUCCESS | IB_MAD_RESULT_REPLY;
}


static int reply_failure(struct ib_smp *smp)
{
	smp->method = IB_MGMT_METHOD_GET_RESP;

	if (smp->mgmt_class == IB_MGMT_CLASS_SUBN_DIRECTED_ROUTE)
		smp->status |= IB_SMP_DIRECTION;

	return IB_MAD_RESULT_FAILURE | IB_MAD_RESULT_REPLY;
}


int pib_ib_process_mad(struct ib_device *ibdev, int mad_flags,	u8 in_port_num,
		       struct ib_wc *in_wc, struct ib_grh *in_grh,
		       struct ib_mad *in_mad, struct ib_mad *out_mad)
{
	int ret;

	BUG_ON(!in_mad || !out_mad);

	ret = IB_MAD_RESULT_SUCCESS;

	*out_mad = *in_mad;

	if (in_mad->mad_hdr.method == IB_MGMT_METHOD_GET_RESP)
		goto done;

	switch (in_mad->mad_hdr.mgmt_class) {

	case IB_MGMT_CLASS_SUBN_DIRECTED_ROUTE:
		return process_subn(ibdev, mad_flags, in_port_num, in_wc, in_grh, in_mad, out_mad);

	case IB_MGMT_CLASS_SUBN_ADM:
		return process_subn_adm(ibdev, mad_flags, in_port_num, in_wc, in_grh, in_mad, out_mad);

	case IB_MGMT_CLASS_SUBN_LID_ROUTED:
	case IB_MGMT_CLASS_PERF_MGMT:
	case IB_MGMT_CLASS_BM:
	case IB_MGMT_CLASS_DEVICE_MGMT:
	case IB_MGMT_CLASS_CM:
	case IB_MGMT_CLASS_SNMP:
	case IB_MGMT_CLASS_DEVICE_ADM:
	case IB_MGMT_CLASS_BOOT_MGMT:
	case IB_MGMT_CLASS_BIS:
	case IB_MGMT_CLASS_CONG_MGMT:
	case IB_MGMT_CLASS_VENDOR_RANGE2_START:
	case IB_MGMT_CLASS_VENDOR_RANGE2_END:
	default:
		pr_err("pib: Not Implementation class: %u\n", in_mad->mad_hdr.mgmt_class);
		pib_print_mad("pib: IN", &in_mad->mad_hdr);
		pib_print_mad("pib: OUT", &out_mad->mad_hdr);
		break;
	}

done:
	return ret;
}


/******************************************************************************/
/* Subnet Management class                                                    */
/******************************************************************************/

static int process_subn(struct ib_device *ibdev, int mad_flags, u8 in_port_num,
			struct ib_wc *in_wc, struct ib_grh *in_grh,
			struct ib_mad *in_mad, struct ib_mad *out_mad)
{
	int ret;
	struct ib_smp *smp  = (struct ib_smp *)out_mad;
	struct pib_ib_dev *dev;

	/* pib_print_smp("in ", smp); */

	*out_mad = *in_mad;

	dev = to_pdev(ibdev);

#if 0
	pib_debug("pib: hca    %s %s dev-id=%u status=0x%x attr_mod=0x%x in_port_num=%u\n",
		  pib_get_mgmt_method(smp->method), pib_get_smp_attr(smp->attr_id),
		  dev->ib_dev_id,
		  smp->status, be32_to_cpu(smp->attr_mod), in_port_num);
#endif

	switch (smp->method) {
	case IB_MGMT_METHOD_GET:
		ret = process_subn_get_method(smp, dev, in_port_num);
		break;

	case IB_MGMT_METHOD_SET:
		ret = process_subn_set_method(smp, dev, in_port_num);
		if (smp->status & ~IB_SMP_DIRECTION)
			break;
		ret = process_subn_get_method(smp, dev, in_port_num);
		break;

#if 0
	case IB_MGMT_METHOD_TRAP_REPRESS:
		if (smp->attr_id == IB_SMP_ATTR_NOTICE)
			ret = subn_trap_repress(smp, dev, in_port_num);
		else {
			smp->status |= IB_SMP_UNSUP_METH_ATTR;
			ret = reply(smp);
		}
		goto bail;

	case IB_MGMT_METHOD_TRAP:
	case IB_MGMT_METHOD_REPORT:
	case IB_MGMT_METHOD_REPORT_RESP:
	case IB_MGMT_METHOD_GET_RESP:
		/*
		 * The ib_mad module will call us to process responses
		 * before checking for other consumers.
		 * Just tell the caller to process it normally.
		 */
		ret = IB_MAD_RESULT_SUCCESS;
		goto bail;

	case IB_MGMT_METHOD_SEND:
		if (ib_get_smp_direction(smp) &&
		    smp->attr_id == QIB_VENDOR_IPG) {
			ppd->dd->f_set_ib_cfg(ppd, QIB_IB_CFG_PORT,
					      smp->data[0]);
			ret = IB_MAD_RESULT_SUCCESS | IB_MAD_RESULT_CONSUMED;
		} else
			ret = IB_MAD_RESULT_SUCCESS;
		goto bail;
#endif

	default:
		pr_err("pib: *** process_subn: %u %u ***", smp->method, be16_to_cpu(smp->attr_id));
		smp->status |= IB_SMP_UNSUP_METHOD;
		ret = reply(smp);
	}

	/* pib_print_smp("out", smp); */

	smp->return_path[smp->hop_ptr + 1] = in_port_num;

	return ret;
}


static int process_subn_get_method(struct ib_smp *smp, struct pib_ib_dev *dev, u8 in_port_num)
{
	memset(smp->data, 0, sizeof(smp->data));

	switch (smp->attr_id) {

	case IB_SMP_ATTR_NODE_DESC:
		return subn_get_nodedescription(smp, dev, in_port_num);
			
	case IB_SMP_ATTR_NODE_INFO:
		return subn_get_nodeinfo(smp, dev, in_port_num);

	case IB_SMP_ATTR_GUID_INFO:
		return subn_get_guidinfo(smp, dev, in_port_num);

	case IB_SMP_ATTR_PORT_INFO:
		return subn_get_portinfo(smp, dev, in_port_num);

	case IB_SMP_ATTR_PKEY_TABLE:
		return subn_get_pkey_table(smp, dev, in_port_num);

	case IB_SMP_ATTR_SL_TO_VL_TABLE:
		return subn_get_sl_to_vl_table(smp, dev, in_port_num);

	case IB_SMP_ATTR_VL_ARB_TABLE:
		return subn_get_vl_arb_table(smp, dev, in_port_num);

	case IB_SMP_ATTR_SM_INFO:
#if 0
		if (ibdev->port_cap_flags & IB_PORT_SM_DISABLED) {
			ret = IB_MAD_RESULT_SUCCESS |
				IB_MAD_RESULT_CONSUMED;
			goto bail;
		}
		if (ibdev->port_cap_flags & IB_PORT_SM) {
			ret = IB_MAD_RESULT_SUCCESS;
			goto bail;
		}
		/* FALLTHROUGH */
#endif

	default:
		pr_err("pib: process_subn: IB_MGMT_METHOD_GET: %u", be16_to_cpu(smp->attr_id));
		smp->status |= IB_SMP_UNSUP_METH_ATTR;
		return reply(smp);
	}
}


static int process_subn_set_method(struct ib_smp *smp, struct pib_ib_dev *dev, u8 in_port_num)
{
	switch (smp->attr_id) {

	case IB_SMP_ATTR_GUID_INFO:
		return subn_set_guidinfo(smp, dev, in_port_num);

	case IB_SMP_ATTR_PORT_INFO:
		return subn_set_portinfo(smp, dev, in_port_num);

	case IB_SMP_ATTR_PKEY_TABLE:
		return subn_set_pkey_table(smp, dev, in_port_num);

	case IB_SMP_ATTR_SL_TO_VL_TABLE:
		return subn_set_sl_to_vl_table(smp, dev, in_port_num);

	case IB_SMP_ATTR_VL_ARB_TABLE:
		return subn_set_vl_arb_table(smp, dev, in_port_num);

	case IB_SMP_ATTR_SM_INFO:
#if 0
		if (ibp->port_cap_flags & IB_PORT_SM_DISABLED) {
			ret = IB_MAD_RESULT_SUCCESS |
				IB_MAD_RESULT_CONSUMED;
			goto bail;
		}
		if (ibp->port_cap_flags & IB_PORT_SM) {
			ret = IB_MAD_RESULT_SUCCESS;
			goto bail;
		}
		/* FALLTHROUGH */
#endif
	default:
		pr_err("pib: process_subn: IB_MGMT_METHOD_SET: %u", be16_to_cpu(smp->attr_id));
		smp->status |= IB_SMP_UNSUP_METH_ATTR;
		return reply(smp);
	}
}


static int subn_get_nodedescription(struct ib_smp *smp, struct pib_ib_dev *dev, u8 in_port_num)
{
	if (smp->attr_mod)
		smp->status |= IB_SMP_INVALID_FIELD;

	strncpy(smp->data, dev->ib_dev.node_desc, 64);

	return reply(smp);
}


static int subn_get_nodeinfo(struct ib_smp *smp, struct pib_ib_dev *dev, u8 in_port_num)
{
	struct pib_mad_node_info *node_info = (struct pib_mad_node_info *)&smp->data;

	/* smp->status |= IB_SMP_INVALID_FIELD; */

	node_info->base_version		= IB_MGMT_BASE_VERSION;
	node_info->class_version	= IB_MGMT_CLASS_VERSION;
	node_info->node_type		= RDMA_NODE_IB_CA;
	node_info->node_ports		= dev->ib_dev.phys_port_cnt;
	node_info->sys_image_guid	= dev->ib_dev_attr.sys_image_guid;
	node_info->node_guid		= dev->ib_dev.node_guid;
	node_info->port_guid		= dev->ports[in_port_num - 1].gid[0].global.interface_id;
	node_info->partition_cap	= cpu_to_be16(1); /* @todo */
	node_info->device_id		= cpu_to_be16(PIB_DRIVER_DEVICE_ID);
	node_info->revision		= cpu_to_be32(PIB_DRIVER_REVISION);
	node_info->local_port_num	= in_port_num;
	node_info->vendor_id[0]		= 0; /* OUI */
	node_info->vendor_id[1]		= 0; /* OUI */
	node_info->vendor_id[2]		= 0; /* OUI */

	return reply(smp);
}


static int subn_get_guidinfo(struct ib_smp *smp, struct pib_ib_dev *dev, u8 in_port_num)
{
	pr_err("pib: *** %s ***", __FUNCTION__);

	return reply_failure(smp);
}


static int subn_set_guidinfo(struct ib_smp *smp, struct pib_ib_dev *dev, u8 in_port_num)
{
	pr_err("pib: *** %s ***", __FUNCTION__);

	return reply_failure(smp);
}


static int subn_get_portinfo(struct ib_smp *smp, struct pib_ib_dev *dev, u8 in_port_num)
{
	struct ib_port_info *port_info = (struct ib_port_info *)&smp->data;
	u32 port_num = be32_to_cpu(smp->attr_mod);
	struct pib_ib_port *port;

	if (port_num == 0)
		port_num = in_port_num;

	if ((port_num < 1) || (dev->ib_dev.phys_port_cnt < port_num)) {
		smp->status |= IB_SMP_INVALID_FIELD;
		goto bail;
	}

	port = &dev->ports[port_num - 1];

	port_info->local_port_num = port_num;

	pib_subn_get_portinfo(smp, port, port_num, PIB_PORT_CA);

bail:
	return reply(smp);
}


void pib_subn_get_portinfo(struct ib_smp *smp, struct pib_ib_port *port, u8 port_num, enum pib_port_type type)
{
	struct ib_port_info *port_info = (struct ib_port_info *)&smp->data;

	/*
	 * m-key check
	 * 失敗したら IB_MAD_RESULT_FAILURE を
	 */

#if 0
	pib_debug("pib: pib_subn_get_portinfo: type=%u, port_num=%u, tid=%llx, lid=%u, state=%u phy_state=%u\n",
		  type, port_num, (unsigned long long)cpu_to_be16(smp->tid), port->ib_port_attr.lid,
		  port->ib_port_attr.state, port->ib_port_attr.phys_state);
#endif

	if (type != PIB_PORT_SW_EXT) {
		port_info->mkey		= port->mkey;
		port_info->lid		= cpu_to_be16(port->ib_port_attr.lid);
		port_info->sm_lid	= cpu_to_be16(port->ib_port_attr.sm_lid);
		port_info->gid_prefix	= port->gid[0].global.subnet_prefix;
		port_info->cap_mask	= cpu_to_be32(port->ib_port_attr.port_cap_flags);
#if 0
		port_info->diag_code;
#endif
		port_info->mkey_lease_period = cpu_to_be16(port->mkey_lease_period);
	}

	if (type != PIB_PORT_BASE_SP0) { 
		port_info->link_width_enabled	= port->link_width_enabled;
		port_info->link_width_supported	= (IB_WIDTH_1X | IB_WIDTH_4X | IB_WIDTH_8X | IB_WIDTH_12X);
		port_info->link_width_active	= port->ib_port_attr.active_width;
	
		/* 4 bits, 4 bits */
		port_info->linkspeed_portstate	=
			(port->ib_port_attr.active_speed << 4) | port->ib_port_attr.state;

		/* 4 bits, 4 bits */
		port_info->portphysstate_linkdown =
			(port->ib_port_attr.phys_state   << 4) | port->link_down_default_state;
	}

	if (type != PIB_PORT_SW_EXT) {
		/* 2 bits, 3, 3 */
		port_info->mkeyprot_resv_lmc =
			(port->mkeyprot << 6) | port->ib_port_attr.lmc;
	}

	if (type != PIB_PORT_BASE_SP0) { 
		/* 4 bits, 4 bits */
		port_info->linkspeedactive_enabled = port->link_speed_enabled;

		/* 4 bits, 4 bits */
		port_info->neighbormtu_mastersmsl |=
			(port->ib_port_attr.active_mtu << 4);
	}

	if (type != PIB_PORT_SW_EXT) {
		port_info->neighbormtu_mastersmsl |= port->master_smsl;
	}

	if (type != PIB_PORT_BASE_SP0) { 
		port_info->vlcap_inittype |= (0x5 << 4);
	}

	if (type != PIB_PORT_SW_EXT) {
		port_info->vlcap_inittype |= 0x0;
	}

#if 0
	port_info->vl_high_limit;
	port_info->vl_arb_high_cap;
	port_info->vl_arb_low_cap;
#endif

	if (type != PIB_PORT_SW_EXT)
		port_info->inittypereply_mtucap |= (0 << 4); /* @todo InitTypeReply */

	if (type != PIB_PORT_BASE_SP0)
		port_info->inittypereply_mtucap |= IB_MTU_4096;

#if 0
	/* 3 bits, 5 bits */
	port_info->vlstallcnt_hoqlife;
	/* 4 bits, 1, 1, 1, 1 */
	prot_info->operationalvl_pei_peo_fpi_fpo;
	port_info->mkey_violations = cpu_to_be16(0);
	port_info->pkey_violations = cpu_to_be16(0);
	port_info->qkey_violations = cpu_to_be16(0);
	port_info->guid_cap;
#endif

	if (type != PIB_PORT_SW_EXT) {
		/* 1 bit, 2 bits, 5 */
		port_info->clientrereg_resv_subnetto =
			(port->client_reregister << 7) | port->subnet_timeout;
#if 0
		/* 3 bits, 5 bits */
		port_info->resv_resptimevalue;
#endif
	}

	if (type != PIB_PORT_BASE_SP0) { 
		/* 4 bits, 4 bits */
		port_info->localphyerrors_overrunerrors =
			(port->local_phy_errors << 4) | port->overrun_errors;
	}

#if 0
	port_info->max_credit_hint = cpu_to_be16(0);

	port_info->link_roundtrip_latency[0];
	port_info->link_roundtrip_latency[1];
	port_info->link_roundtrip_latency[2];
#endif

}


static int subn_set_portinfo(struct ib_smp *smp, struct pib_ib_dev *dev, u8 in_port_num)
{
	int port_index;
	struct ib_port_info *port_info = (struct ib_port_info *)&smp->data;
	u32 port_num = be32_to_cpu(smp->attr_mod);
	struct pib_ib_port *port;
	struct ib_event event;
	u16 old_lid, new_lid;
	u16 old_sm_lid, new_sm_lid;
	enum ib_port_state old_state;

	if (port_num == 0)
		port_num = in_port_num;

	if ((port_num < 1) || (dev->ib_dev.phys_port_cnt < port_num)) {
		smp->status |= IB_SMP_INVALID_FIELD;
		goto bail;
	}

	port_index = port_num - 1;

	port = &dev->ports[port_index];

	old_lid    = port->ib_port_attr.lid;
	new_lid    = be16_to_cpu(port_info->lid);
	old_sm_lid = port->ib_port_attr.sm_lid;
	new_sm_lid = be16_to_cpu(port_info->sm_lid);

#ifdef PIB_USE_EASY_SWITCH
	if (old_lid != new_lid) {
		/* @todo need lock */
		if (old_lid != 0)
			dev->ports[port_index].lid_table[old_lid] = NULL;
		if (new_lid != 0)
			dev->ports[port_index].lid_table[new_lid] = 
				dev->ports[port_num - 1].sockaddr;
	}
#endif

	old_state = port->ib_port_attr.state;
	
	pib_subn_set_portinfo(smp, port, port_num, PIB_PORT_CA);

	event.device           = &dev->ib_dev;
	event.element.port_num = port_num;

	if ((port->ib_port_attr.state != IB_PORT_ACTIVE) && (old_state == IB_PORT_ACTIVE)) {
		event.event = IB_EVENT_PORT_ERR;
		ib_dispatch_event(&event);
	}

	if ((port->ib_port_attr.state == IB_PORT_ACTIVE) && (old_state != IB_PORT_ACTIVE)) {
		event.event = IB_EVENT_PORT_ACTIVE;
		ib_dispatch_event(&event);
	}

	if (old_sm_lid != new_sm_lid) {
		event.event = IB_EVENT_SM_CHANGE;
		ib_dispatch_event(&event);
	}

	if (old_lid != new_lid) {
		event.event = IB_EVENT_LID_CHANGE;
		ib_dispatch_event(&event);
	}

	if (port->ib_port_attr.state < IB_PORT_INIT)
		port->ib_port_attr.state = IB_PORT_INIT;

#if 0
	pr_debug("pib: ib_dev(set_portinfo) in_port_num=%u, port_num=%u, lid=%u, state=%u, phys_state=%u\n",
		 in_port_num, port_num,
		 port->ib_port_attr.lid,
		 port->ib_port_attr.state,
		 port->ib_port_attr.phys_state);
#endif

bail:
	return reply(smp);
}


void pib_subn_set_portinfo(struct ib_smp *smp, struct pib_ib_port *port, u8 port_num, enum pib_port_type type)
{
	struct ib_port_info *port_info = (struct ib_port_info *)&smp->data;

	/*
	 *  lid と sm_lid は 1以上、PIB_MCAST_LID_BASE 未満のこと
	 */

	/*
	 * m-key check
	 * 失敗したら IB_MAD_RESULT_FAILURE を
	 */
	if (type != PIB_PORT_SW_EXT) {
		port->mkey			= port_info->mkey;
		port->ib_port_attr.lid		= be16_to_cpu(port_info->lid);
		port->ib_port_attr.sm_lid	= be16_to_cpu(port_info->sm_lid);
		port->gid[0].global.subnet_prefix = port_info->gid_prefix;
		port->mkey_lease_period		= be16_to_cpu(port_info->mkey_lease_period);
	}

	if (type != PIB_PORT_BASE_SP0) { 
		if (port_info->link_width_enabled)
			port->link_width_enabled = port_info->link_width_enabled;

		if (port_info->linkspeed_portstate & 0xF)
			port->ib_port_attr.state  = port_info->linkspeed_portstate & 0xF;

		if (port_info->portphysstate_linkdown >> 4)
			port->ib_port_attr.phys_state = (port_info->portphysstate_linkdown >> 4);

		if (port_info->portphysstate_linkdown & 0xF)
			port->link_down_default_state = (port_info->portphysstate_linkdown & 0xF);
	}

	if (type != PIB_PORT_SW_EXT) {
		port->mkeyprot		= (port_info->mkeyprot_resv_lmc >> 6) & 0x3;
		port->ib_port_attr.lmc	= port_info->mkeyprot_resv_lmc & 0x7;
	}

	if (type != PIB_PORT_BASE_SP0) { 
		if (port_info->linkspeedactive_enabled & 0xF)
			port->link_speed_enabled = (port_info->linkspeedactive_enabled & 0xF);

		port->ib_port_attr.active_mtu	= (port_info->neighbormtu_mastersmsl >> 4);
	}

	if (type != PIB_PORT_SW_EXT) {
		port->master_smsl		= (port_info->neighbormtu_mastersmsl & 0xF);
	}

#if 0
	port_info->vl_high_limit;
	port_info->vl_arb_high_cap;
	port_info->vl_arb_low_cap;

	port_info->inittypereply_mtucap = IB_MTU_4096;

	/* 3 bits, 5 bits */
	port_info->vlstallcnt_hoqlife;
	/* 4 bits, 1, 1, 1, 1 */
	prot_info->operationalvl_pei_peo_fpi_fpo;
	port_info->mkey_violations = cpu_to_be16(0);
	port_info->pkey_violations = cpu_to_be16(0);
	port_info->qkey_violations = cpu_to_be16(0);
	port_info->guid_cap;
#endif

	if (type != PIB_PORT_SW_EXT) {
		/* 1 bit, 2 bits, 5 */
		port->client_reregister    = (port_info->clientrereg_resv_subnetto >> 7) & 0x1;
		port->subnet_timeout	   = (port_info->clientrereg_resv_subnetto ) & 0x1F;
	}

	if (type != PIB_PORT_BASE_SP0) { 
		/* 4 bits, 4 bits */
		port->local_phy_errors     = (port_info->localphyerrors_overrunerrors >> 4) & 0xF;
		port->overrun_errors       = port_info->localphyerrors_overrunerrors & 0xF;
	}

#if 0
	pib_debug("pib: pib_subn_set_portinfo: type=%u, port_num=%u, tid=%llx, lid=%u, state=%u phy_state=%u\n",
		  type, port_num, (unsigned long long)cpu_to_be16(smp->tid), port->ib_port_attr.lid,
		  port->ib_port_attr.state, port->ib_port_attr.phys_state);
#endif
}


static int subn_get_pkey_table(struct ib_smp *smp, struct pib_ib_dev *dev, u8 in_port_num)
{
	int i;
	u32 attr_mod, block_index, sw_port_index;
	__be16 *pkey_table = (__be16 *)&smp->data[0];

	attr_mod      = be32_to_cpu(smp->attr_mod);

	block_index   = attr_mod         & 0xFFFF;
	sw_port_index = (attr_mod >> 16) & 0xFFFF;

	if (block_index != 0) {
		pr_err("pib: *** %s: block_index = %u ***", __FUNCTION__, block_index);
		smp->status |= IB_SMP_INVALID_FIELD;
		goto bail;
	}

	for (i=0; i<PIB_PKEY_PER_BLOCK; i++)
		pkey_table[i] = cpu_to_be16(dev->ports[in_port_num - 1].pkey_table[i]);

bail:
	return reply(smp);
}


static int subn_set_pkey_table(struct ib_smp *smp, struct pib_ib_dev *dev, u8 in_port_num)
{
	int i;
	int changed = 0;
	u32 attr_mod, block_index, sw_port_index;
	__be16 *pkey_table = (__be16 *)&smp->data[0];

	attr_mod      = be32_to_cpu(smp->attr_mod);

	block_index   = attr_mod         & 0xFFFF;
	sw_port_index = (attr_mod >> 16) & 0xFFFF;

	if (block_index != 0) {
		pr_err("pib: *** %s: block_index = %u ***", __FUNCTION__, block_index);
		smp->status |= IB_SMP_INVALID_FIELD;
		goto bail;
	}

	for (i=0; i<PIB_PKEY_PER_BLOCK; i++) {
		u16 key  = be16_to_cpu(pkey_table[i]);
		u16 okey = dev->ports[in_port_num - 1].pkey_table[i];

		if (key == okey)
			continue;

		if (okey & 0x7FFF)
			changed = 1;

		if (key & 0x7FFF)
			changed = 1;

		dev->ports[in_port_num - 1].pkey_table[i] = key;
	}

	if (changed) {
		struct ib_event event;
		event.device           = &dev->ib_dev;
		event.event            = IB_EVENT_PKEY_CHANGE;
		event.element.port_num = in_port_num;
		ib_dispatch_event(&event);
	}

bail:
	return reply(smp);
}


static int subn_get_sl_to_vl_table(struct ib_smp *smp, struct pib_ib_dev *dev, u8 in_port_num)
{
	pr_err("pib: *** %s ***", __FUNCTION__);

	return reply_failure(smp);
}


static int subn_set_sl_to_vl_table(struct ib_smp *smp, struct pib_ib_dev *dev, u8 in_port_num)
{
	pr_err("pib: *** %s ***", __FUNCTION__);

	return reply_failure(smp);
}


static int subn_get_vl_arb_table(struct ib_smp *smp, struct pib_ib_dev *dev, u8 in_port_num)
{
	pr_err("pib: *** %s ***", __FUNCTION__);

	return reply_failure(smp);
}


static int subn_set_vl_arb_table(struct ib_smp *smp, struct pib_ib_dev *dev, u8 in_port_num)
{
	pr_err("pib: *** %s ***", __FUNCTION__);

	return reply_failure(smp);
}


/******************************************************************************/
/* Subnet Administration class                                                */
/******************************************************************************/

static int process_subn_adm(struct ib_device *ibdev, int mad_flags, u8 in_port_num,
			    struct ib_wc *in_wc, struct ib_grh *in_grh,
			    struct ib_mad *in_mad, struct ib_mad *out_mad)
{
	struct pib_ib_dev *dev;
	struct ib_sa_mad *sa_mad;

	*out_mad = *in_mad;
	
	sa_mad = (struct ib_sa_mad*)out_mad;

	dev = to_pdev(ibdev);

	pib_debug("pib: process SubnAdm dev-id=%u in_port_num=%u\n", dev->ib_dev_id, in_port_num);
	pib_print_sa_mad("pib: IN", sa_mad);

	switch (be16_to_cpu(sa_mad->mad_hdr.attr_id)) {

	case IB_SA_ATTR_CLASS_PORTINFO:
	case IB_SA_ATTR_NOTICE:
	case IB_SA_ATTR_INFORM_INFO:
	case IB_SA_ATTR_NODE_REC:
	case IB_SA_ATTR_PORT_INFO_REC:
	case IB_SA_ATTR_SL2VL_REC:
	case IB_SA_ATTR_SWITCH_REC:
	case IB_SA_ATTR_LINEAR_FDB_REC:
	case IB_SA_ATTR_RANDOM_FDB_REC:
	case IB_SA_ATTR_MCAST_FDB_REC:
	case IB_SA_ATTR_SM_INFO_REC:
	case IB_SA_ATTR_LINK_REC:
	case IB_SA_ATTR_GUID_INFO_REC:
	case IB_SA_ATTR_SERVICE_REC:
	case IB_SA_ATTR_PARTITION_REC:
	case IB_SA_ATTR_PATH_REC:
	case IB_SA_ATTR_VL_ARB_REC:
	case IB_SA_ATTR_MC_MEMBER_REC:
	case IB_SA_ATTR_TRACE_REC:
	case IB_SA_ATTR_MULTI_PATH_REC:
	case IB_SA_ATTR_SERVICE_ASSOC_REC:
	case IB_SA_ATTR_INFORM_INFO_REC:
	default:
		break;
	}
	
	return 0;
}
