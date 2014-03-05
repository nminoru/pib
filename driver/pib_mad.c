/*
 * pib_mad.c - Management Datagram(MAD) Processing and Subnet Management Agent
 *
 * Copyright (c) 2013,2014 Minoru NAKAMURA <nminoru@nminoru.jp>
 *
 * This code is licenced under the GPL version 2 or BSD license.
 */
#include <linux/module.h>
#include <linux/init.h>
#include <rdma/ib_mad.h>
#include <rdma/ib_smi.h>

#include "pib.h"
#include "pib_mad.h"


static int process_subn(struct pib_dev *dev, int mad_flags, u8 in_port_num,
			struct ib_wc *in_wc, struct ib_grh *in_grh,
			struct ib_mad *in_mad, struct ib_mad *out_mad);
static int process_subn_get_method(struct ib_smp *smp, struct pib_dev *dev, u8 in_port_num);
static int process_subn_set_method(struct ib_smp *smp, struct pib_dev *dev, u8 in_port_num);
static int subn_get_nodedescription(struct ib_smp *smp, struct pib_dev *dev, u8 in_port_num);
static int subn_get_nodeinfo(struct ib_smp *smp, struct pib_dev *dev, u8 in_port_num);
static int subn_get_guidinfo(struct ib_smp *smp, struct pib_dev *dev, u8 in_port_num);
static int subn_set_guidinfo(struct ib_smp *smp, struct pib_dev *dev, u8 in_port_num);
static int subn_get_portinfo(struct ib_smp *smp, struct pib_dev *dev, u8 in_port_num);
static int subn_set_portinfo(struct ib_smp *smp, struct pib_dev *dev, u8 in_port_num);
static int subn_get_pkey_table(struct ib_smp *smp, struct pib_dev *dev, u8 in_port_num);
static int subn_set_pkey_table(struct ib_smp *smp, struct pib_dev *dev, u8 in_port_num);
static int subn_get_sl_to_vl_table(struct ib_smp *smp, struct pib_dev *dev, u8 in_port_num);
static int subn_set_sl_to_vl_table(struct ib_smp *smp, struct pib_dev *dev, u8 in_port_num);
static int subn_get_vl_arb_table(struct ib_smp *smp, struct pib_dev *dev, u8 in_port_num);
static int subn_set_vl_arb_table(struct ib_smp *smp, struct pib_dev *dev, u8 in_port_num);


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


int pib_process_mad(struct ib_device *ibdev, int mad_flags, u8 in_port_num,
		    struct ib_wc *in_wc, struct ib_grh *in_grh,
		    struct ib_mad *in_mad, struct ib_mad *out_mad)
{
	struct pib_dev *dev;

	BUG_ON(!in_mad || !out_mad);

	dev = to_pdev(ibdev);

	if (in_mad->mad_hdr.method == IB_MGMT_METHOD_GET_RESP)
		return IB_MAD_RESULT_SUCCESS;

	switch (in_mad->mad_hdr.mgmt_class) {

	case IB_MGMT_CLASS_SUBN_DIRECTED_ROUTE:
	case IB_MGMT_CLASS_SUBN_LID_ROUTED:
		return process_subn(dev, mad_flags, in_port_num, in_wc, in_grh, in_mad, out_mad);

	case IB_MGMT_CLASS_PERF_MGMT: {
		struct pib_node node = {
			.port_count = dev->ib_dev.phys_port_cnt + 1, /* 1 個余分に数える */
			.port_start = 1,
			.ports      = dev->ports,
		};

		return pib_process_pma_mad(&node, in_port_num, in_mad, out_mad);
	}

	default:
		return IB_MAD_RESULT_SUCCESS;
	}
}


/******************************************************************************/
/* Subnet Management class                                                    */
/******************************************************************************/

static int process_subn(struct pib_dev *dev, int mad_flags, u8 in_port_num,
			struct ib_wc *in_wc, struct ib_grh *in_grh,
			struct ib_mad *in_mad, struct ib_mad *out_mad)
{
	int ret;
	struct ib_smp *smp;

	*out_mad = *in_mad;

	smp  = (struct ib_smp *)out_mad;

	/* @todo class version のチェックも */
	if (in_mad->mad_hdr.base_version != IB_MGMT_BASE_VERSION) {
		out_mad->mad_hdr.status = IB_MGMT_MAD_STATUS_BAD_VERSION;
		return IB_MAD_RESULT_FAILURE | IB_MAD_RESULT_REPLY;
	}

#if 0
	pib_print_smp("IN ", smp);
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
#endif

	case IB_MGMT_METHOD_TRAP:
	case IB_MGMT_METHOD_REPORT:
	case IB_MGMT_METHOD_REPORT_RESP:
	case IB_MGMT_METHOD_GET_RESP:
		if (in_mad->mad_hdr.mgmt_class == IB_MGMT_CLASS_SUBN_LID_ROUTED) {
			ret = IB_MAD_RESULT_SUCCESS;
			break;
		}
		/* pass through */

#if 0
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
		smp->status |= PIB_SMP_UNSUP_METHOD;
		ret = reply(smp);
	}

	/* pib_print_smp("out", smp); */

	smp->return_path[smp->hop_ptr + 1] = in_port_num;

	return ret;
}


static int process_subn_get_method(struct ib_smp *smp, struct pib_dev *dev, u8 in_port_num)
{
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

	case IB_SMP_ATTR_SM_INFO: {
		u32 port_cap_flags;
		
		port_cap_flags = dev->ports[in_port_num - 1].ib_port_attr.port_cap_flags;

		if (port_cap_flags & IB_PORT_SM_DISABLED)
			return IB_MAD_RESULT_SUCCESS | IB_MAD_RESULT_CONSUMED;

		if (port_cap_flags & IB_PORT_SM)
			return IB_MAD_RESULT_SUCCESS;

		pr_err("pib: process_subn: GET SMInfo on no SM port\n");
		smp->status |= PIB_SMP_UNSUP_METH_ATTR;
		return reply(smp);
	}

	default:
		pr_err("pib: process_subn: IB_MGMT_METHOD_GET: %u", be16_to_cpu(smp->attr_id));
		smp->status |= PIB_SMP_UNSUP_METH_ATTR;
		return reply(smp);
	}
}


static int process_subn_set_method(struct ib_smp *smp, struct pib_dev *dev, u8 in_port_num)
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

	case IB_SMP_ATTR_SM_INFO: {
		u32 port_cap_flags;
		
		port_cap_flags = dev->ports[in_port_num - 1].ib_port_attr.port_cap_flags;

		if (port_cap_flags & IB_PORT_SM_DISABLED)
			return IB_MAD_RESULT_SUCCESS | IB_MAD_RESULT_CONSUMED;

		if (port_cap_flags & IB_PORT_SM)
			return IB_MAD_RESULT_SUCCESS;

		pr_err("pib: process_subn: SET SMInfo on no SM port\n");
		smp->status |= PIB_SMP_UNSUP_METH_ATTR;
		return reply(smp);
	}

	default:
		pr_err("pib: process_subn: IB_MGMT_METHOD_SET: %u", be16_to_cpu(smp->attr_id));
		smp->status |= PIB_SMP_UNSUP_METH_ATTR;
		return reply(smp);
	}
}


static int subn_get_nodedescription(struct ib_smp *smp, struct pib_dev *dev, u8 in_port_num)
{
	unsigned long flags;

	if (smp->attr_mod)
		smp->status |= PIB_SMP_INVALID_FIELD;

 	spin_lock_irqsave(&dev->lock, flags);
	memset(smp->data, 0, sizeof(smp->data));
	strncpy(smp->data, dev->ib_dev.node_desc, 64);
	spin_unlock_irqrestore(&dev->lock, flags);

	return reply(smp);
}


static int subn_get_nodeinfo(struct ib_smp *smp, struct pib_dev *dev, u8 in_port_num)
{
	unsigned long flags;
	struct pib_smp_node_info *node_info = (struct pib_smp_node_info *)&smp->data;

	/* smp->status |= IB_SMP_INVALID_FIELD; */

	memset(smp->data, 0, sizeof(smp->data));

 	spin_lock_irqsave(&dev->lock, flags);
	node_info->base_version		= IB_MGMT_BASE_VERSION;
	node_info->class_version	= PIB_MGMT_CLASS_VERSION;
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
	spin_unlock_irqrestore(&dev->lock, flags);

	return reply(smp);
}


static int subn_get_guidinfo(struct ib_smp *smp, struct pib_dev *dev, u8 in_port_num)
{
	pr_err("pib: *** %s ***", __FUNCTION__);

	memset(smp->data, 0, sizeof(smp->data));

	return reply_failure(smp);
}


static int subn_set_guidinfo(struct ib_smp *smp, struct pib_dev *dev, u8 in_port_num)
{
	pr_err("pib: *** %s ***", __FUNCTION__);

	return reply_failure(smp);
}


static int subn_get_portinfo(struct ib_smp *smp, struct pib_dev *dev, u8 in_port_num)
{
	unsigned long flags;
	struct ib_port_info *port_info = (struct ib_port_info *)&smp->data;
	u32 port_num;
	struct pib_port *port;

	memset(smp->data, 0, sizeof(smp->data));

	port_num = be32_to_cpu(smp->attr_mod);

	if (port_num == 0)
		port_num = in_port_num;

	if ((port_num < 1) || (dev->ib_dev.phys_port_cnt < port_num)) {
		smp->status |= PIB_SMP_INVALID_FIELD;
		goto bail;
	}

	port = &dev->ports[port_num - 1];
	port_info->local_port_num = port_num;

 	spin_lock_irqsave(&dev->lock, flags);
	pib_subn_get_portinfo(smp, port, port_num, PIB_PORT_CA);
	spin_unlock_irqrestore(&dev->lock, flags);

bail:
	return reply(smp);
}


void pib_subn_get_portinfo(struct ib_smp *smp, struct pib_port *port, u8 port_num, enum pib_port_type type)
{
	struct ib_port_info *port_info;

	memset(smp->data, 0, sizeof(smp->data));

	port_info = (struct ib_port_info *)&smp->data;

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
		port_info->link_width_supported	= PIB_LINK_WIDTH_SUPPORTED;
		port_info->link_width_active	= port->ib_port_attr.active_width;

		/* 4 bits, 4 bits */
		port_info->linkspeed_portstate	= (PIB_LINK_SPEED_SUPPORTED << 4) | port->ib_port_attr.state;

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
		port_info->linkspeedactive_enabled =
			(port->ib_port_attr.active_speed << 4) | port->link_speed_enabled;

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


static int subn_set_portinfo(struct ib_smp *smp, struct pib_dev *dev, u8 in_port_num)
{
	unsigned long flags;
	int port_index;
	struct ib_port_info *port_info;
	u32 port_num;
	struct pib_port *port;
	struct ib_event event;
	u16 old_lid, new_lid;
	u16 old_sm_lid, new_sm_lid;
	enum ib_port_state old_state;

	port_info = (struct ib_port_info *)&smp->data;
	port_num = be32_to_cpu(smp->attr_mod);

	if (port_num == 0)
		port_num = in_port_num;

	if ((port_num < 1) || (dev->ib_dev.phys_port_cnt < port_num)) {
		smp->status |= PIB_SMP_INVALID_FIELD;
		goto bail;
	}

	port_index = port_num - 1;

	port = &dev->ports[port_index];

 	spin_lock_irqsave(&dev->lock, flags);

	old_lid    = port->ib_port_attr.lid;
	new_lid    = be16_to_cpu(port_info->lid);
	old_sm_lid = port->ib_port_attr.sm_lid;
	new_sm_lid = be16_to_cpu(port_info->sm_lid);

	if (!pib_multi_host_mode) {
		if (old_lid != new_lid) {
			if (old_lid != 0)
				pib_lid_table[old_lid] = NULL;
			if (new_lid != 0)
				pib_lid_table[new_lid] =
					dev->ports[port_num - 1].sockaddr;
		}
	}

	old_state = port->ib_port_attr.state;
	
	pib_subn_set_portinfo(smp, port, port_num, PIB_PORT_CA);

	if (port->is_connected) {
		if (port->ib_port_attr.phys_state != PIB_PHYS_PORT_LINK_UP)
			port->ib_port_attr.phys_state = PIB_PHYS_PORT_LINK_UP;

		if (port->ib_port_attr.state < IB_PORT_INIT)
			port->ib_port_attr.state = IB_PORT_INIT;
	}

	spin_unlock_irqrestore(&dev->lock, flags);

	memset(&event, 0, sizeof(event));

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


void pib_subn_set_portinfo(struct ib_smp *smp, struct pib_port *port, u8 port_num, enum pib_port_type type)
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
		switch (port_info->link_width_enabled) {
		case 0: /* No State Change */
			break;
		case 255: /* */
			port->link_width_enabled = PIB_LINK_WIDTH_SUPPORTED;
			break;
		default:
			port->link_width_enabled = port_info->link_width_enabled;
			break;
		}

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
		switch (port_info->linkspeedactive_enabled & 0xF) {
		case 0: /* No State Change */
			break;
		case 15: /* */
			port->link_speed_enabled = PIB_LINK_SPEED_SUPPORTED;
			break;
		default:
			port->link_speed_enabled = (port_info->linkspeedactive_enabled & 0xF);
			break;
		}

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


	/* set LinkWidthActive */
	if ((port->link_width_enabled == 0) || (15 < port->link_width_enabled))
	    ; /* No change */
	else if (port->link_width_enabled == 1)
		port->ib_port_attr.active_width = IB_WIDTH_1X;
	else if (port->link_width_enabled <= 3)
		port->ib_port_attr.active_width = IB_WIDTH_4X;
	else if (port->link_width_enabled <= 7)
		port->ib_port_attr.active_width = IB_WIDTH_8X;
	else
		port->ib_port_attr.active_width = IB_WIDTH_12X;

	/* set LinkSpeedActive */
	switch (port->link_speed_enabled) {
	case 1:
		port->ib_port_attr.active_speed = IB_SPEED_SDR; /*  2.5 Gbps (1) */
		break;
	case 3:
		port->ib_port_attr.active_speed = IB_SPEED_DDR; /*  5.0 Gbps (2) */
		break;
	case 5: case 7:
		port->ib_port_attr.active_speed = IB_SPEED_QDR; /* 10.0 Gbps (4) */
		break;		
	default: /* No change */
		break;
	}

#if 0
	pib_debug("pib: pib_subn_set_portinfo: type=%u, port_num=%u, tid=%llx, lid=%u, state=%u phy_state=%u\n",
		  type, port_num, (unsigned long long)cpu_to_be16(smp->tid), port->ib_port_attr.lid,
		  port->ib_port_attr.state, port->ib_port_attr.phys_state);
#endif
}


static int subn_get_pkey_table(struct ib_smp *smp, struct pib_dev *dev, u8 in_port_num)
{
	int i;
	unsigned long flags;
	u32 attr_mod, block_index, sw_port_index;
	__be16 *pkey_table;

	memset(smp->data, 0, sizeof(smp->data));

	pkey_table    = (__be16 *)&smp->data[0];

	attr_mod      = be32_to_cpu(smp->attr_mod);
	block_index   = attr_mod         & 0xFFFF;
	sw_port_index = (attr_mod >> 16) & 0xFFFF;

	if (block_index != 0) {
		pr_err("pib: *** %s: block_index = %u ***", __FUNCTION__, block_index);
		smp->status |= PIB_SMP_INVALID_FIELD;
		goto bail;
	}

 	spin_lock_irqsave(&dev->lock, flags);
	for (i=0; i<PIB_PKEY_PER_BLOCK; i++)
		pkey_table[i] = cpu_to_be16(dev->ports[in_port_num - 1].pkey_table[i]);
	spin_unlock_irqrestore(&dev->lock, flags);

bail:
	return reply(smp);
}


static int subn_set_pkey_table(struct ib_smp *smp, struct pib_dev *dev, u8 in_port_num)
{
	int i;
	unsigned long flags;
	int changed = 0;
	u32 attr_mod, block_index, sw_port_index;
	__be16 *pkey_table = (__be16 *)&smp->data[0];

	attr_mod      = be32_to_cpu(smp->attr_mod);

	block_index   = attr_mod         & 0xFFFF;
	sw_port_index = (attr_mod >> 16) & 0xFFFF;

	if (block_index != 0) {
		pr_err("pib: *** %s: block_index = %u ***", __FUNCTION__, block_index);
		smp->status |= PIB_SMP_INVALID_FIELD;
		goto bail;
	}

 	spin_lock_irqsave(&dev->lock, flags);
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
	spin_unlock_irqrestore(&dev->lock, flags);

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


static int subn_get_sl_to_vl_table(struct ib_smp *smp, struct pib_dev *dev, u8 in_port_num)
{
	pr_err("pib: *** %s ***", __FUNCTION__);

	return reply_failure(smp);
}


static int subn_set_sl_to_vl_table(struct ib_smp *smp, struct pib_dev *dev, u8 in_port_num)
{
	pr_err("pib: *** %s ***", __FUNCTION__);

	return reply_failure(smp);
}


static int subn_get_vl_arb_table(struct ib_smp *smp, struct pib_dev *dev, u8 in_port_num)
{
	pr_err("pib: *** %s ***", __FUNCTION__);

	return reply_failure(smp);
}


static int subn_set_vl_arb_table(struct ib_smp *smp, struct pib_dev *dev, u8 in_port_num)
{
	pr_err("pib: *** %s ***", __FUNCTION__);

	return reply_failure(smp);
}
