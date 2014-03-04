/*
 * smp.c - Pocess Subnet Management Packet(SMP)
 *
 * Copyright (c) 2014 Minoru NAKAMURA <nminoru@nminoru.jp>
 *
 * This code is licenced under the GPL version 2 or BSD license.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

#include "pibnetd.h"
#include "pibnetd_packet.h"


static int process_smp_get_method(struct pib_smp *smp, struct pib_switch *sw, u8 in_port_num);
static int process_smp_set_method(struct pib_smp *smp, struct pib_switch *sw, u8 in_port_num);
static int subn_get_nodedescription(struct pib_smp *smp, struct pib_switch *sw, u8 in_port_num);
static int subn_get_nodeinfo(struct pib_smp *smp, struct pib_switch *sw, u8 in_port_num);
static int subn_get_switchinfo(struct pib_smp *smp, struct pib_switch *sw, u8 in_port_num);
static int subn_set_switchinfo(struct pib_smp *smp, struct pib_switch *sw, u8 in_port_num);
static int subn_get_guidinfo(struct pib_smp *smp, struct pib_switch *sw, u8 in_port_num);
static int subn_set_guidinfo(struct pib_smp *smp, struct pib_switch *sw, u8 in_port_num);
static int subn_get_portinfo(struct pib_smp *smp, struct pib_switch *sw, u8 in_port_num);
static int subn_set_portinfo(struct pib_smp *smp, struct pib_switch *sw, u8 in_port_num);
static int subn_get_pkey_table(struct pib_smp *smp, struct pib_switch *sw, u8 in_port_num);
static int subn_set_pkey_table(struct pib_smp *smp, struct pib_switch *sw, u8 in_port_num);
static int subn_get_sl_to_vl_table(struct pib_smp *smp, struct pib_switch *sw, u8 in_port_num);
static int subn_set_sl_to_vl_table(struct pib_smp *smp, struct pib_switch *sw, u8 in_port_num);
static int subn_get_vl_arb_table(struct pib_smp *smp, struct pib_switch *sw, u8 in_port_num);
static int subn_set_vl_arb_table(struct pib_smp *smp, struct pib_switch *sw, u8 in_port_num);
static int subn_get_linear_forward_table(struct pib_smp *smp, struct pib_switch *sw, u8 in_port_num);
static int subn_set_linear_forward_table(struct pib_smp *smp, struct pib_switch *sw, u8 in_port_num);
static int subn_get_random_forward_table(struct pib_smp *smp, struct pib_switch *sw, u8 in_port_num);
static int subn_set_random_forward_table(struct pib_smp *smp, struct pib_switch *sw, u8 in_port_num);
static int subn_get_mcast_forward_table(struct pib_smp *smp, struct pib_switch *sw, u8 in_port_num);
static int subn_set_mcast_forward_table(struct pib_smp *smp, struct pib_switch *sw, u8 in_port_num);
static int reply(struct pib_smp *smp);
static int reply_failure(struct pib_smp *smp);


int pib_process_smp(struct pib_smp *smp, struct pib_switch *sw, uint8_t in_port_num)
{
	int ret;

	switch (smp->method) {

	case PIB_MGMT_METHOD_GET:
		return process_smp_get_method(smp, sw, in_port_num);

	case PIB_MGMT_METHOD_SET:
		ret = process_smp_set_method(smp, sw, in_port_num);
		if (smp->status & ~PIB_SMP_DIRECTION)
			return ret;
		return process_smp_get_method(smp, sw, in_port_num);

	case PIB_MGMT_METHOD_GET_RESP:
		if (smp->mgmt_class == PIB_MGMT_CLASS_SUBN_LID_ROUTED)
			return PIB_SMP_RESULT_SUCCESS | PIB_SMP_RESULT_CONSUMED;
		/* pass through */

	default:
		pib_report_debug("pibnetd: process_smp: %u %u",
				 smp->method, be16_to_cpu(smp->attr_id));
		smp->status |= PIB_SMP_UNSUP_METHOD;
		return reply(smp);
	}
}


static int process_smp_get_method(struct pib_smp *smp, struct pib_switch *sw, u8 in_port_num)
{
	memset(smp->data, 0, sizeof(smp->data));

	switch (be16_to_cpu(smp->attr_id)) {

	case PIB_SMP_ATTR_NODE_DESC:
		return subn_get_nodedescription(smp, sw, in_port_num);

	case PIB_SMP_ATTR_NODE_INFO:
		return subn_get_nodeinfo(smp, sw, in_port_num);

	case PIB_SMP_ATTR_SWITCH_INFO:
		return subn_get_switchinfo(smp, sw, in_port_num);

	case PIB_SMP_ATTR_GUID_INFO:
		return subn_get_guidinfo(smp, sw, in_port_num);

	case PIB_SMP_ATTR_PORT_INFO:
		return subn_get_portinfo(smp, sw, in_port_num);

	case PIB_SMP_ATTR_PKEY_TABLE:
		return subn_get_pkey_table(smp, sw, in_port_num);

	case PIB_SMP_ATTR_SL_TO_VL_TABLE:
		return subn_get_sl_to_vl_table(smp, sw, in_port_num);

	case PIB_SMP_ATTR_VL_ARB_TABLE:
		return subn_get_vl_arb_table(smp, sw, in_port_num);

	case PIB_SMP_ATTR_LINEAR_FORWARD_TABLE:
		return subn_get_linear_forward_table(smp, sw, in_port_num);

	case PIB_SMP_ATTR_RANDOM_FORWARD_TABLE:
		return subn_get_random_forward_table(smp, sw, in_port_num);

	case PIB_SMP_ATTR_MCAST_FORWARD_TABLE:
		return subn_get_mcast_forward_table(smp, sw, in_port_num);

	default:
		pib_report_debug("pibnet: process_subn: IB_MGMT_METHOD_GET: %u",
				 be16_to_cpu(smp->attr_id));
		smp->status |= PIB_SMP_UNSUP_METH_ATTR;
		return reply(smp);
	}
}


static int process_smp_set_method(struct pib_smp *smp, struct pib_switch *sw, u8 in_port_num)
{
	switch (be16_to_cpu(smp->attr_id)) {

	case PIB_SMP_ATTR_SWITCH_INFO:
		return subn_set_switchinfo(smp, sw, in_port_num);

	case PIB_SMP_ATTR_GUID_INFO:
		return subn_set_guidinfo(smp, sw, in_port_num);

	case PIB_SMP_ATTR_PORT_INFO:
		return subn_set_portinfo(smp, sw, in_port_num);

	case PIB_SMP_ATTR_PKEY_TABLE:
		return subn_set_pkey_table(smp, sw, in_port_num);

	case PIB_SMP_ATTR_SL_TO_VL_TABLE:
		return subn_set_sl_to_vl_table(smp, sw, in_port_num);

	case PIB_SMP_ATTR_VL_ARB_TABLE:
		return subn_set_vl_arb_table(smp, sw, in_port_num);

	case PIB_SMP_ATTR_LINEAR_FORWARD_TABLE:
		return subn_set_linear_forward_table(smp, sw, in_port_num);

	case PIB_SMP_ATTR_RANDOM_FORWARD_TABLE:
		return subn_set_random_forward_table(smp, sw, in_port_num);

	case PIB_SMP_ATTR_MCAST_FORWARD_TABLE:
		return subn_set_mcast_forward_table(smp, sw, in_port_num);

	default:
		pib_report_debug("pibnetd: process_smp: IB_MGMT_METHOD_SET: %u",
				 be16_to_cpu(smp->attr_id));
		smp->status |= PIB_SMP_UNSUP_METH_ATTR;
		return reply(smp);
	}
}


static int subn_get_nodedescription(struct pib_smp *smp, struct pib_switch *sw, u8 in_port_num)
{
	if (smp->attr_mod)
		smp->status |= PIB_SMP_INVALID_FIELD;

	strncpy((char*)smp->data, PIB_SWITCH_DESCRIPTION, 64);

	return reply(smp);
}


static int subn_get_nodeinfo(struct pib_smp *smp, struct pib_switch *sw, u8 in_port_num)
{
	struct pib_smp_node_info *node_info = (struct pib_smp_node_info *)&smp->data;

	/* smp->status |= PIB_SMP_INVALID_FIELD; */

	node_info->base_version		= PIB_MGMT_BASE_VERSION;
	node_info->class_version	= PIB_MGMT_CLASS_VERSION;
	node_info->node_type		= IBV_NODE_SWITCH;
	node_info->node_ports		= sw->port_cnt - 1;
	node_info->sys_image_guid	= cpu_to_be64(pib_hca_guid_base | 0x0200ULL);
	node_info->node_guid		= cpu_to_be64(pib_hca_guid_base | 0x0100ULL);
	node_info->port_guid		= cpu_to_be64(pib_hca_guid_base | 0x0100ULL);
	node_info->partition_cap	= cpu_to_be16(1); /* @todo */
	node_info->device_id		= cpu_to_be16(PIB_DRIVER_DEVICE_ID);
	node_info->revision		= cpu_to_be32(PIB_DRIVER_REVISION);
	node_info->local_port_num	= in_port_num;
	node_info->vendor_id[0]		= 0; /* OUI */
	node_info->vendor_id[1]		= 0; /* OUI */
	node_info->vendor_id[2]		= 0; /* OUI */

	return reply(smp);
}


static int subn_get_switchinfo(struct pib_smp *smp, struct pib_switch *sw, u8 in_port_num)
{
	struct pib_smp_switch_info *switch_info = (struct pib_smp_switch_info *)&smp->data;
	u8 opimized_sl_to_vl_mapping_programming;

	switch_info->linear_fdb_cap	= cpu_to_be16(768);
	switch_info->random_fdb_cap	= cpu_to_be16(3072);
	switch_info->multicast_fdb_cap	= cpu_to_be16(256); /* @todo */
	switch_info->linear_fdb_top	= cpu_to_be16(sw->linear_fdb_top);

	switch_info->default_port	= sw->default_port;
	switch_info->default_mcast_primary_port = sw->default_mcast_primary_port;
	switch_info->default_mcast_not_primary_port = sw->default_mcast_not_primary_port;

	opimized_sl_to_vl_mapping_programming = 0;

	switch_info->various1 = (sw->life_time_value << 3) | (sw->port_state_change << 2) |
		opimized_sl_to_vl_mapping_programming;

	switch_info->lids_per_port	= cpu_to_be16(1);
	switch_info->partition_enforcement_cap = cpu_to_be16(0);

	switch_info->various2		= 0;

	return reply(smp);
}


static int subn_set_switchinfo(struct pib_smp *smp, struct pib_switch *sw, u8 in_port_num)
{
	struct pib_smp_switch_info *switch_info = (struct pib_smp_switch_info *)&smp->data;

	sw->linear_fdb_top	= be16_to_cpu(switch_info->linear_fdb_top);
	sw->default_port	= switch_info->default_port;
	sw->default_mcast_primary_port = switch_info->default_mcast_primary_port;
	sw->default_mcast_not_primary_port = switch_info->default_mcast_not_primary_port;

	sw->life_time_value	= (switch_info->various1 >> 3) & 0x1F;

	if ((switch_info->various1 >> 2) & 0x01)
		sw->port_state_change = 0; /* clear */ 

	return reply(smp);
}


static int subn_get_guidinfo(struct pib_smp *smp, struct pib_switch *sw, u8 in_port_num)
{
	pib_report_debug("pibnetd: *** %s ***", __FUNCTION__);
	return reply_failure(smp);
}


static int subn_set_guidinfo(struct pib_smp *smp, struct pib_switch *sw, u8 in_port_num)
{
	pib_report_debug("pibnetd: *** %s ***", __FUNCTION__);
	return reply_failure(smp);
}


static int subn_get_portinfo(struct pib_smp *smp, struct pib_switch *sw, u8 in_port_num)
{
	uint8_t port_num;
	struct pib_port *port;
	struct pib_port_info *port_info;
	enum pib_port_type type;

	port_num  = be32_to_cpu(smp->attr_mod);
	port      = &sw->ports[port_num];

	port_info = (struct pib_port_info *)&smp->data;
	port_info->local_port_num = in_port_num;

	type = (port_num != 0) ? PIB_PORT_SW_EXT : PIB_PORT_BASE_SP0;

	memset(smp->data, 0, sizeof(smp->data));

	/*
	 * m-key check
	 * 失敗したら IB_MAD_RESULT_FAILURE を
	 */

	if (type != PIB_PORT_SW_EXT) {
		port_info->mkey		= port->mkey;
		port_info->lid		= cpu_to_be16(port->ibv_port_attr.lid);
		port_info->sm_lid	= cpu_to_be16(port->ibv_port_attr.sm_lid);
		port_info->gid_prefix	= port->gid[0].global.subnet_prefix;
		port_info->cap_mask	= cpu_to_be32(port->ibv_port_attr.port_cap_flags);
#if 0
		port_info->diag_code;
#endif
		port_info->mkey_lease_period = cpu_to_be16(port->mkey_lease_period);
	}

	if (type != PIB_PORT_BASE_SP0) { 
		port_info->link_width_enabled	= port->link_width_enabled;
		port_info->link_width_supported	= PIB_LINK_WIDTH_SUPPORTED;
		port_info->link_width_active	= port->ibv_port_attr.active_width;

		/* 4 bits, 4 bits */
		port_info->linkspeed_portstate	= (PIB_LINK_SPEED_SUPPORTED << 4) | port->ibv_port_attr.state;

		/* 4 bits, 4 bits */
		port_info->portphysstate_linkdown =
			(port->ibv_port_attr.phys_state   << 4) | port->link_down_default_state;
	}

	if (type != PIB_PORT_SW_EXT) {
		/* 2 bits, 3, 3 */
		port_info->mkeyprot_resv_lmc =
			(port->mkeyprot << 6) | port->ibv_port_attr.lmc;
	}

	if (type != PIB_PORT_BASE_SP0) {
		/* 4 bits, 4 bits */
		port_info->linkspeedactive_enabled =
			(port->ibv_port_attr.active_speed << 4) | port->link_speed_enabled;

		/* 4 bits, 4 bits */
		port_info->neighbormtu_mastersmsl |=
			(port->ibv_port_attr.active_mtu << 4);
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
		port_info->inittypereply_mtucap |= IBV_MTU_4096;

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

	return reply(smp);
}


static int subn_set_portinfo(struct pib_smp *smp, struct pib_switch *sw, u8 in_port_num)
{
	uint8_t port_num;
	struct pib_port *port;
	struct pib_port_info *port_info;
	enum pib_port_type type;

	port_num = be32_to_cpu(smp->attr_mod);
	port     = &sw->ports[port_num];

	port_info = (struct pib_port_info *)&smp->data;

	type = (port_num != 0) ? PIB_PORT_SW_EXT : PIB_PORT_BASE_SP0;

	if (type != PIB_PORT_SW_EXT) {
		port->mkey			= port_info->mkey;
		port->ibv_port_attr.lid		= be16_to_cpu(port_info->lid);
		port->ibv_port_attr.sm_lid	= be16_to_cpu(port_info->sm_lid);
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
			port->ibv_port_attr.state  = port_info->linkspeed_portstate & 0xF;

		if (port_info->portphysstate_linkdown >> 4)
			port->ibv_port_attr.phys_state = (port_info->portphysstate_linkdown >> 4);

		if (port_info->portphysstate_linkdown & 0xF)
			port->link_down_default_state = (port_info->portphysstate_linkdown & 0xF);
	}

	if (type != PIB_PORT_SW_EXT) {
		port->mkeyprot		= (port_info->mkeyprot_resv_lmc >> 6) & 0x3;
		port->ibv_port_attr.lmc	= port_info->mkeyprot_resv_lmc & 0x7;
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

		port->ibv_port_attr.active_mtu	= (port_info->neighbormtu_mastersmsl >> 4);
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
		port->ibv_port_attr.active_width = PIB_WIDTH_1X;
	else if (port->link_width_enabled <= 3)
		port->ibv_port_attr.active_width = PIB_WIDTH_4X;
	else if (port->link_width_enabled <= 7)
		port->ibv_port_attr.active_width = PIB_WIDTH_8X;
	else
		port->ibv_port_attr.active_width = PIB_WIDTH_12X;

	/* set LinkSpeedActive */
	switch (port->link_speed_enabled) {
	case 1:
		port->ibv_port_attr.active_speed = PIB_SPEED_SDR; /*  2.5 Gbps (1) */
		break;
	case 3:
		port->ibv_port_attr.active_speed = PIB_SPEED_DDR; /*  5.0 Gbps (2) */
		break;
	case 5: case 7:
		port->ibv_port_attr.active_speed = PIB_SPEED_QDR; /* 10.0 Gbps (4) */
		break;		
	default: /* No change */
		break;
	}

	if (port->ibv_port_attr.phys_state != PIB_PHYS_PORT_LINK_UP)
		port->ibv_port_attr.phys_state = PIB_PHYS_PORT_LINK_UP;

	if (port->ibv_port_attr.state < IBV_PORT_INIT) {
		sw->port_state_change    = 1;
		port->ibv_port_attr.state = IBV_PORT_INIT;
	}

	return reply(smp);
}


static int subn_get_pkey_table(struct pib_smp *smp, struct pib_switch *sw, u8 in_port_num)
{
	int i;
	u32 attr_mod, block_index, sw_port_index;
	__be16 *pkey_table = (__be16 *)&smp->data[0];

	attr_mod      = be32_to_cpu(smp->attr_mod);

	block_index   = attr_mod         & 0xFFFF;
	sw_port_index = (attr_mod >> 16) & 0xFFFF;

	if (block_index != 0) {
		smp->status |= PIB_SMP_INVALID_FIELD;
		goto bail;
	}

	if (sw->port_cnt <= sw_port_index) {
		smp->status |= PIB_SMP_INVALID_FIELD;
		goto bail;
	}

	for (i=0; i<PIB_PKEY_PER_BLOCK; i++)
		pkey_table[i] = cpu_to_be16(sw->ports[sw_port_index].pkey_table[i]);

bail:
	return reply(smp);
}


static int subn_set_pkey_table(struct pib_smp *smp, struct pib_switch *sw, u8 in_port_num)
{
	int i;
	u32 attr_mod, block_index, sw_port_index;
	__be16 *pkey_table = (__be16 *)&smp->data[0];

	attr_mod      = be32_to_cpu(smp->attr_mod);

	block_index   = attr_mod         & 0xFFFF;
	sw_port_index = (attr_mod >> 16) & 0xFFFF;

	if (block_index != 0) {
		smp->status |= PIB_SMP_INVALID_FIELD;
		goto bail;
	}

	if (sw->port_cnt <= sw_port_index) {
		smp->status |= PIB_SMP_INVALID_FIELD;
		goto bail;
	}

	for (i=0; i<PIB_PKEY_PER_BLOCK; i++)
		sw->ports[sw_port_index].pkey_table[i] = be16_to_cpu(pkey_table[i]);

bail:
	return reply(smp);
}


static int subn_get_sl_to_vl_table(struct pib_smp *smp, struct pib_switch *sw, u8 in_port_num)
{
	pib_report_debug("pibnetd: *** %s ***", __FUNCTION__);
	return reply_failure(smp);
}


static int subn_set_sl_to_vl_table(struct pib_smp *smp, struct pib_switch *sw, u8 in_port_num)
{
	pib_report_debug("pibnetd: *** %s ***", __FUNCTION__);
	return reply_failure(smp);
}


static int subn_get_vl_arb_table(struct pib_smp *smp, struct pib_switch *sw, u8 in_port_num)
{
	pib_report_debug("pibnetd: *** %s ***", __FUNCTION__);
	return reply_failure(smp);
}


static int subn_set_vl_arb_table(struct pib_smp *smp, struct pib_switch *sw, u8 in_port_num)
{
	pib_report_debug("pibnetd: *** %s ***", __FUNCTION__);
	return reply_failure(smp);
}


static int subn_get_linear_forward_table(struct pib_smp *smp, struct pib_switch *sw, u8 in_port_num)
{
	u32 i, attr_mod;
	u8 *table = (u8 *)&smp->data[0];

	attr_mod = be32_to_cpu(smp->attr_mod);

	if (767 < attr_mod) {
		smp->status |= PIB_SMP_INVALID_FIELD;
		goto bail;
	}
	
	for (i = 0 ; i < 64 ; i++)
		if (attr_mod * 64 + i <= sw->linear_fdb_top)
			table[i] = sw->ucast_fwd_table[attr_mod * 64 + i];

bail:
	return reply(smp);
}


static int subn_set_linear_forward_table(struct pib_smp *smp, struct pib_switch *sw, u8 in_port_num)
{
	u32 i, attr_mod;
	u8 *table = (u8 *)&smp->data[0];

	attr_mod = be32_to_cpu(smp->attr_mod);

	if (767 < attr_mod) {
		smp->status |= PIB_SMP_INVALID_FIELD;
		goto bail;
	}
	
	for (i = 0 ; i < 64 ; i++)
		sw->ucast_fwd_table[attr_mod * 64 + i] = table[i];

bail:
	return reply(smp);
}


static int subn_get_random_forward_table(struct pib_smp *smp, struct pib_switch *sw, u8 in_port_num)
{
	pib_report_debug("pibnetd: *** %s ***", __FUNCTION__);
	return reply_failure(smp);
}


static int subn_set_random_forward_table(struct pib_smp *smp, struct pib_switch *sw, u8 in_port_num)
{
	u32 i, attr_mod;
	__be32 *table = (__be32 *)&smp->data[0];

	attr_mod = be32_to_cpu(smp->attr_mod);

	if (3071 < attr_mod) {
		smp->status |= PIB_SMP_INVALID_FIELD;
		goto bail;
	}
	
	for (i = 0 ; i < 16 ; i++) {
		u32 value = be32_to_cpu(table[i]);
		u16 dlid  = value >> 16;

		/* @todo LMC */
		
		sw->ucast_fwd_table[dlid] = (value & 0x8000U) ?
			(value & 0xFFU) : sw->default_port;
	}

bail:
	return reply(smp);
}


static int subn_get_mcast_forward_table(struct pib_smp *smp, struct pib_switch *sw, u8 in_port_num)
{
	u32 attr_mod;
	u32 i, mcast_lid_offset, port_index;
	__be16 *table = (__be16 *)&smp->data[0];

	attr_mod = be32_to_cpu(smp->attr_mod);
	
	mcast_lid_offset = (attr_mod & 0xFF) * 32;
	port_index       = (attr_mod >> 28);

	for (i=0 ; i<32 ; i++)
		table[i] = cpu_to_be16(sw->mcast_fwd_table[mcast_lid_offset + i].pm_blocks[port_index]);

	return reply(smp);
}


static int subn_set_mcast_forward_table(struct pib_smp *smp, struct pib_switch *sw, u8 in_port_num)
{
	u32 attr_mod;
	u32 i, mcast_lid_offset, port_index;
	__be16 *table = (__be16 *)&smp->data[0];

	attr_mod = be32_to_cpu(smp->attr_mod);
	
	mcast_lid_offset = (attr_mod & 0xFF) * 32;
	port_index       = (attr_mod >> 28);

	for (i=0 ; i<32 ; i++)
		sw->mcast_fwd_table[mcast_lid_offset + i].pm_blocks[port_index] =
			be16_to_cpu(table[i]);

	return reply(smp);
}


static int reply(struct pib_smp *smp)
{
	smp->method = PIB_MGMT_METHOD_GET_RESP;

	if (smp->mgmt_class == PIB_MGMT_CLASS_SUBN_DIRECTED_ROUTE)
		smp->status |= PIB_SMP_DIRECTION;

	return PIB_SMP_RESULT_SUCCESS | PIB_SMP_RESULT_REPLY;
}


static int reply_failure(struct pib_smp *smp)
{
	smp->method = PIB_MGMT_METHOD_GET_RESP;

	if (smp->mgmt_class == PIB_MGMT_CLASS_SUBN_DIRECTED_ROUTE)
		smp->status |= PIB_SMP_DIRECTION;

	return PIB_SMP_RESULT_FAILURE | PIB_SMP_RESULT_REPLY;
}

