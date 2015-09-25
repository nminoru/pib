/*
 * pib_mad_pmc.c - Performance Management Agent
 *
 * Copyright (c) 2013-2015 Minoru NAKAMURA <nminoru@nminoru.jp>
 *
 * This code is licenced under the GPL version 2 or BSD license.
 */
#include <linux/module.h>
#include <linux/init.h>
#include <rdma/ib_mad.h>
#include <rdma/ib_pma.h>

#include "pib.h"
#include "pib_mad.h"

#define PIB_PMA_CLASS_VERSION			(1)

#define PIB_PMA_STATUS_BAD_VERSION		(0x1 << 2)
#define PIB_PMA_STATUS_UNSUPPORTED_METHOD	(0x2 << 2) /* discard response ? */
#define PIB_PMA_STATUS_UNSUPPORTED_METHOD_ATTRIB	(0x3 << 2)
#define PIB_PMA_STATUS_INVALID_ATTRIB_VALUE	(0x7 << 2)

#define PIB_PMA_PORT_RCV_ERROR_DETAILS		(0x0015)
#define PIB_PMA_PORT_XMIT_DISCARD_DETAILS	(0x0016)
#define PIB_PMA_PORT_OP_RCV_COUNTERS		(0x0017)
#define PIB_PMA_PORT_FLOW_CTL_COUNTERS		(0x0018)
#define PIB_PMA_PORT_VL_OP_PACKETS		(0x0019)
#define PIB_PMA_PORT_VL_OP_DATA			(0x001A)
#define PIB_PMA_PORT_VL_XMIT_FLOW_CTL_UPDATE_ERRORS	(0x001B)
#define PIB_PMA_PORT_VL_XMIT_WAIT_COUNTERS	(0x001C)
#define PIB_PMA_PORT_COUNTERS_EXT		(0x001D)
#define PIB_PMA_PORT_SAMPLES_RESULT_EXT		(0x001E)
#define PIB_PMA_PORT_VL_CONGESTION		(0x0030)

#define PIB_PMA_SAMPLE_STATUS_DONE		(0x00)
#define PIB_PMA_SAMPLE_STATUS_STARTED		(0x01)
#define PIB_PMA_SAMPLE_STATUS_RUNNING		(0x02)

#define PIB_PMA_SEL_PORT_RCV_SWITCH_RELAY_ERRORS	cpu_to_be16(0x0020)
#define PIB_PMA_SEL_PORT_XMIT_CONSTRAINT_ERRORS	cpu_to_be16(0x0080)
#define PIB_PMA_SEL_PORT_RCV_CONSTRAINT_ERRORS	cpu_to_be16(0x0100)


static u8 get_saturation4(u64 value)
{
	if (value > 0xF)
		return 0xF;
	else
		return (value & 0xF);
}


static u8 get_saturation8(u64 value)
{
	if (value > 0xFF)
		return 0xFF;
	else
		return (u8)value;
}


static u16 get_saturation16(u64 value)
{
	if (value > 0xFFFF)
		return 0xFFFF;
	else
		return (u16)value;
}


static u32 get_saturation32(u64 value)
{
	if (value >> 32)
		return 0xFFFFFFFF;
	else
		return (u32)value;
}


static int pma_get_method(struct ib_pma_mad *pmp, struct pib_node *node, u8 port_num);
static int pma_set_method(struct ib_pma_mad *pmp, struct pib_node *node, u8 port_num);

static int pma_get_class_port_info(struct ib_pma_mad *pmp, struct pib_node *node, u8 port_num);
static int pma_get_port_samples_control(struct ib_pma_mad *pmp, struct pib_node *node, u8 port_num);
static int pma_set_port_samples_control(struct ib_pma_mad *pmp, struct pib_node *node, u8 port_num);
static int pma_get_port_samples_result(struct ib_pma_mad *pmp, struct pib_node *node, u8 port_num);
static int pma_get_port_samples_result_ext(struct ib_pma_mad *pmp, struct pib_node *node, u8 port_num);
static int pma_get_port_counters(struct ib_pma_mad *pmp, struct pib_node *node, u8 port_num);
static int pma_set_port_counters(struct ib_pma_mad *pmp, struct pib_node *node, u8 port_num);
static int pma_get_port_counters_ext(struct ib_pma_mad *pmp, struct pib_node *node, u8 port_num);
static int pma_set_port_counters_ext(struct ib_pma_mad *pmp, struct pib_node *node, u8 port_num);


static int reply(struct ib_mad_hdr *mad_hdr)
{
	mad_hdr->method = IB_MGMT_METHOD_GET_RESP;

	return IB_MAD_RESULT_SUCCESS | IB_MAD_RESULT_REPLY;
}


int pib_process_pma_mad(struct pib_node *node, u8 port_num,
			const struct ib_mad *in_mad, struct ib_mad *out_mad)
{
	int ret;
	struct ib_pma_mad *pmp = (struct ib_pma_mad *)out_mad;
	u8 method;

	*out_mad = *in_mad;

	pmp = (struct ib_pma_mad *)out_mad;

	if ((pmp->mad_hdr.base_version  != IB_MGMT_BASE_VERSION) ||
	    (pmp->mad_hdr.class_version != PIB_PMA_CLASS_VERSION)) {
		pmp->mad_hdr.status = PIB_PMA_STATUS_BAD_VERSION;
		return reply(&pmp->mad_hdr);
	}

	method = pmp->mad_hdr.method;
	
	switch (method) {

	case IB_MGMT_METHOD_GET:
		ret = pma_get_method(pmp, node, port_num);
		break;

	case IB_MGMT_METHOD_SET:
		ret = pma_set_method(pmp, node, port_num);
		break;

	case IB_MGMT_METHOD_TRAP:
	case IB_MGMT_METHOD_GET_RESP:
		pr_info("*** %s %u ***\n", __FUNCTION__, __LINE__);
		return IB_MAD_RESULT_SUCCESS;

	default:
		pr_err("pib: *** %s subn: %u ***", __func__, method);
		pmp->mad_hdr.status = PIB_PMA_STATUS_UNSUPPORTED_METHOD;
		ret = reply(&pmp->mad_hdr);
		break;
	}

	return ret;

}


static int pma_get_method(struct ib_pma_mad *pmp, struct pib_node *node, u8 port_num)
{
	switch (pmp->mad_hdr.attr_id) {

	case IB_PMA_CLASS_PORT_INFO:
		return pma_get_class_port_info(pmp, node, port_num);

	case IB_PMA_PORT_SAMPLES_CONTROL:
		pr_info("pib: PerformanceGet(PORT_SAMPLES_CONTROL) attr_id=0x%04x", be16_to_cpu(pmp->mad_hdr.attr_id));
		return pma_get_port_samples_control(pmp, node, port_num);

	case IB_PMA_PORT_SAMPLES_RESULT:
		pr_info("pib: PerformanceGet(PORT_SAMPLES_RESULT) attr_id=0x%04x", be16_to_cpu(pmp->mad_hdr.attr_id));
		return pma_get_port_samples_result(pmp, node, port_num);

	case IB_PMA_PORT_SAMPLES_RESULT_EXT:
		pr_info("pib: PerformanceGet(PORT_SAMPLES_RESULT_EXT) attr_id=0x%04x", be16_to_cpu(pmp->mad_hdr.attr_id));
		return pma_get_port_samples_result_ext(pmp, node, port_num);

	case IB_PMA_PORT_COUNTERS:
		return pma_get_port_counters(pmp, node, port_num);

	case IB_PMA_PORT_COUNTERS_EXT:
		return pma_get_port_counters_ext(pmp, node, port_num);

	default:
		pr_err("pib: PerformanceGet() attr_id=0x%04x", be16_to_cpu(pmp->mad_hdr.attr_id));
		pmp->mad_hdr.status = PIB_PMA_STATUS_UNSUPPORTED_METHOD_ATTRIB;
		return reply(&pmp->mad_hdr);
	}
}


static int pma_set_method(struct ib_pma_mad *pmp, struct pib_node *node, u8 port_num)
{
	switch (pmp->mad_hdr.attr_id) {

	case IB_PMA_PORT_SAMPLES_CONTROL:
		pr_info("pib: PerformanceSet(PORT_SAMPLES_CONTROL) attr_id=0x%04x", be16_to_cpu(pmp->mad_hdr.attr_id));
		return pma_set_port_samples_control(pmp, node, port_num);

#if 0
	case IB_PMA_PORT_SAMPLES_RESULT_EXT:
		return pma_set_port_samples_result_ext(pmp, node, port_num);
#endif

	case IB_PMA_PORT_COUNTERS:
		return pma_set_port_counters(pmp, node, port_num);

	case IB_PMA_PORT_COUNTERS_EXT:
		return pma_set_port_counters_ext(pmp, node, port_num);

	default:
		pr_err("pib: PerformanceSet() attr_id=0x%04x", be16_to_cpu(pmp->mad_hdr.attr_id));
		pmp->mad_hdr.status = PIB_PMA_STATUS_UNSUPPORTED_METHOD_ATTRIB;
		return reply(&pmp->mad_hdr);
	}
}


static int pma_get_class_port_info(struct ib_pma_mad *pmp, struct pib_node *node, u8 port_num)
{
	struct ib_class_port_info *info =
		(struct ib_class_port_info *)pmp->data;

	memset(pmp->data, 0, sizeof(pmp->data));

	if (pmp->mad_hdr.attr_mod != cpu_to_be16(0)) {
		pmp->mad_hdr.status = PIB_PMA_STATUS_INVALID_ATTRIB_VALUE;
		goto bail;
	}

	info->base_version    = IB_MGMT_BASE_VERSION;
	info->class_version   = PIB_PMA_CLASS_VERSION;
	info->capability_mask = IB_PMA_CLASS_CAP_EXT_WIDTH;

	/*
	 * Set the most significant bit of CM2 to indicate support for
	 * congestion statistics
	 */
	/* p->reserved[0] = dd->psxmitwait_supported << 7; */
	
	/*
	 * Expected response time is 4.096 usec. * 2^18 == 1.073741824 sec.
	 */
	info->resp_time_value = 18;

bail:
	return reply(&pmp->mad_hdr);
}


static int pma_get_port_samples_control(struct ib_pma_mad *pmp, struct pib_node *node, u8 port_num)
{
	int i;
	struct ib_pma_portsamplescontrol *p =
		(struct ib_pma_portsamplescontrol *)pmp->data;
	struct pib_port_perf *perf; 
	u8 port_select;

	port_select = p->port_select;

	memset(pmp->data, 0, sizeof(pmp->data));

	p->port_select = port_select;
	
	if (pmp->mad_hdr.attr_mod != cpu_to_be16(0)) {
		pmp->mad_hdr.status = PIB_PMA_STATUS_INVALID_ATTRIB_VALUE;
		goto bail;
	}

	/* Base management port is ignore. */
	if ((port_select < node->port_start) || (node->port_count <= port_select)) {
		pmp->mad_hdr.status = PIB_PMA_STATUS_INVALID_ATTRIB_VALUE;
		goto bail;
	}

	perf = &node->ports[port_select - node->port_start].perf;

	p->opcode            = perf->OpCode;
	p->tick              = 1;
	p->counter_width     = 4; /* 32 bits counter */

	p->counter_mask0_9   = cpu_to_be32(0x09249249);
	p->counter_mask10_14 = cpu_to_be16(0x1249);

	p->sample_mechanisms = 0; /* one sample mechanism is available. */
	p->sample_status     = PIB_PMA_SAMPLE_STATUS_DONE;

	p->sample_start      = cpu_to_be32(0);
	p->sample_interval   = cpu_to_be32(0);
	p->tag               = cpu_to_be16(perf->tag);

	for (i=0 ; i<ARRAY_SIZE(p->counter_select) ; i++)
		p->counter_select[i] = cpu_to_be16(perf->counter_select[i]);

bail:
	return reply(&pmp->mad_hdr);
}


static int pma_set_port_samples_control(struct ib_pma_mad *pmp, struct pib_node *node, u8 port_num)
{
	int i;
	struct ib_pma_portsamplescontrol *p =
		(struct ib_pma_portsamplescontrol *)pmp->data;
	struct pib_port_perf *perf; 
	u8 port_select;

	port_select = p->port_select;

	memset(pmp->data, 0, sizeof(pmp->data));

	p->port_select = port_select;

	if (pmp->mad_hdr.attr_mod != cpu_to_be16(0)) {
		pmp->mad_hdr.status = PIB_PMA_STATUS_INVALID_ATTRIB_VALUE;
		goto bail;
	}

	/* Base management port is ignore. */
	if ((port_select < node->port_start) || (node->port_count <= port_select)) {
		pmp->mad_hdr.status = PIB_PMA_STATUS_INVALID_ATTRIB_VALUE;
		goto bail;
	}

	perf = &node->ports[port_select - node->port_start].perf; 

	perf->OpCode	= p->opcode;
	perf->tag	= be16_to_cpu(p->tag);

#if 0
	p->sample_start      = cpu_to_be32();
	p->sample_interval   = cpu_to_be32();
#endif

	for (i=0 ; i<ARRAY_SIZE(p->counter_select) ; i++)
		perf->counter_select[i] = be16_to_cpu(p->counter_select[i]);

bail:
	return pma_get_port_samples_control(pmp, node, port_num);
}


static int pma_get_port_samples_result(struct ib_pma_mad *pmp, struct pib_node *node, u8 port_num)
{
	int i;
	struct ib_pma_portsamplesresult *p =
		(struct ib_pma_portsamplesresult *)pmp->data;
	struct pib_port_perf *perf; 

	memset(pmp->data, 0, sizeof(pmp->data));

	if (pmp->mad_hdr.attr_mod != cpu_to_be16(0)) {
		pmp->mad_hdr.status = PIB_PMA_STATUS_INVALID_ATTRIB_VALUE;
		goto bail;
	}

	perf = &node->ports[port_num - node->port_start].perf;

	p->tag           = cpu_to_be16(perf->tag);
	p->sample_status = PIB_PMA_SAMPLE_STATUS_DONE;

	for (i=0 ; i<ARRAY_SIZE(p->counter) ; i++)
		p->counter[i] = cpu_to_be32((u32)perf->counter[i]);

bail:
	return reply(&pmp->mad_hdr);
}


static int pma_get_port_samples_result_ext(struct ib_pma_mad *pmp, struct pib_node *node, u8 port_num)
{
	int i;
	struct ib_pma_portsamplesresult_ext *p = 
		(struct ib_pma_portsamplesresult_ext *)pmp->data;
	struct pib_port_perf *perf; 

	memset(pmp->data, 0, sizeof(pmp->data));

	if (pmp->mad_hdr.attr_mod != cpu_to_be16(0)) {
		pmp->mad_hdr.status = PIB_PMA_STATUS_INVALID_ATTRIB_VALUE;
		goto bail;
	}

	perf = &node->ports[port_num - node->port_start].perf;

	p->tag            = cpu_to_be16(perf->tag);
	p->sample_status  = cpu_to_be16(PIB_PMA_SAMPLE_STATUS_DONE);
	p->extended_width = cpu_to_be32(0x80000000); /* 64 bits counter */

	for (i=0 ; i<ARRAY_SIZE(p->counter) ; i++)
		p->counter[i] = cpu_to_be64(perf->counter[i]);

bail:
	return reply(&pmp->mad_hdr);
}


static int pma_get_port_counters(struct ib_pma_mad *pmp, struct pib_node *node, u8 port_num)
{
	struct ib_pma_portcounters *p =
		(struct ib_pma_portcounters *)pmp->data;
	struct pib_port_perf *perf; 
	u8 port_select;

	port_select = p->port_select;

	memset(pmp->data, 0, sizeof(pmp->data));

	p->port_select = port_select;
	
	if (pmp->mad_hdr.attr_mod != cpu_to_be16(0)) {
		pmp->mad_hdr.status = PIB_PMA_STATUS_INVALID_ATTRIB_VALUE;
		goto bail;
	}

	/* Base management port is ignore. */
	if ((port_select < node->port_start) || (node->port_count <= port_select)) {
		pmp->mad_hdr.status = PIB_PMA_STATUS_INVALID_ATTRIB_VALUE;
		goto bail;
	}

	perf = &node->ports[port_select - node->port_start].perf;

	p->symbol_error_counter		= cpu_to_be16(get_saturation16(perf->symbol_error_counter));
	p->link_error_recovery_counter	= get_saturation8(perf->link_error_recovery_counter);
	p->link_downed_counter		= get_saturation8(perf->link_downed_counter);
	p->port_rcv_errors		= cpu_to_be16(get_saturation16(perf->rcv_errors));
	p->port_rcv_remphys_errors	= cpu_to_be16(get_saturation16(perf->rcv_remphys_errors));
	p->port_rcv_switch_relay_errors	= cpu_to_be16(get_saturation16(perf->rcv_switch_relay_errors));
	p->port_xmit_discards		= cpu_to_be16(get_saturation16(perf->xmit_discards));
	p->port_xmit_constraint_errors	= get_saturation8(perf->xmit_constraint_errors);
	p->port_rcv_constraint_errors	= get_saturation8(perf->rcv_constraint_errors);

	p->link_overrun_errors		=
		(get_saturation4(perf->local_link_integrity_errors)  << 4) |
		get_saturation4(perf->excessive_buffer_overrun_errors);

	p->vl15_dropped			= cpu_to_be16(get_saturation16(perf->vl15_dropped));
	p->port_xmit_data		= cpu_to_be32(get_saturation32(perf->xmit_data));
	p->port_rcv_data		= cpu_to_be32(get_saturation32(perf->rcv_data));
	p->port_xmit_packets		= cpu_to_be32(get_saturation32(perf->xmit_packets));
	p->port_rcv_packets		= cpu_to_be32(get_saturation32(perf->rcv_packets));
	p->port_xmit_wait		= cpu_to_be32(get_saturation32(perf->xmit_wait));

bail:
	return reply(&pmp->mad_hdr);
}


static int pma_set_port_counters(struct ib_pma_mad *pmp, struct pib_node *node, u8 port_num)
{
	struct ib_pma_portcounters *p =
		(struct ib_pma_portcounters *)pmp->data;
	struct pib_port_perf *perf; 
	u8 port_select;

	port_select = p->port_select;

	memset(pmp->data, 0, sizeof(pmp->data));

	p->port_select = port_select;
	
	if (pmp->mad_hdr.attr_mod != cpu_to_be16(0)) {
		pmp->mad_hdr.status = PIB_PMA_STATUS_INVALID_ATTRIB_VALUE;
		goto bail;
	}

	/* Base management port is ignore. */
	if ((port_select < node->port_start) || (node->port_count <= port_select)) {
		pmp->mad_hdr.status = PIB_PMA_STATUS_INVALID_ATTRIB_VALUE;
		goto bail;
	}

	perf = &node->ports[port_select - node->port_start].perf;

	if (p->counter_select & IB_PMA_SEL_SYMBOL_ERROR)
		perf->symbol_error_counter = be16_to_cpu(p->symbol_error_counter);

	if (p->counter_select & IB_PMA_SEL_LINK_ERROR_RECOVERY)
		perf->link_error_recovery_counter = p->link_error_recovery_counter;

	if (p->counter_select & IB_PMA_SEL_LINK_DOWNED)
		perf->link_downed_counter = p->link_downed_counter;

	if (p->counter_select & IB_PMA_SEL_PORT_RCV_ERRORS)
		perf->rcv_errors = be16_to_cpu(p->port_rcv_errors);

	if (p->counter_select & IB_PMA_SEL_PORT_RCV_REMPHYS_ERRORS)
		perf->rcv_remphys_errors = be16_to_cpu(p->port_rcv_remphys_errors);

	if (p->counter_select & PIB_PMA_SEL_PORT_RCV_SWITCH_RELAY_ERRORS)
		perf->rcv_switch_relay_errors = be16_to_cpu(p->port_rcv_switch_relay_errors);

	if (p->counter_select & IB_PMA_SEL_PORT_XMIT_DISCARDS)
		perf->xmit_discards = be16_to_cpu(p->port_xmit_discards);

	if (p->counter_select & PIB_PMA_SEL_PORT_XMIT_CONSTRAINT_ERRORS)
		perf->xmit_constraint_errors = p->port_xmit_constraint_errors;

	if (p->counter_select & PIB_PMA_SEL_PORT_RCV_CONSTRAINT_ERRORS)
		perf->rcv_constraint_errors = p->port_rcv_constraint_errors;

	if (p->counter_select & IB_PMA_SEL_LOCAL_LINK_INTEGRITY_ERRORS)
		perf->local_link_integrity_errors = (p->link_overrun_errors >> 4) & 0xF;

	if (p->counter_select & IB_PMA_SEL_EXCESSIVE_BUFFER_OVERRUNS)
		perf->excessive_buffer_overrun_errors = (p->link_overrun_errors  & 0xF);

	if (p->counter_select & IB_PMA_SEL_PORT_VL15_DROPPED)
		perf->vl15_dropped = be16_to_cpu(p->vl15_dropped);

	if (p->counter_select & IB_PMA_SEL_PORT_XMIT_DATA)
		perf->xmit_data = be32_to_cpu(p->port_xmit_data);

	if (p->counter_select & IB_PMA_SEL_PORT_RCV_DATA)
		perf->rcv_data = be32_to_cpu(p->port_rcv_data);

	if (p->counter_select & IB_PMA_SEL_PORT_XMIT_PACKETS)
		perf->xmit_packets = be32_to_cpu(p->port_xmit_packets);

	if (p->counter_select & IB_PMA_SEL_PORT_RCV_PACKETS)
		perf->rcv_packets = be32_to_cpu(p->port_rcv_packets);

bail:
	return pma_set_port_counters(pmp, node, port_num);
}


static int pma_get_port_counters_ext(struct ib_pma_mad *pmp, struct pib_node *node, u8 port_num)
{
	struct ib_pma_portcounters_ext *p =
		(struct ib_pma_portcounters_ext *)pmp->data;
	struct pib_port_perf *perf; 
	u8 port_select;

	port_select = p->port_select;

	memset(pmp->data, 0, sizeof(pmp->data));

	p->port_select = port_select;
	
	if (pmp->mad_hdr.attr_mod != cpu_to_be16(0)) {
		pmp->mad_hdr.status = PIB_PMA_STATUS_INVALID_ATTRIB_VALUE;
		goto bail;
	}

	/* Base management port is ignore. */
	if ((port_select < node->port_start) || (node->port_count <= port_select)) {
		pmp->mad_hdr.status = PIB_PMA_STATUS_INVALID_ATTRIB_VALUE;
		goto bail;
	}

	perf = &node->ports[port_select - node->port_start].perf;

	p->port_xmit_data		= cpu_to_be64(perf->xmit_data);
	p->port_rcv_data		= cpu_to_be64(perf->rcv_data);
	p->port_xmit_packets		= cpu_to_be64(perf->xmit_packets);
	p->port_rcv_packets		= cpu_to_be64(perf->rcv_packets);
	p->port_unicast_xmit_packets	= cpu_to_be64(perf->unicast_xmit_packets);
	p->port_unicast_rcv_packets	= cpu_to_be64(perf->unicast_rcv_packets);
	p->port_multicast_xmit_packets	= cpu_to_be64(perf->multicast_xmit_packets);
	p->port_multicast_rcv_packets	= cpu_to_be64(perf->multicast_rcv_packets);

bail:
	return reply(&pmp->mad_hdr);
}


static int pma_set_port_counters_ext(struct ib_pma_mad *pmp, struct pib_node *node, u8 port_num)
{
	struct ib_pma_portcounters_ext *p =
		(struct ib_pma_portcounters_ext *)pmp->data;
	struct pib_port_perf *perf;
	u8 port_select;

	port_select = p->port_select;

	if (pmp->mad_hdr.attr_mod != cpu_to_be16(0)) {
		pmp->mad_hdr.status = PIB_PMA_STATUS_INVALID_ATTRIB_VALUE;
		goto bail;
	}

	/* Base management port is ignore. */
	if ((port_select < node->port_start) || (node->port_count <= port_select)) {
		pmp->mad_hdr.status = PIB_PMA_STATUS_INVALID_ATTRIB_VALUE;
		goto bail;
	}

	perf = &node->ports[port_select - node->port_start].perf;

	if (p->counter_select & IB_PMA_SELX_PORT_XMIT_DATA)
		perf->xmit_data = be64_to_cpu(p->port_xmit_data);

	if (p->counter_select & IB_PMA_SELX_PORT_RCV_DATA)
		perf->rcv_data = be64_to_cpu(p->port_rcv_data);

	if (p->counter_select & IB_PMA_SELX_PORT_XMIT_PACKETS)
		perf->xmit_packets = be64_to_cpu(p->port_xmit_packets);

	if (p->counter_select & IB_PMA_SELX_PORT_RCV_PACKETS)
		perf->rcv_packets = be64_to_cpu(p->port_rcv_packets);

	if (p->counter_select & IB_PMA_SELX_PORT_UNI_XMIT_PACKETS)
		p->port_unicast_xmit_packets = 0;

	if (p->counter_select & IB_PMA_SELX_PORT_UNI_RCV_PACKETS)
		p->port_unicast_rcv_packets = 0;

	if (p->counter_select & IB_PMA_SELX_PORT_MULTI_XMIT_PACKETS)
		p->port_multicast_xmit_packets = 0;

	if (p->counter_select & IB_PMA_SELX_PORT_MULTI_RCV_PACKETS)
		p->port_multicast_rcv_packets = 0;

bail:
	return pma_get_port_counters_ext(pmp, node, port_num);
}
