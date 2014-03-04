/*
 * perf.c - Performance Management Agent
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

#define PIB_PMA_CLASS_VERSION			(1)

#define PIB_PMA_STATUS_BAD_VERSION		(0x1 << 2)
#define PIB_PMA_STATUS_UNSUPPORTED_METHOD	(0x2 << 2) /* discard response ? */
#define PIB_PMA_STATUS_UNSUPPORTED_METHOD_ATTRIB	(0x3 << 2)
#define PIB_PMA_STATUS_INVALID_ATTRIB_VALUE	(0x7 << 2)

#define PIB_PMA_CLASS_CAP_ALLPORTSELECT  cpu_to_be16(1 << 8)
#define PIB_PMA_CLASS_CAP_EXT_WIDTH      cpu_to_be16(1 << 9)
#define PIB_PMA_CLASS_CAP_XMIT_WAIT      cpu_to_be16(1 << 12)

#define PIB_PMA_CLASS_PORT_INFO			(0x0001)
#define PIB_PMA_PORT_SAMPLES_CONTROL		(0x0010)
#define PIB_PMA_PORT_SAMPLES_RESULT		(0x0011)
#define PIB_PMA_PORT_COUNTERS			(0x0012)
#define PIB_PMA_PORT_COUNTERS_EXT		(0x001D)
#define PIB_PMA_PORT_SAMPLES_RESULT_EXT		(0x001E)

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

#define PIB_PMA_SEL_SYMBOL_ERROR                 cpu_to_be16(0x0001)
#define PIB_PMA_SEL_LINK_ERROR_RECOVERY          cpu_to_be16(0x0002)
#define PIB_PMA_SEL_LINK_DOWNED                  cpu_to_be16(0x0004)
#define PIB_PMA_SEL_PORT_RCV_ERRORS              cpu_to_be16(0x0008)
#define PIB_PMA_SEL_PORT_RCV_REMPHYS_ERRORS      cpu_to_be16(0x0010)
#define PIB_PMA_SEL_PORT_XMIT_DISCARDS           cpu_to_be16(0x0040)
#define PIB_PMA_SEL_LOCAL_LINK_INTEGRITY_ERRORS  cpu_to_be16(0x0200)
#define PIB_PMA_SEL_EXCESSIVE_BUFFER_OVERRUNS    cpu_to_be16(0x0400)
#define PIB_PMA_SEL_PORT_VL15_DROPPED            cpu_to_be16(0x0800)
#define PIB_PMA_SEL_PORT_XMIT_DATA               cpu_to_be16(0x1000)
#define PIB_PMA_SEL_PORT_RCV_DATA                cpu_to_be16(0x2000)
#define PIB_PMA_SEL_PORT_XMIT_PACKETS            cpu_to_be16(0x4000)
#define PIB_PMA_SEL_PORT_RCV_PACKETS             cpu_to_be16(0x8000)
#define PIB_PMA_SEL_PORT_RCV_SWITCH_RELAY_ERRORS	cpu_to_be16(0x0020)
#define PIB_PMA_SEL_PORT_XMIT_CONSTRAINT_ERRORS	cpu_to_be16(0x0080)
#define PIB_PMA_SEL_PORT_RCV_CONSTRAINT_ERRORS	cpu_to_be16(0x0100)
#define PIB_PMA_SELX_PORT_XMIT_DATA              cpu_to_be16(0x0001)
#define PIB_PMA_SELX_PORT_RCV_DATA               cpu_to_be16(0x0002)
#define PIB_PMA_SELX_PORT_XMIT_PACKETS           cpu_to_be16(0x0004)
#define PIB_PMA_SELX_PORT_RCV_PACKETS            cpu_to_be16(0x0008)
#define PIB_PMA_SELX_PORT_UNI_XMIT_PACKETS       cpu_to_be16(0x0010)
#define PIB_PMA_SELX_PORT_UNI_RCV_PACKETS        cpu_to_be16(0x0020)
#define PIB_PMA_SELX_PORT_MULTI_XMIT_PACKETS     cpu_to_be16(0x0040)
#define PIB_PMA_SELX_PORT_MULTI_RCV_PACKETS      cpu_to_be16(0x0080)


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


static int reply(struct pib_mad_hdr *mad_hdr)
{
	mad_hdr->method = PIB_MGMT_METHOD_GET_RESP;

	return PIB_MAD_RESULT_SUCCESS | PIB_MAD_RESULT_REPLY;
}


static int reply_failure(struct pib_mad_hdr *mad_hdr)
{
	mad_hdr->method = PIB_MGMT_METHOD_GET_RESP;

	return PIB_MAD_RESULT_FAILURE | PIB_MAD_RESULT_REPLY;
}


static int pma_get_method(struct pib_pma_mad *pmp, struct pib_switch *sw, u8 port_num);
static int pma_set_method(struct pib_pma_mad *pmp, struct pib_switch *sw, u8 port_num);
static int pma_get_class_port_info(struct pib_pma_mad *pmp, struct pib_switch *sw, u8 port_num);
static int pma_get_port_samples_control(struct pib_pma_mad *pmp, struct pib_switch *sw, u8 port_num);
static int pma_set_port_samples_control(struct pib_pma_mad *pmp, struct pib_switch *sw, u8 port_num);
static int pma_get_port_samples_result(struct pib_pma_mad *pmp, struct pib_switch *sw, u8 port_num);
static int pma_get_port_samples_result_ext(struct pib_pma_mad *pmp, struct pib_switch *sw, u8 port_num);
static int pma_get_port_counters(struct pib_pma_mad *pmp, struct pib_switch *sw, u8 port_num);
static int pma_set_port_counters(struct pib_pma_mad *pmp, struct pib_switch *sw, u8 port_num);
static int pma_get_port_counters_ext(struct pib_pma_mad *pmp, struct pib_switch *sw, u8 port_num);
static int pma_set_port_counters_ext(struct pib_pma_mad *pmp, struct pib_switch *sw, u8 port_num);


int pib_process_pma_mad(struct pib_pma_mad *pmp, struct pib_switch *sw, uint8_t port_num)
{
	int ret;

	if ((pmp->mad_hdr.base_version  != PIB_MGMT_BASE_VERSION) ||
	    (pmp->mad_hdr.class_version != PIB_PMA_CLASS_VERSION)) {
		pmp->mad_hdr.status = PIB_PMA_STATUS_BAD_VERSION;
		return reply(&pmp->mad_hdr);
	}

	switch (pmp->mad_hdr.method) {

	case PIB_MGMT_METHOD_GET:
		ret = pma_get_method(pmp, sw, port_num);
		break;

	case PIB_MGMT_METHOD_SET:
		ret = pma_set_method(pmp, sw, port_num);
		break;

	case PIB_MGMT_METHOD_TRAP:
	case PIB_MGMT_METHOD_GET_RESP:
		pib_report_debug("pibnet: pib_process_pma_mad: %u %u",
			       pmp->mad_hdr.method, be16_to_cpu(pmp->mad_hdr.attr_id));
		ret = reply(&pmp->mad_hdr);
		break;

	default:
		pib_report_err("pibnet: pib_process_pma_mad: %u %u",
			       pmp->mad_hdr.method, be16_to_cpu(pmp->mad_hdr.attr_id));
		ret = reply_failure(&pmp->mad_hdr);
		break;
	}

	return ret;
}


static int pma_get_method(struct pib_pma_mad *pmp, struct pib_switch *sw, u8 port_num)
{
	uint16_t attr_id;

	attr_id = be16_to_cpu(pmp->mad_hdr.attr_id);

	switch (attr_id) {

	case PIB_PMA_CLASS_PORT_INFO:
		return pma_get_class_port_info(pmp, sw, port_num);

	case PIB_PMA_PORT_SAMPLES_CONTROL:
		return pma_get_port_samples_control(pmp, sw, port_num);

	case PIB_PMA_PORT_SAMPLES_RESULT:
		return pma_get_port_samples_result(pmp, sw, port_num);

	case PIB_PMA_PORT_SAMPLES_RESULT_EXT:
		return pma_get_port_samples_result_ext(pmp, sw, port_num);

	case PIB_PMA_PORT_COUNTERS:
		return pma_get_port_counters(pmp, sw, port_num);

	case PIB_PMA_PORT_COUNTERS_EXT:
		return pma_get_port_counters_ext(pmp, sw, port_num);

	default:
		pib_report_err("pibnet: PerformanceGet() attr_id=0x%04x", attr_id);
		pmp->mad_hdr.status = PIB_PMA_STATUS_UNSUPPORTED_METHOD_ATTRIB;
		return reply_failure(&pmp->mad_hdr);
	}
}


static int pma_set_method(struct pib_pma_mad *pmp, struct pib_switch *sw, u8 port_num)
{
	uint16_t attr_id;

	attr_id = be16_to_cpu(pmp->mad_hdr.attr_id);

	switch (attr_id) {

	case PIB_PMA_PORT_SAMPLES_CONTROL:
		return pma_set_port_samples_control(pmp, sw, port_num);

#if 0
	case PIB_PMA_PORT_SAMPLES_RESULT_EXT:
		return pma_set_port_samples_result_ext(pmp, sw, port_num);
#endif

	case PIB_PMA_PORT_COUNTERS:
		return pma_set_port_counters(pmp, sw, port_num);

	case PIB_PMA_PORT_COUNTERS_EXT:
		return pma_set_port_counters_ext(pmp, sw, port_num);

	default:
		pib_report_err("pibnet: PerformanceGet() attr_id=0x%04x", attr_id);
		pmp->mad_hdr.status = PIB_PMA_STATUS_UNSUPPORTED_METHOD_ATTRIB;
		return reply_failure(&pmp->mad_hdr);
	}
}


static int pma_get_class_port_info(struct pib_pma_mad *pmp, struct pib_switch *sw, u8 port_num)
{
	struct pib_class_port_info *info =
		(struct pib_class_port_info *)pmp->data;

	memset(pmp->data, 0, sizeof(pmp->data));

	if (pmp->mad_hdr.attr_mod != cpu_to_be16(0)) {
		pmp->mad_hdr.status = PIB_PMA_STATUS_INVALID_ATTRIB_VALUE;
		goto bail;
	}

	info->base_version    = PIB_MGMT_BASE_VERSION;
	info->class_version   = PIB_PMA_CLASS_VERSION;
	info->capability_mask = PIB_PMA_CLASS_CAP_EXT_WIDTH;

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


static int pma_get_port_samples_control(struct pib_pma_mad *pmp, struct pib_switch *sw, u8 port_num)
{
	int i;
	struct pib_pma_portsamplescontrol *p =
		(struct pib_pma_portsamplescontrol *)pmp->data;
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
	if ((port_select < 0) || (sw->port_cnt <= port_select)) {
		pmp->mad_hdr.status = PIB_PMA_STATUS_INVALID_ATTRIB_VALUE;
		goto bail;
	}

	perf = &sw->ports[port_select].perf;

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


static int pma_set_port_samples_control(struct pib_pma_mad *pmp, struct pib_switch *sw, u8 port_num)
{
	int i;
	struct pib_pma_portsamplescontrol *p =
		(struct pib_pma_portsamplescontrol *)pmp->data;
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
	if ((port_select < 0) || (sw->port_cnt <= port_select)) {
		pmp->mad_hdr.status = PIB_PMA_STATUS_INVALID_ATTRIB_VALUE;
		goto bail;
	}

	perf = &sw->ports[port_select].perf;

	perf->OpCode	= p->opcode;
	perf->tag	= be16_to_cpu(p->tag);

#if 0
	p->sample_start      = cpu_to_be32();
	p->sample_interval   = cpu_to_be32();
#endif

	for (i=0 ; i<ARRAY_SIZE(p->counter_select) ; i++)
		perf->counter_select[i] = be16_to_cpu(p->counter_select[i]);

bail:
	return pma_get_port_samples_control(pmp, sw, port_num);
}


static int pma_get_port_samples_result(struct pib_pma_mad *pmp, struct pib_switch *sw, u8 port_num)
{
	int i;
	struct pib_pma_portsamplesresult *p =
		(struct pib_pma_portsamplesresult *)pmp->data;
	struct pib_port_perf *perf; 

	memset(pmp->data, 0, sizeof(pmp->data));

	if (pmp->mad_hdr.attr_mod != cpu_to_be16(0)) {
		pmp->mad_hdr.status = PIB_PMA_STATUS_INVALID_ATTRIB_VALUE;
		goto bail;
	}

	perf = &sw->ports[port_num].perf;

	p->tag           = cpu_to_be16(perf->tag);
	p->sample_status = PIB_PMA_SAMPLE_STATUS_DONE;

	for (i=0 ; i<ARRAY_SIZE(p->counter) ; i++)
		p->counter[i] = cpu_to_be32((u32)perf->counter[i]);

bail:
	return reply(&pmp->mad_hdr);
}


static int pma_get_port_samples_result_ext(struct pib_pma_mad *pmp, struct pib_switch *sw, u8 port_num)
{
	int i;
	struct pib_pma_portsamplesresult_ext *p = 
		(struct pib_pma_portsamplesresult_ext *)pmp->data;
	struct pib_port_perf *perf; 

	memset(pmp->data, 0, sizeof(pmp->data));

	if (pmp->mad_hdr.attr_mod != cpu_to_be16(0)) {
		pmp->mad_hdr.status = PIB_PMA_STATUS_INVALID_ATTRIB_VALUE;
		goto bail;
	}

	perf = &sw->ports[port_num].perf;

	p->tag            = cpu_to_be16(perf->tag);
	p->sample_status  = cpu_to_be16(PIB_PMA_SAMPLE_STATUS_DONE);
	p->extended_width = cpu_to_be32(0x80000000); /* 64 bits counter */

	for (i=0 ; i<ARRAY_SIZE(p->counter) ; i++)
		p->counter[i] = cpu_to_be64(perf->counter[i]);

bail:
	return reply(&pmp->mad_hdr);
}


static int pma_get_port_counters(struct pib_pma_mad *pmp, struct pib_switch *sw, u8 port_num)
{
	struct pib_pma_portcounters *p =
		(struct pib_pma_portcounters *)pmp->data;
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
	if ((port_select < 0) || (sw->port_cnt <= port_select)) {
		pmp->mad_hdr.status = PIB_PMA_STATUS_INVALID_ATTRIB_VALUE;
		goto bail;
	}

	perf = &sw->ports[port_select].perf;

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


static int pma_set_port_counters(struct pib_pma_mad *pmp, struct pib_switch *sw, u8 port_num)
{
	struct pib_pma_portcounters *p =
		(struct pib_pma_portcounters *)pmp->data;
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
	if ((port_select < 0) || (sw->port_cnt <= port_select)) {
		pmp->mad_hdr.status = PIB_PMA_STATUS_INVALID_ATTRIB_VALUE;
		goto bail;
	}

	perf = &sw->ports[port_select].perf;

	if (p->counter_select & PIB_PMA_SEL_SYMBOL_ERROR)
		perf->symbol_error_counter = be16_to_cpu(p->symbol_error_counter);

	if (p->counter_select & PIB_PMA_SEL_LINK_ERROR_RECOVERY)
		perf->link_error_recovery_counter = p->link_error_recovery_counter;

	if (p->counter_select & PIB_PMA_SEL_LINK_DOWNED)
		perf->link_downed_counter = p->link_downed_counter;

	if (p->counter_select & PIB_PMA_SEL_PORT_RCV_ERRORS)
		perf->rcv_errors = be16_to_cpu(p->port_rcv_errors);

	if (p->counter_select & PIB_PMA_SEL_PORT_RCV_REMPHYS_ERRORS)
		perf->rcv_remphys_errors = be16_to_cpu(p->port_rcv_remphys_errors);

	if (p->counter_select & PIB_PMA_SEL_PORT_RCV_SWITCH_RELAY_ERRORS)
		perf->rcv_switch_relay_errors = be16_to_cpu(p->port_rcv_switch_relay_errors);

	if (p->counter_select & PIB_PMA_SEL_PORT_XMIT_DISCARDS)
		perf->xmit_discards = be16_to_cpu(p->port_xmit_discards);

	if (p->counter_select & PIB_PMA_SEL_PORT_XMIT_CONSTRAINT_ERRORS)
		perf->xmit_constraint_errors = p->port_xmit_constraint_errors;

	if (p->counter_select & PIB_PMA_SEL_PORT_RCV_CONSTRAINT_ERRORS)
		perf->rcv_constraint_errors = p->port_rcv_constraint_errors;

	if (p->counter_select & PIB_PMA_SEL_LOCAL_LINK_INTEGRITY_ERRORS)
		perf->local_link_integrity_errors = (p->link_overrun_errors >> 4) & 0xF;

	if (p->counter_select & PIB_PMA_SEL_EXCESSIVE_BUFFER_OVERRUNS)
		perf->excessive_buffer_overrun_errors = (p->link_overrun_errors  & 0xF);

	if (p->counter_select & PIB_PMA_SEL_PORT_VL15_DROPPED)
		perf->vl15_dropped = be16_to_cpu(p->vl15_dropped);

	if (p->counter_select & PIB_PMA_SEL_PORT_XMIT_DATA)
		perf->xmit_data = be32_to_cpu(p->port_xmit_data);

	if (p->counter_select & PIB_PMA_SEL_PORT_RCV_DATA)
		perf->rcv_data = be32_to_cpu(p->port_rcv_data);

	if (p->counter_select & PIB_PMA_SEL_PORT_XMIT_PACKETS)
		perf->xmit_packets = be32_to_cpu(p->port_xmit_packets);

	if (p->counter_select & PIB_PMA_SEL_PORT_RCV_PACKETS)
		perf->rcv_packets = be32_to_cpu(p->port_rcv_packets);

bail:
	return pma_set_port_counters(pmp, sw, port_num);
}


static int pma_get_port_counters_ext(struct pib_pma_mad *pmp, struct pib_switch *sw, u8 port_num)
{
	struct pib_pma_portcounters_ext *p =
		(struct pib_pma_portcounters_ext *)pmp->data;
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
	if ((port_select < 0) || (sw->port_cnt <= port_select)) {
		pmp->mad_hdr.status = PIB_PMA_STATUS_INVALID_ATTRIB_VALUE;
		goto bail;
	}

	perf = &sw->ports[port_select].perf;

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


static int pma_set_port_counters_ext(struct pib_pma_mad *pmp, struct pib_switch *sw, u8 port_num)
{
	struct pib_pma_portcounters_ext *p =
		(struct pib_pma_portcounters_ext *)pmp->data;
	struct pib_port_perf *perf;
	u8 port_select;

	port_select = p->port_select;

	if (pmp->mad_hdr.attr_mod != cpu_to_be16(0)) {
		pmp->mad_hdr.status = PIB_PMA_STATUS_INVALID_ATTRIB_VALUE;
		goto bail;
	}

	/* Base management port is ignore. */
	if ((port_select < 0) || (sw->port_cnt <= port_select)) {
		pmp->mad_hdr.status = PIB_PMA_STATUS_INVALID_ATTRIB_VALUE;
		goto bail;
	}

	perf = &sw->ports[port_select].perf;

	if (p->counter_select & PIB_PMA_SELX_PORT_XMIT_DATA)
		perf->xmit_data = be64_to_cpu(p->port_xmit_data);

	if (p->counter_select & PIB_PMA_SELX_PORT_RCV_DATA)
		perf->rcv_data = be64_to_cpu(p->port_rcv_data);

	if (p->counter_select & PIB_PMA_SELX_PORT_XMIT_PACKETS)
		perf->xmit_packets = be64_to_cpu(p->port_xmit_packets);

	if (p->counter_select & PIB_PMA_SELX_PORT_RCV_PACKETS)
		perf->rcv_packets = be64_to_cpu(p->port_rcv_packets);

	if (p->counter_select & PIB_PMA_SELX_PORT_UNI_XMIT_PACKETS)
		p->port_unicast_xmit_packets = 0;

	if (p->counter_select & PIB_PMA_SELX_PORT_UNI_RCV_PACKETS)
		p->port_unicast_rcv_packets = 0;

	if (p->counter_select & PIB_PMA_SELX_PORT_MULTI_XMIT_PACKETS)
		p->port_multicast_xmit_packets = 0;

	if (p->counter_select & PIB_PMA_SELX_PORT_MULTI_RCV_PACKETS)
		p->port_multicast_rcv_packets = 0;

bail:
	return pma_get_port_counters_ext(pmp, sw, port_num);
}
