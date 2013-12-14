/*
 * Copyright (c) 2013 Minoru NAKAMURA <nminoru@nminoru.jp>
 *
 * This code is licenced under the GPL version 2 or BSD license.
 */
#include <linux/module.h>
#include <linux/init.h>

#include <rdma/ib_pack.h>

#include "pib.h"


static const char *str_qp_type[IB_QPT_MAX] = {
	[IB_QPT_SMI]     = "SMI",
	[IB_QPT_GSI]     = "GSI",
	[IB_QPT_RC ]     = "RC",
	[IB_QPT_UC ]     = "UC",
	[IB_QPT_UD ]     = "UD",
	[IB_QPT_XRC_INI] = "XRC_INIT",
	[IB_QPT_XRC_TGT] = "XRC_TGT",
};


static const char *str_qp_state[] = {
	[IB_QPS_RESET]   = "RESET",
	[IB_QPS_INIT ]   = "INIT",
	[IB_QPS_RTR  ]   = "RTR",
	[IB_QPS_RTS  ]   = "RTS",
	[IB_QPS_SQD  ]   = "SQD",
	[IB_QPS_SQE  ]   = "SQE",
	[IB_QPS_ERR  ]   = "ERR",
};


static const char *str_wc_status[] = {
	[IB_WC_SUCCESS]            = "SUCCESS",
	[IB_WC_LOC_LEN_ERR]        = "LOC_LEN_ERR",
	[IB_WC_LOC_QP_OP_ERR]      = "LOC_QP_OP_ERR",
	[IB_WC_LOC_EEC_OP_ERR]     = "LOC_EEC_OP_ERR",
	[IB_WC_LOC_PROT_ERR]       = "LOC_PROT_ERR",
	[IB_WC_WR_FLUSH_ERR]       = "WR_FLUSH_ERR",
	[IB_WC_MW_BIND_ERR]        = "MW_BIND_ERR",
	[IB_WC_BAD_RESP_ERR]       = "BAD_RESP_ERR",
	[IB_WC_LOC_ACCESS_ERR]     = "LOC_ACCESS_ERR",
	[IB_WC_REM_INV_REQ_ERR]    = "REM_INV_REQ_ERR",
	[IB_WC_REM_ACCESS_ERR]     = "REM_ACCESS_ERR",
	[IB_WC_REM_OP_ERR]         = "REM_OP_ERR",
	[IB_WC_RETRY_EXC_ERR]      = "RETRY_EXC_ERR",
	[IB_WC_RNR_RETRY_EXC_ERR]  = "RNR_RETRY_EXC_ERR",
	[IB_WC_LOC_RDD_VIOL_ERR]   = "LOC_RDD_VIOL_ERR",
	[IB_WC_REM_INV_RD_REQ_ERR] = "REM_INV_RD_REQ_ERR",
	[IB_WC_REM_ABORT_ERR]      = "REM_ABORT_ERR",
	[IB_WC_INV_EECN_ERR]       = "INV_EECN_ERR",
	[IB_WC_INV_EEC_STATE_ERR]  = "INV_EEC_STATE_ERR",
	[IB_WC_FATAL_ERR]          = "FATAL_ERR",
	[IB_WC_RESP_TIMEOUT_ERR]   = "RESP_TIMEOUT_ERR",
	[IB_WC_GENERAL_ERR]        = "GENERAL_ERR",
};


#define USEC_TO_JIFFIES(value) \
	((u32)(((value ## ULL) * 1000) / (HZ * 1000ULL)))

static const u32 rnr_nak_timeout[] = {
	[IB_RNR_TIMER_655_36] = USEC_TO_JIFFIES(655360),
	[IB_RNR_TIMER_000_01] = USEC_TO_JIFFIES(    10),
	[IB_RNR_TIMER_000_02] = USEC_TO_JIFFIES(    20),
	[IB_RNR_TIMER_000_03] = USEC_TO_JIFFIES(    30),
	[IB_RNR_TIMER_000_04] = USEC_TO_JIFFIES(    40),
	[IB_RNR_TIMER_000_06] = USEC_TO_JIFFIES(    60),
	[IB_RNR_TIMER_000_08] = USEC_TO_JIFFIES(    80),
	[IB_RNR_TIMER_000_12] = USEC_TO_JIFFIES(   120),
	[IB_RNR_TIMER_000_16] = USEC_TO_JIFFIES(   160),
	[IB_RNR_TIMER_000_24] = USEC_TO_JIFFIES(   240),
	[IB_RNR_TIMER_000_32] = USEC_TO_JIFFIES(   320),
	[IB_RNR_TIMER_000_48] = USEC_TO_JIFFIES(   480),
	[IB_RNR_TIMER_000_64] = USEC_TO_JIFFIES(   640),
	[IB_RNR_TIMER_000_96] = USEC_TO_JIFFIES(   960),
	[IB_RNR_TIMER_001_28] = USEC_TO_JIFFIES(  1280),
	[IB_RNR_TIMER_001_92] = USEC_TO_JIFFIES(  1920),
	[IB_RNR_TIMER_002_56] = USEC_TO_JIFFIES(  2560),
	[IB_RNR_TIMER_003_84] = USEC_TO_JIFFIES(  3840),
	[IB_RNR_TIMER_005_12] = USEC_TO_JIFFIES(  5120),
	[IB_RNR_TIMER_007_68] = USEC_TO_JIFFIES(  7680),
	[IB_RNR_TIMER_010_24] = USEC_TO_JIFFIES( 10240),
	[IB_RNR_TIMER_015_36] = USEC_TO_JIFFIES( 15360),
	[IB_RNR_TIMER_020_48] = USEC_TO_JIFFIES( 20480),
	[IB_RNR_TIMER_030_72] = USEC_TO_JIFFIES( 30720),
	[IB_RNR_TIMER_040_96] = USEC_TO_JIFFIES( 40960),
	[IB_RNR_TIMER_061_44] = USEC_TO_JIFFIES( 61440),
	[IB_RNR_TIMER_081_92] = USEC_TO_JIFFIES( 81920),
	[IB_RNR_TIMER_122_88] = USEC_TO_JIFFIES(122880),
	[IB_RNR_TIMER_163_84] = USEC_TO_JIFFIES(163840),
	[IB_RNR_TIMER_245_76] = USEC_TO_JIFFIES(245760),
	[IB_RNR_TIMER_327_68] = USEC_TO_JIFFIES(327680),
	[IB_RNR_TIMER_491_52] = USEC_TO_JIFFIES(491520),
};


#define NSEC_TO_JIFFIES(value)					\
	((u32)(((value ## ULL) * 1000) / (HZ * 1000000ULL)))

/* IBA Spec. Vol.1 9.7.6.1.3 */
static const u64 local_ack_timeout[] = {
	/* [ 0] is inifinity */
	[ 1] = NSEC_TO_JIFFIES(         8192),
	[ 2] = NSEC_TO_JIFFIES(        16384),
	[ 3] = NSEC_TO_JIFFIES(        32768),
	[ 4] = NSEC_TO_JIFFIES(        65536),
	[ 5] = NSEC_TO_JIFFIES(       131072),
	[ 6] = NSEC_TO_JIFFIES(       262144),
	[ 7] = NSEC_TO_JIFFIES(       524288),
	[ 8] = NSEC_TO_JIFFIES(      1048576),
	[ 9] = NSEC_TO_JIFFIES(      2087152),
	[10] = NSEC_TO_JIFFIES(      4194304),
	[11] = NSEC_TO_JIFFIES(      8388608),
	[12] = NSEC_TO_JIFFIES(     16777216),
	[13] = NSEC_TO_JIFFIES(     33554432),
	[14] = NSEC_TO_JIFFIES(     67108864),
	[15] = NSEC_TO_JIFFIES(    134217728),

	[16] = NSEC_TO_JIFFIES(    268435456),
	[17] = NSEC_TO_JIFFIES(    536870912),
	[18] = NSEC_TO_JIFFIES(   1073741824),
	[19] = NSEC_TO_JIFFIES(   2147483648),
	[20] = NSEC_TO_JIFFIES(   4294967296),
	[21] = NSEC_TO_JIFFIES(   8589934592),
	[22] = NSEC_TO_JIFFIES(  17179869184),
	[23] = NSEC_TO_JIFFIES(  34359738368),
	[24] = NSEC_TO_JIFFIES(  68719476736),
	[25] = NSEC_TO_JIFFIES( 137438953472),
	[26] = NSEC_TO_JIFFIES( 274877906944),
	[27] = NSEC_TO_JIFFIES( 549755813888),
	[28] = NSEC_TO_JIFFIES(1099511627776),
	[29] = NSEC_TO_JIFFIES(2199023255552),
	[30] = NSEC_TO_JIFFIES(4398046511104),
	[31] = NSEC_TO_JIFFIES(8796093022208),
};


enum {
	PIB_STARTING_OPCODE    = 0x1,
	PIB_MIDDLE_OPCODE      = 0x2,
	PIB_ENDING_OPCODE      = 0x4,
	PIB_ACKNOWLEDGE_OPCODE = 0x8
};


static const int attr_OpCode[] = {
	[IB_OPCODE_SEND_FIRST                    ] = PIB_STARTING_OPCODE,
	[IB_OPCODE_SEND_MIDDLE                   ] = PIB_MIDDLE_OPCODE,
	[IB_OPCODE_SEND_LAST                     ] = PIB_ENDING_OPCODE,
	[IB_OPCODE_SEND_LAST_WITH_IMMEDIATE      ] = PIB_ENDING_OPCODE,
	[IB_OPCODE_SEND_ONLY                     ] = PIB_STARTING_OPCODE | PIB_ENDING_OPCODE,
	[IB_OPCODE_SEND_ONLY_WITH_IMMEDIATE      ] = PIB_STARTING_OPCODE | PIB_ENDING_OPCODE,
	[IB_OPCODE_RDMA_WRITE_FIRST              ] = PIB_STARTING_OPCODE,
	[IB_OPCODE_RDMA_WRITE_MIDDLE             ] = PIB_MIDDLE_OPCODE,
	[IB_OPCODE_RDMA_WRITE_LAST               ] = PIB_ENDING_OPCODE,
	[IB_OPCODE_RDMA_WRITE_LAST_WITH_IMMEDIATE] = PIB_ENDING_OPCODE,
	[IB_OPCODE_RDMA_WRITE_ONLY               ] = PIB_STARTING_OPCODE | PIB_ENDING_OPCODE,
	[IB_OPCODE_RDMA_WRITE_ONLY_WITH_IMMEDIATE] = PIB_STARTING_OPCODE | PIB_ENDING_OPCODE,
	[IB_OPCODE_RDMA_READ_REQUEST             ] = PIB_STARTING_OPCODE | PIB_ENDING_OPCODE,
	[IB_OPCODE_COMPARE_SWAP                  ] = PIB_STARTING_OPCODE | PIB_ENDING_OPCODE,
	[IB_OPCODE_FETCH_ADD                     ] = PIB_STARTING_OPCODE | PIB_ENDING_OPCODE,

	[IB_OPCODE_ACKNOWLEDGE                   ] = PIB_ACKNOWLEDGE_OPCODE,
	[IB_OPCODE_RDMA_READ_RESPONSE_FIRST      ] = PIB_ACKNOWLEDGE_OPCODE,
	[IB_OPCODE_RDMA_READ_RESPONSE_MIDDLE     ] = PIB_ACKNOWLEDGE_OPCODE,
	[IB_OPCODE_RDMA_READ_RESPONSE_LAST       ] = PIB_ACKNOWLEDGE_OPCODE,
	[IB_OPCODE_RDMA_READ_RESPONSE_ONLY       ] = PIB_ACKNOWLEDGE_OPCODE,
	[IB_OPCODE_ATOMIC_ACKNOWLEDGE            ] = PIB_ACKNOWLEDGE_OPCODE,
};


u32 pib_random(void)
{
	u32 d1, d2, d3;
	struct timespec tv;

	static u32 count;

	getnstimeofday(&tv);

	d1 = jiffies;
	d2 = (u32)(uintptr_t)current;

	if (1 == cpu_to_be32(1))
		d3 = cpu_to_le32(tv.tv_sec ^ tv.tv_nsec);
	else
		d3 = cpu_to_be32(tv.tv_sec ^ tv.tv_nsec);

	count++;

	return d1 ^ d2 ^ d3 ^ count;
}


const char *pib_get_qp_type(enum ib_qp_type type)
{
	if ((type < IB_QPT_MAX) && str_qp_type[type])
		return str_qp_type[type];
	else
		return "unkonwn";
}


const char *pib_get_qp_state(enum ib_qp_state state)
{
	return str_qp_state[state];
}


const char *pib_get_wc_status(enum ib_wc_status status)
{
	return str_wc_status[status];
}


u32 pib_get_maxium_packet_length(enum ib_mtu mtu)
{
	return 256U << (mtu - IB_MTU_256);
}


int pib_is_recv_ok(enum ib_qp_state state)
{
	switch (state) {

	case IB_QPS_RTR:
	case IB_QPS_RTS:
	case IB_QPS_SQD:
	case IB_QPS_SQE:
		return 1;

	default:
		return 0;
	}
}


int pib_opcode_is_acknowledge(int OpCode)
{
	return (attr_OpCode[OpCode & 0xFF] & PIB_ACKNOWLEDGE_OPCODE) == PIB_ACKNOWLEDGE_OPCODE;
}

enum ib_wc_opcode pib_convert_wr_opcode_to_wc_opcode(enum ib_wr_opcode opcode)
{
	switch (opcode) {
	case IB_WR_RDMA_WRITE:
	case IB_WR_RDMA_WRITE_WITH_IMM:
		return IB_WC_RDMA_WRITE;
	case IB_WR_SEND:
	case IB_WR_SEND_WITH_IMM:
		return IB_WC_SEND;
	case IB_WR_RDMA_READ:
		return IB_WC_RDMA_READ;
	case IB_WR_ATOMIC_CMP_AND_SWP:
		return IB_WC_COMP_SWAP;
	case IB_WR_ATOMIC_FETCH_AND_ADD:
		return IB_WC_FETCH_ADD;
	case IB_WR_LOCAL_INV:
		return IB_WC_LOCAL_INV;
	case IB_WR_LSO:
		return IB_WC_LSO;
	case IB_WR_FAST_REG_MR:
		return IB_WC_FAST_REG_MR;
	case IB_WR_MASKED_ATOMIC_CMP_AND_SWP:
		return IB_WC_MASKED_COMP_SWAP;
	case IB_WR_MASKED_ATOMIC_FETCH_AND_ADD:
		return IB_WC_MASKED_FETCH_ADD;
#if 0
	case IB_WR_BIND_MW:
		return IB_WC_BIND_MW;

	case IB_WR_SEND_WITH_INV,
	case IB_WR_RDMA_READ_WITH_INV:
#endif
	default:
		BUG();
	}
}


int pib_opcode_is_in_order_sequence(int OpCode, int last_OpCode)
{
	int cur_OpCode_attr;

	OpCode      &= 0xFF;
	last_OpCode &= 0xFF;

	cur_OpCode_attr = attr_OpCode[OpCode] ;

	if ((cur_OpCode_attr & (PIB_STARTING_OPCODE | PIB_MIDDLE_OPCODE |PIB_ENDING_OPCODE)) == 0)
		return 0;

	if (cur_OpCode_attr & PIB_STARTING_OPCODE)
		return (attr_OpCode[last_OpCode] & PIB_ENDING_OPCODE);

	switch (OpCode) {

	case IB_OPCODE_SEND_MIDDLE:
	case IB_OPCODE_SEND_LAST:
	case IB_OPCODE_SEND_LAST_WITH_IMMEDIATE:
		if ((last_OpCode == IB_OPCODE_SEND_FIRST) ||
		    (last_OpCode == IB_OPCODE_SEND_MIDDLE))
			return 1;
		break;

	case IB_OPCODE_RDMA_WRITE_MIDDLE:
	case IB_OPCODE_RDMA_WRITE_LAST:
	case IB_OPCODE_RDMA_WRITE_LAST_WITH_IMMEDIATE:
		if ((last_OpCode == IB_OPCODE_RDMA_WRITE_FIRST) || 
		    (last_OpCode == IB_OPCODE_RDMA_WRITE_MIDDLE))
			return 1;
		break;

	default:
		break;
	}

	return 0;
}


u32 pib_get_num_of_packets(struct pib_ib_qp *qp, u32 length)
{
	u32 num_packets;

	num_packets = (length / 128U) >> qp->ib_qp_attr.path_mtu;

	if (num_packets == 0)
		return 1;
	
	if (length > ((num_packets * 128U) << qp->ib_qp_attr.path_mtu))
		num_packets++;

	return num_packets;
}


u32 pib_get_rnr_nak_time(int timeout)
{
	if (rnr_nak_timeout[timeout] == 0)
		return 1;

	return rnr_nak_timeout[timeout];
}


u32 pib_get_local_ack_time(int timeout)
{
	if (timeout == 0)
		return PIB_SCHED_TIMEOUT;

	if (local_ack_timeout[timeout] == 0)
		return 1;

	return local_ack_timeout[timeout];
}
