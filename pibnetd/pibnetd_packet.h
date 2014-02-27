/*
 * pibnetd_packet.h
 *
 * Copyright (c) 2014 Minoru NAKAMURA <nminoru@nminoru.jp>
 *
 * This code is licenced under the GPL version 2 or BSD license.
 */
#ifndef _PIBNETD_PACKET_H_
#define _PIBNETD_PACKET_H_

#include <stdint.h>
#include "byteorder.h"

#define PIB_MGMT_BASE_VERSION			(1)
#define PIB_MGMT_CLASS_VERSION			(1)

/* Management classes */
#define PIB_MGMT_CLASS_SUBN_LID_ROUTED		(0x01)
#define PIB_MGMT_CLASS_SUBN_DIRECTED_ROUTE	(0x81)
#define PIB_MGMT_CLASS_SUBN_ADM			(0x03)
#define PIB_MGMT_CLASS_PERF_MGMT		(0x04)

/* Management methods */
#define PIB_MGMT_METHOD_GET			(0x01)
#define PIB_MGMT_METHOD_SET			(0x02)
#define PIB_MGMT_METHOD_GET_RESP		(0x81)
#define PIB_MGMT_METHOD_SEND			(0x03)
#define PIB_MGMT_METHOD_TRAP			(0x05)
#define PIB_MGMT_METHOD_REPORT			(0x06)
#define PIB_MGMT_METHOD_REPORT_RESP		(0x86)
#define PIB_MGMT_METHOD_TRAP_REPRESS		(0x07)

#define PIB_SMP_UNSUP_VERSION    		cpu_to_be16(0x0004)
#define PIB_SMP_UNSUP_METHOD     		cpu_to_be16(0x0008)
#define PIB_SMP_UNSUP_METH_ATTR  		cpu_to_be16(0x000C)
#define PIB_SMP_INVALID_FIELD    		cpu_to_be16(0x001C)

#define PIB_SMP_DIRECTION			cpu_to_be16(0x8000)

/* Subnet management attributes */
#define PIB_SMP_ATTR_NOTICE			(0x0002)
#define PIB_SMP_ATTR_NODE_DESC			(0x0010)
#define PIB_SMP_ATTR_NODE_INFO			(0x0011)
#define PIB_SMP_ATTR_SWITCH_INFO		(0x0012)
#define PIB_SMP_ATTR_GUID_INFO			(0x0014)
#define PIB_SMP_ATTR_PORT_INFO			(0x0015)
#define PIB_SMP_ATTR_PKEY_TABLE			(0x0016)
#define PIB_SMP_ATTR_SL_TO_VL_TABLE		(0x0017)
#define PIB_SMP_ATTR_VL_ARB_TABLE		(0x0018)
#define PIB_SMP_ATTR_LINEAR_FORWARD_TABLE	(0x0019)
#define PIB_SMP_ATTR_RANDOM_FORWARD_TABLE	(0x001A)
#define PIB_SMP_ATTR_MCAST_FORWARD_TABLE	(0x001B)
#define PIB_SMP_ATTR_SM_INFO			(0x0020)
#define PIB_SMP_ATTR_VENDOR_DIAG		(0x0030)
#define PIB_SMP_ATTR_LED_INFO			(0x0031)
#define PIB_SMP_ATTR_VENDOR_MASK		(0xFF00)


enum pib_smp_result {
	PIB_SMP_RESULT_FAILURE  = 0,      /* (!SUCCESS is the important flag) */
	PIB_SMP_RESULT_SUCCESS  = 1 << 0, /* MAD was successfully processed   */
	PIB_SMP_RESULT_REPLY    = 1 << 1, /* Reply packet needs to be sent    */
	PIB_SMP_RESULT_CONSUMED = 1 << 2  /* Packet consumed: stop processing */
};


/* Local Route Header */
struct pib_packet_lrh {
	__be16	dlid;

	/*
	 * Virtual Lane      4 bits
	 * Link Version      4 bits
	 */
	u8	vl_lver;

	/*
	 * Service Level     4 bits
	 * Reserved          2 bits
	 * Link Next Header  2 bits
	 */
	u8	sl_rsv_lnh;

	__be16	slid;

	/*
	 * Reserved          5 bits
	 * Packet Length    11 bits
	 */
	__be16  pktlen;

} __attribute__ ((packed));


static inline u8 pib_packet_lrh_get_pktlen(const struct pib_packet_lrh *lrh)
{
	return be16_to_cpu(lrh->pktlen) & 0x7FF;
}


static inline void pib_packet_lrh_set_pktlen(struct pib_packet_lrh *lrh, u8 value)
{
	lrh->pktlen = cpu_to_be16(value & 0x7FF);
}


struct pib_grh {
	__be32		version_tclass_flow;
	__be16		paylen;
	u8		next_hdr;
	u8		hop_limit;
	union ibv_gid	sgid;
	union ibv_gid	dgid;
} __attribute__ ((packed));


/* Base Transport Header */
struct pib_packet_bth {
	u8	OpCode;	/* Opcode */
	
	/*
	 * Solicited Event          1 bit
	 * MigReq                   1 bit
	 * Pad Count                2 bits
	 * Transport Header Version 4 bits
	 */
	u8	se_m_padcnt_tver;

	__be16	pkey;	/* Partition Key */
	__be32	destQP;	/* Destinatino QP (The most significant 8-bits must be zero.) */
	__be32	psn;	/* Packet Sequence Number (The MSB is A bit) */
} __attribute__ ((packed));


static inline u8 pib_packet_bth_get_padcnt(const struct pib_packet_bth *bth)
{
	return (bth->se_m_padcnt_tver >> 4) & 0x3;
}


static inline void pib_packet_bth_set_padcnt(struct pib_packet_bth *bth, u8 padcnt)
{
	bth->se_m_padcnt_tver &= ~0x30;
	bth->se_m_padcnt_tver |= ((padcnt & 0x3) << 4);
}


/* Datagram Extended Transport Header */
struct pib_packet_deth {
	__be32	qkey;	/* Queue Key */
	__be32	srcQP;	/* Source QP  (The most significant 8-bits must be zero.) */
} __attribute__ ((packed));


struct pib_mad_hdr {
	u8	base_version;
	u8	mgmt_class;
	u8	class_version;
	u8	method;
	__be16	status;
	__be16	class_specific;
	__be64	tid;
	__be16	attr_id;
	__be16	resv;
	__be32	attr_mod;
};


enum {
	PIB_MGMT_MAD_DATA = 232
};


struct pib_mad {
	struct pib_mad_hdr	mad_hdr;
	u8			data[PIB_MGMT_MAD_DATA];
};


enum {
	PIB_SMP_DATA_SIZE	= 64,
	PIB_SMP_MAX_PATH_HOPS	= 64
};


struct pib_smp {
	u8	base_version;
	u8	mgmt_class;
	u8	class_version;
	u8	method;
	__be16	status;
	u8	hop_ptr;
	u8	hop_cnt;
	__be64	tid;
	__be16	attr_id;
	__be16	resv;
	__be32	attr_mod;
	__be64	mkey;
	__be16	dr_slid;
	__be16	dr_dlid;
	u8	reserved[28];
	u8	data[PIB_SMP_DATA_SIZE];
	u8	initial_path[PIB_SMP_MAX_PATH_HOPS];
	u8	return_path[PIB_SMP_MAX_PATH_HOPS];
} __attribute__ ((packed));


struct pib_pma_mad {
	struct pib_mad_hdr mad_hdr;
	u8 reserved[40];
	u8 data[192];
} __packed;


struct pib_smp_node_info {
	u8	base_version;
	u8	class_version;
	u8	node_type;
	u8	node_ports;
	__be64	sys_image_guid;
	__be64	node_guid;
	__be64	port_guid;
	__be16	partition_cap;
	__be16	device_id;
	__be32	revision;
	u8	local_port_num;
	u8	vendor_id[3];
} __attribute__ ((packed));


struct pib_smp_switch_info {
	__be16  linear_fdb_cap;
	__be16  random_fdb_cap;
	__be16  multicast_fdb_cap;
	__be16  linear_fdb_top;
	u8      default_port;
	u8      default_mcast_primary_port;
	u8      default_mcast_not_primary_port;

	/*
	 * LifeTimeValue          5 bits
	 * PortStateChange        1 bit
	 * OptimizedSLtoVLMappingProgramming 2bits
	 */
	u8      various1;

	__be16  lids_per_port;
	__be16  partition_enforcement_cap;

	/*
	 * InboundEnforcementCap  1 bit
	 * OutboundEnforcementCap 1 bit
	 * FilterRawInboundCap    1 bit
	 * EnhancedPort0          1 bit
	 * Reserved               3 bits
	 */
	u8      various2;
} __attribute__ ((packed));


struct pib_packet_link {
	__be32	cmd;
} __attribute__ ((packed));


union pib_packet_footer {
	struct {
		__be16	vcrc; /* Variant CRC */
	} native;
	struct {
		__be64	port_guid;
	} pib;
} __attribute__ ((packed));


struct pib_port_info {
	__be64 mkey;
	__be64 gid_prefix;
	__be16 lid;
	__be16 sm_lid;
	__be32 cap_mask;
	__be16 diag_code;
	__be16 mkey_lease_period;
	u8 local_port_num;
	u8 link_width_enabled;
	u8 link_width_supported;
	u8 link_width_active;
	u8 linkspeed_portstate;			/* 4 bits, 4 bits */
	u8 portphysstate_linkdown;		/* 4 bits, 4 bits */
	u8 mkeyprot_resv_lmc;			/* 2 bits, 3, 3 */
	u8 linkspeedactive_enabled;		/* 4 bits, 4 bits */
	u8 neighbormtu_mastersmsl;		/* 4 bits, 4 bits */
	u8 vlcap_inittype;			/* 4 bits, 4 bits */
	u8 vl_high_limit;
	u8 vl_arb_high_cap;
	u8 vl_arb_low_cap;
	u8 inittypereply_mtucap;		/* 4 bits, 4 bits */
	u8 vlstallcnt_hoqlife;			/* 3 bits, 5 bits */
	u8 operationalvl_pei_peo_fpi_fpo;	/* 4 bits, 1, 1, 1, 1 */
	__be16 mkey_violations;
	__be16 pkey_violations;
	__be16 qkey_violations;
	u8 guid_cap;
	u8 clientrereg_resv_subnetto;		/* 1 bit, 2 bits, 5 */
	u8 resv_resptimevalue;			/* 3 bits, 5 bits */
	u8 localphyerrors_overrunerrors;	/* 4 bits, 4 bits */
	__be16 max_credit_hint;
	u8 resv;
	u8 link_roundtrip_latency[3];
};


struct pib_trap {
	/*
	 * - IsGeneric
	 * - Type
	 * - ProducerType / VendorID
	 */
	__be32 generice_type_prodtype; /* 1 bit, 7 bits, 24 bits */
	__be16 trapnum;

	/* IssuerLID */
	__be16 issuerlid;

	/*
	 * - NoticeToggle
	 * - NoticeCount
	 */	
	__be16 toggle_count;  /* 1bit, 15 bits */

	union {
		struct {
			u8 details[54];
		} raw_data;

		struct {
			__be16	lidaddr;
		} __attribute__ ((packed)) ntc_128;
	} details;
};

#endif /* _PIBNETD_PACKET_H_ */
