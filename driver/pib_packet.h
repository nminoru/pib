/*
 * pib_packet.h - Structures of IB packets.
 *
 * Copyright (c) 2013-2015 Minoru NAKAMURA <nminoru@nminoru.jp>
 *
 * This code is licenced under the GPL version 2 or BSD license.
 */
#ifndef PIB_PACKET_H
#define PIB_PACKET_H

#include <linux/module.h>
#include <linux/init.h>
#include <rdma/ib_mad.h>
#include <rdma/ib_smi.h>
#include <rdma/ib_pack.h>


enum {
	PIB_OPCODE_CNP                   = 0x80,
	PIB_OPCODE_CNP_SEND_NOTIFY       = 0x80
};

enum {
	IB_OPCODE_SEND_LAST_WITH_INVALIDATE	    = 0x16,
	IB_OPCODE_SEND_ONLY_WITH_INVALIDATE         = 0x17,

	IB_OPCODE(RC, SEND_LAST_WITH_INVALIDATE),
	IB_OPCODE(RC, SEND_ONLY_WITH_INVALIDATE),
};


/* NAK Codes */
enum pib_syndrome {
	/* Major code (bit[7:5]) */
	PIB_SYND_ACK_CODE                = 0x00, /* ACK                      */
	PIB_SYND_RNR_NAK_CODE            = 0x20, /* RNR NAK                  */
	PIB_SYND_NAK_CODE                = 0x60, /* General NAK except RNR   */

	/* Major code mask */
	PIB_SYND_CODE_MASK		 = 0xE0,

	/* Subcode */
	PIB_SYND_NAK_CODE_PSN_SEQ_ERR    = 0x60, /* PSN Sequence Error       */
	PIB_SYND_NAK_CODE_INV_REQ_ERR    = 0x61, /* Invalid Request          */
	PIB_SYND_NAK_CODE_REM_ACCESS_ERR = 0x62, /* Remote Access Error      */
	PIB_SYND_NAK_CODE_REM_OP_ERR     = 0x63, /* Remote Operational Error */
	PIB_SYND_NAK_CODE_INV_RD_REQ_ERR = 0x64  /* Invalid RD Request       */
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


static inline u16 pib_packet_lrh_get_pktlen(const struct pib_packet_lrh *lrh)
{
	return be16_to_cpu(lrh->pktlen) & 0x7FF;
}


static inline void pib_packet_lrh_set_pktlen(struct pib_packet_lrh *lrh, u16 value)
{
	lrh->pktlen = cpu_to_be16(value & 0x7FF);
}


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


static inline u8 pib_packet_bth_get_solicited(const struct pib_packet_bth *bth)
{
	return (bth->se_m_padcnt_tver >> 7) & 0x1;
}


static inline void pib_packet_bth_set_solicited(struct pib_packet_bth *bth, int solicited)
{
	bth->se_m_padcnt_tver &= ~0x80;
	bth->se_m_padcnt_tver |= ((!!solicited) << 7);
}


/* Datagram Extended Transport Header */
struct pib_packet_deth {
	__be32	qkey;	/* Queue Key */
	__be32	srcQP;	/* Source QP  (The most significant 8-bits must be zero.) */
} __attribute__ ((packed));


/* RDMA Extended Trasnport Header */
struct pib_packet_reth {
	__u64	vaddr;	/* Virtual Address */
	__u32	rkey;	/* Remote Key */
	__u32	dmalen;	/* DMA Length */
} __attribute__ ((packed));


/* Atomic Extended Trasnport Header */
struct pib_packet_atomiceth {
	__u64	vaddr;	/* Virtual Address */
	__u32	rkey;	/* Remote Key */
	__u64	swap_dt;/* Swap (or Add) Data */	
	__u64	cmp_dt;	/* Compare Data */
} __attribute__ ((packed));


/* ACK Extended Transport Header */
struct pib_packet_aeth {
	/*
	 * Syndrome                  8 bits
	 * Message Sequence Number  24 bits
	 */
	__u32	syndrome_msn;
} __attribute__ ((packed));


/* Atomic ACK Extended Transport Header */
struct pib_packet_atomicacketh {
	__u64	orig_rem_dt;	/* Virtual Address */
} __attribute__ ((packed));


/* Invalidate Extended Transport */
struct pib_packet_ieth {
	__u32	rkey;	/* Remote Key */
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


#endif /* PIB_PACKET_H */
