/*
 * Copyright (c) 2013 Minoru NAKAMURA <nminoru@nminoru.jp>
 *
 * This code is licenced under the GPL version 2 or BSD license.
 */
#ifndef PIB_PACKET_H
#define PIB_PACKET_H

#include <linux/module.h>
#include <linux/init.h>

#include <rdma/ib_mad.h>
#include <rdma/ib_smi.h>


/* NAK Codes */
enum pib_ib_syndrome {
	PIB_IB_ACK_CODE                = 0x00, /* ACK                      */
	PIB_IB_RNR_NAK_CODE            = 0x20, /* RNR NAK                  */
	PIB_IB_NAK_CODE_PSN_SEQ_ERR    = 0x60, /* PSN Sequence Error       */
	PIB_IB_NAK_CODE_INV_REQ_ERR    = 0x61, /* Invalid Request          */
	PIB_IB_NAK_CODE_REM_ACCESS_ERR = 0x62, /* Remote Access Error      */
	PIB_IB_NAK_CODE_REM_OP_ERR     = 0x63, /* Remote Operational Error */
	PIB_IB_NAK_CODE_INV_RD_REQ_ERR = 0x64  /* Invalid RD Request       */
};


/* Local Route Header */
struct pib_packet_lrh {
	u32 DLID   : 16;
	u32 LNH    :  2; /* Link Next Header */
	u32        :  2;
	u32 SL     :  4; /* Service Level */
	u32 LVer   :  4; /* Llink Version */
	u32 VL     :  4; /* Virtual Lane */

	u32 SLID   : 16;
	u32 PktLen : 11; /* Packet Length */
	u32        :  5;
};


/* Base Transport Header */
struct pib_packet_bth {

	u32 P_Key  : 16; /* Partition Key */
	u32 TVer   :  4; /* Transport Header Version */
	u32 PadCnt :  2; /* Pad Count */
	u32 M      :  1; /* MigReq */
	u32 SE     :  1; /* Solicited Event */
	u32 OpCode :  8; /* Opcode */

	u32 DestQP;      /* Destinatino QP (The most significant 8-bits must be zero.) */

	u32 PSN    : 24; /* Packet Sequence Number */
	u32        :  7;
	u32 A      :  1; /* Acknowledge Request */
};


/* Datagram Extended Transport Header */
struct pib_packet_deth {
	u32 Q_Key;       /* Queue Key */

	u32 SrcQP;       /* Source QP  (The most significant 8-bits must be zero.) */
};


/* RDMA Extended Trasnport Header */
struct pib_packet_reth {
	u32 VA_hi;      /* Virtual Address (high) */

	u32 VA_lo;      /* Virtual Address (low) */

	u32 R_Key;      /* Remote Key */

	u32 DMALen;     /* DMA Length */
};


/* Atomic Extended Trasnport Header */
struct pib_packet_atomiceth {
	u32 VA_hi;      /* Virtual Address [high] */

	u32 VA_lo;      /* Virtual Address [low] */

	u32 R_Key;      /* Remote Key */

	u32 SwapDt_hi;  /* Swap (or Add) Data [high] */

	u32 SwapDt_lo;  /* Swap (or Add) Data [low] */

	u32 CmpDt_hi;   /* Compare Data [high] */

	u32 CmpDt_lo;   /* Compare Data [low] */
};


/* ACK Extended Transport Header */
struct pib_packet_aeth {
	u32 MSN      : 24; /* Message Sequence Number */
	u32 Syndrome :  8; /* Syndrome */ 
};


/* Atomic ACK Extended Transport Header */
struct pib_packet_atomicacketh {
	u32 OrigRemDt_hi;
	u32 OrigRemDt_lo;
};


struct pib_packet_ud_request {
	struct pib_packet_lrh   lrh;
	struct pib_packet_bth   bth;
	struct pib_packet_deth  deth;
};


struct pib_packet_rc_request {
	struct pib_packet_lrh   lrh;
	struct pib_packet_bth   bth;
};


struct pib_packet_rc_acknowledge {
	struct pib_packet_lrh   lrh;
	struct pib_packet_bth   bth;
	struct pib_packet_aeth  aeth;
};


struct pib_packet_mad {
	struct pib_packet_lrh   lrh;
	struct pib_packet_bth   bth;
	struct pib_packet_deth  deth;
	struct ib_mad		mad;
};


struct pib_packet_smp {
	struct pib_packet_lrh   lrh;
	struct pib_packet_bth   bth;
	struct pib_packet_deth  deth;
	struct ib_smp		smp;
};

#endif /* PIB_PACKET_H */
