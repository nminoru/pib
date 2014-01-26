/*
 * pib_uc.c - Unreliable Datagram service processing
 *
 * Copyright (c) 2013,2014 Minoru NAKAMURA <nminoru@nminoru.jp>
 *
 * This code is licenced under the GPL version 2 or BSD license.
 */
#include <linux/module.h>
#include <linux/init.h>
#include <linux/version.h>
#include <linux/bitmap.h>
#include <linux/timer.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/errno.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/rtnetlink.h>
#include <linux/if_vlan.h>
#include <linux/random.h>
#include <linux/kthread.h>
#include <net/sock.h> /* for struct sock */

#include <rdma/ib_user_verbs.h>
#include <rdma/ib_pack.h>

#include "pib.h"
#include "pib_packet.h"


/*
 *  state は RTS
 *
 *  Lock: qp
 */
int pib_process_ud_qp_request(struct pib_dev *dev, struct pib_qp *qp, struct pib_send_wqe *send_wqe)
{
	int ret;
	int push_wc;
	struct pib_pd *pd;
	void *buffer;
	u8 port_num;
	struct pib_ah *ah;
	u16 slid, dlid;
	struct pib_packet_lrh *lrh;
	struct ib_grh         *grh;
	struct pib_packet_bth *bth;
	struct pib_packet_deth *deth;
	u8 lnh;
	enum ib_wr_opcode opcode;
	enum ib_wc_status status = IB_WC_SUCCESS;
	int with_imm;
	unsigned long flags;
	u32 packet_length, fix_packet_length;

	opcode = send_wqe->opcode;

	with_imm = (opcode == IB_WR_SEND_WITH_IMM);

	/* Check Opcode */
	switch (opcode) {
	case IB_WR_SEND:
	case IB_WR_SEND_WITH_IMM:
		break;

	default:
		/* Unsupported Opcode */
		status = IB_WC_LOC_QP_OP_ERR;
		goto completion_error;
	}

	/* Check address handle */
	ah = to_pah(send_wqe->wr.ud.ah);
	if (!ah) {
		status = IB_WC_LOC_QP_OP_ERR;
		goto completion_error;
	}

	if (qp->ib_qp.pd != ah->ib_ah.pd) {
		/* @todo PIB_BEHAVIOR_AH_PD_VIOLATOIN_COMP_ERR が立っていればここにはこない */
		status = IB_WC_LOC_QP_OP_ERR;
		goto completion_error;
	}

	/* Check port_num */
	port_num = ah->ib_ah_attr.port_num;
	if (port_num < 1 || dev->ib_dev.phys_port_cnt < port_num) {
		status = IB_WC_LOC_QP_OP_ERR;
		goto completion_error;
	}

	if (qp->qp_type == IB_QPT_UD) /* ignore port_num check if SMI QP and GSI QP */
		if (qp->ib_qp_attr.port_num != port_num) {
			status = IB_WC_LOC_QP_OP_ERR;
			goto completion_error;
		}

	slid = dev->ports[port_num - 1].ib_port_attr.lid;
	dlid = ah->ib_ah_attr.dlid;

	push_wc  = (qp->ib_qp_init_attr.sq_sig_type == IB_SIGNAL_ALL_WR)
		|| (send_wqe->send_flags & IB_SEND_SIGNALED);

	pd = to_ppd(qp->ib_qp.pd);

	buffer = dev->thread.buffer;

	memset(buffer, 0, sizeof(*lrh) + sizeof(*grh) + sizeof(*bth) + sizeof(*deth));

	/* write IB Packet Header (LRH, GRH, BTH, DETH) */
	lrh = (struct pib_packet_lrh*)buffer; 
	buffer += sizeof(*lrh);
	if (ah->ib_ah_attr.ah_flags & IB_AH_GRH) {
		grh = (struct ib_grh*)buffer;
		pib_fill_grh(dev, port_num, grh, &ah->ib_ah_attr.grh);
		buffer += sizeof(*grh);
		lnh = 0x3;
	} else {
		grh = NULL;
		lnh = 0x2;
	}
	bth = (struct pib_packet_bth*)buffer;
	buffer += sizeof(*bth);
	deth = (struct pib_packet_deth*)buffer;
	buffer += sizeof(*deth);

	bth->OpCode = with_imm ? IB_OPCODE_UD_SEND_ONLY_WITH_IMMEDIATE : IB_OPCODE_UD_SEND_ONLY;

	lrh->sl_rsv_lnh = (ah->ib_ah_attr.sl << 4) | lnh; /* Transport: IBA & Next Header: BTH */
	lrh->dlid   = cpu_to_be16(ah->ib_ah_attr.dlid);
	lrh->slid   = cpu_to_be16(slid);

	bth->pkey   = cpu_to_be16(send_wqe->wr.ud.pkey_index); /* @todo from QP for UD/RC QP */
	bth->destQP = cpu_to_be32(send_wqe->wr.ud.remote_qpn);
	bth->psn    = cpu_to_be32(qp->ib_qp_attr.sq_psn & PIB_PSN_MASK); /* A-bit is 0 */

	/*
	 *  An attempt to send a Q_Key with the most siginificant bit set results
	 *  in using the Q_key in the QP context instead of Send WR context.
	 *
	 *  @see IBA Spec. Vol.1 3.5.3 KEYS
	 */
	deth->qkey  = cpu_to_be32(((s32)send_wqe->wr.ud.remote_qkey < 0) ?
				  qp->ib_qp_attr.qkey : send_wqe->wr.ud.remote_qkey);

	deth->srcQP = cpu_to_be32(qp->ib_qp.qp_num);

	if (with_imm) {
		*(__be32*)buffer = send_wqe->imm_data;
		buffer += 4;
	}

	/* SMP の場合の補正 */
	if (send_wqe->wr.ud.remote_qpn == PIB_QP0) {
		struct ib_smp *smp = (struct ib_smp*)buffer;
		if (smp->mgmt_class == IB_MGMT_CLASS_SUBN_DIRECTED_ROUTE) { 
			if (smp->dr_slid == IB_LID_PERMISSIVE)
				lrh->slid = IB_LID_PERMISSIVE;
			if (smp->dr_dlid == IB_LID_PERMISSIVE)
				lrh->dlid = IB_LID_PERMISSIVE;
		}
	}

	/* The maximum message length constrained in size to fi in a single packet. */
	if (send_wqe->processing.all_packets != 1) {
		status = IB_WC_LOC_LEN_ERR;
		goto completion_error;
	}

	if (send_wqe->total_length == 0) {
		
	} else if (send_wqe->send_flags & IB_SEND_INLINE) {
		memcpy(buffer, send_wqe->inline_data_buffer, send_wqe->total_length);
	} else {
		spin_lock_irqsave(&pd->lock, flags);
		status = pib_util_mr_copy_data(pd, send_wqe->sge_array, send_wqe->num_sge,
					       buffer, 0, send_wqe->total_length,
					       0,
					       PIB_MR_COPY_FROM);
		spin_unlock_irqrestore(&pd->lock, flags);
	}

	if (status != IB_WC_SUCCESS)
		goto completion_error;

	buffer += send_wqe->total_length;

	/* サイズの再計算 */
	packet_length     = buffer - dev->thread.buffer;
	fix_packet_length = (packet_length + 3) & ~3;

	pib_packet_lrh_set_pktlen(lrh, fix_packet_length / 4); 
	pib_packet_bth_set_padcnt(bth, fix_packet_length - packet_length);

	dev->thread.port_num	= port_num;
	dev->thread.src_qp_num	= qp->ib_qp.qp_num;
	dev->thread.slid	= slid;
	dev->thread.dlid	= dlid;
	dev->thread.msg_size	= fix_packet_length;
	dev->thread.ready_to_send = 1;

	qp->ib_qp_attr.sq_psn++;

	list_del_init(&send_wqe->list);
	qp->requester.nr_sending_swqe--;
	send_wqe->processing.list_type = PIB_SWQE_FREE;

	if (!push_wc)
		return 0;
	else {
		struct ib_wc wc = {
			.wr_id    = send_wqe->wr_id,
			.status   = IB_WC_SUCCESS,
			.opcode   = pib_convert_wr_opcode_to_wc_opcode(send_wqe->opcode),
			.qp       = &qp->ib_qp,
		};

		ret = pib_util_insert_wc_success(qp->send_cq, &wc);
		/* @todo チェック */
	}

	return 0;

completion_error:
	qp->state = IB_QPS_SQE;

	pib_util_insert_wc_error(qp->send_cq, qp, send_wqe->wr_id,
				 status, send_wqe->opcode);

	BUG_ON(send_wqe->processing.list_type != PIB_SWQE_SENDING);
	list_del_init(&send_wqe->list);
	qp->requester.nr_sending_swqe--;
	send_wqe->processing.list_type = PIB_SWQE_FREE;

	pib_util_flush_qp(qp, 1);

	return -1;
}


void pib_receive_ud_qp_incoming_message(struct pib_dev *dev, u8 port_num, struct pib_qp *qp, struct pib_packet_lrh *lrh, struct ib_grh *grh, struct pib_packet_bth *bth, void *buffer, int size)
{
	struct pib_pd *pd;
	struct pib_recv_wqe *recv_wqe = NULL;
	struct pib_packet_deth *deth;
	u32 qkey;
	enum ib_wc_status status = IB_WC_SUCCESS;
	__be32 imm_data = 0;
	unsigned long flags;

	if (!pib_is_recv_ok(qp->state))
		goto silently_drop;

	switch (bth->OpCode) {

	case IB_OPCODE_UD_SEND_ONLY:
	case IB_OPCODE_UD_SEND_ONLY_WITH_IMMEDIATE:
		break;
		
	default:
		goto silently_drop;
	}

	/* UD don't set acknowledge request bit */
	if (be32_to_cpu(bth->psn) & 0x80000000U) /* A-bit */
		goto silently_drop;

	/* Analyze Datagram Extended Transport Header */
	if (size < sizeof(struct pib_packet_deth))
		goto silently_drop;

	deth = (struct pib_packet_deth*)buffer;

	buffer += sizeof(*deth);
	size   -= sizeof(*deth);

	if (qp->qp_type == IB_QPT_UD) /* ignore port_num check if SMI QP and GSI QP */
		if (qp->ib_qp_attr.port_num != port_num)
			goto silently_drop;

	qkey = be32_to_cpu(deth->qkey);

	/* BTH: Q_Key check */
	switch (qp->qp_type) {
	case IB_QPT_SMI:
		break;

	case IB_QPT_GSI:
		if (qkey != IB_QP1_QKEY)
			goto silently_drop;
		break;

	default:
		if (qkey != qp->ib_qp_attr.qkey)
			goto silently_drop;
		break;
	}

	/* Analyze Immediate Extended Transport Header */
	if (bth->OpCode == IB_OPCODE_UD_SEND_ONLY_WITH_IMMEDIATE) {
		if (size < 4)
			goto silently_drop;

		imm_data = *(__be32*)buffer; /* @odo */

		buffer += 4;
		size   -= 4;
	}

	if (qp->ib_qp_init_attr.srq) {
		recv_wqe = pib_util_get_srq(to_psrq(qp->ib_qp_init_attr.srq));
		if (!recv_wqe)
			goto silently_drop;

	} else {

		if (list_empty(&qp->responder.recv_wqe_head))
			goto silently_drop;

		recv_wqe = list_first_entry(&qp->responder.recv_wqe_head, struct pib_recv_wqe, list);
		list_del_init(&recv_wqe->list);
		qp->responder.nr_recv_wqe--;
	}

	if (recv_wqe->total_length < size)
		goto silently_drop; /* UD don't cause local length error */

	pd = to_ppd(qp->ib_qp.pd);

	spin_lock_irqsave(&pd->lock, flags);

	if (grh)
		status = pib_util_mr_copy_data(pd, recv_wqe->sge_array, recv_wqe->num_sge,
					       grh, 0, sizeof(*grh),
					       IB_ACCESS_LOCAL_WRITE,
					       PIB_MR_COPY_TO);
	if (status == IB_WC_SUCCESS)
		status = pib_util_mr_copy_data(pd, recv_wqe->sge_array, recv_wqe->num_sge,
					       buffer, sizeof(*grh), size,
					       IB_ACCESS_LOCAL_WRITE,
					       PIB_MR_COPY_TO);

	spin_unlock_irqrestore(&pd->lock, flags);

	if (status != IB_WC_SUCCESS) {
		if (status == IB_WC_LOC_LEN_ERR) {
			if (qp->ib_qp_init_attr.srq)
				goto abort_error;
			else
				goto silently_drop;
		}
		goto completion_error;
	}

	{
		int ret;
		struct ib_wc wc = {
			.wr_id       = recv_wqe->wr_id,
			.status      = IB_WC_SUCCESS,
			.opcode      = IB_WC_RECV,
			.byte_len    = size + 40,
			.qp          = &qp->ib_qp,
			.ex.imm_data = imm_data,
			.src_qp      = be32_to_cpu(deth->srcQP) & PIB_QPN_MASK,
			.slid        = be16_to_cpu(lrh->slid),
		};

		if (grh)
			wc.wc_flags |= IB_WC_GRH;

		if (bth->OpCode == IB_OPCODE_UD_SEND_ONLY_WITH_IMMEDIATE)
			wc.wc_flags |= IB_WC_WITH_IMM;

		ret = pib_util_insert_wc_success(qp->recv_cq, &wc); /* @todo */
	}

	qp->push_rcqe = 1;
	qp->ib_qp_attr.rq_psn++;
	pib_util_free_recv_wqe(qp, recv_wqe);

	return;

silently_drop:
	if (recv_wqe)
		pib_util_free_recv_wqe(qp, recv_wqe); /* @todo WC をあげるべき */

	return;

completion_error:
	qp->state = IB_QPS_ERR;

	pib_util_insert_wc_error(qp->send_cq, qp, recv_wqe->wr_id,
				 status, IB_WC_RECV);

	pib_util_flush_qp(qp, 0);
	qp->push_rcqe = 1;
	pib_util_free_recv_wqe(qp, recv_wqe);

	return;

abort_error:
	pib_util_insert_wc_error(qp->send_cq, qp, recv_wqe->wr_id,
				 IB_WC_REM_ABORT_ERR, IB_WC_RECV);
	qp->push_rcqe = 1;
	pib_util_free_recv_wqe(qp, recv_wqe);

	return; 
}
