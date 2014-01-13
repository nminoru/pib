/*
 * Copyright (c) 2013 Minoru NAKAMURA <nminoru@nminoru.jp>
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
int pib_process_ud_qp_request(struct pib_ib_dev *dev, struct pib_ib_qp *qp, struct pib_ib_send_wqe *send_wqe)
{
	int ret;
	int push_wc;
	struct pib_ib_pd *pd;
	void *buffer;
	u8 port_num;
	struct pib_ib_ah *ah;
	struct sockaddr *sockaddr;
	u64 total_length = 0;
	struct pib_packet_ud_request *ud_packet;
	enum ib_wr_opcode opcode;
	enum ib_wc_status status = IB_WC_SUCCESS;
	int with_imm;
	unsigned long flags;

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

	sockaddr = pib_get_sockaddr_from_lid(dev, port_num, qp, ah->ib_ah_attr.dlid);

	if (!sockaddr) {
		pr_err("pib: Not found the destination address in ld_table (ah.dlid=%u)", ah->ib_ah_attr.dlid);
		return 0;
	}

	push_wc  = (qp->ib_qp_init_attr.sq_sig_type == IB_SIGNAL_ALL_WR)
		|| (send_wqe->send_flags & IB_SEND_SIGNALED);

	pd = to_ppd(qp->ib_qp.pd);

	buffer = dev->thread.buffer;

	/* write IB Packet Header (LRH, BTH, DETH) */
	ud_packet = (struct pib_packet_ud_request*)buffer;

	memset(ud_packet, 0, sizeof(*ud_packet));

	ud_packet->bth.OpCode = with_imm ? IB_OPCODE_UD_SEND_ONLY_WITH_IMMEDIATE : IB_OPCODE_UD_SEND_ONLY;

	ud_packet->lrh.VL     = 0;
	ud_packet->lrh.LVer   = 0;
	ud_packet->lrh.SL     = ah->ib_ah_attr.sl;
	ud_packet->lrh.LNH    = 1; /* Transport: IBA & Next Header: BTH */
	ud_packet->lrh.DLID   = ah->ib_ah_attr.dlid;
	ud_packet->lrh.SLID   = dev->ports[port_num - 1].ib_port_attr.lid;

	ud_packet->bth.SE     = 0;
	ud_packet->bth.M      = 0;
	ud_packet->bth.TVer   = 0;
	ud_packet->bth.P_Key  = send_wqe->wr.ud.pkey_index; /* @todo from QP for UD/RC QP */
	ud_packet->bth.DestQP = send_wqe->wr.ud.remote_qpn;
	ud_packet->bth.A      = 0;
	ud_packet->bth.PSN    = qp->ib_qp_attr.sq_psn;

	/*
	 *  An attempt to send a Q_Key with the most siginificant bit set results
	 *  in using the Q_key in the QP context instead of Send WR context.
	 *
	 *  @see IBA Spec. Vol.1 3.5.3 KEYS
	 */
	ud_packet->deth.Q_Key = ((s32)send_wqe->wr.ud.remote_qkey < 0) ?
		qp->ib_qp_attr.qkey : send_wqe->wr.ud.remote_qkey;

	ud_packet->deth.SrcQP = qp->ib_qp.qp_num;

	buffer += sizeof(*ud_packet);

	if (with_imm) {
		*(__be32*)buffer = send_wqe->imm_data;
		buffer += 4;
	}

	/* The maximum message length constrained in size to fi in a single packet. */
	if (send_wqe->processing.all_packets != 1) {
		status = IB_WC_LOC_LEN_ERR;
		goto completion_error;
	}

	spin_lock_irqsave(&pd->lock, flags);
	status = pib_util_mr_copy_data(pd, send_wqe->sge_array, send_wqe->num_sge,
				       buffer, 0, send_wqe->total_length,
				       0,
				       PIB_MR_COPY_FROM);
	spin_unlock_irqrestore(&pd->lock, flags);

	if (status != IB_WC_SUCCESS)
		goto completion_error;

	buffer += send_wqe->total_length;

	/* サイズの再計算 */
	total_length = buffer - dev->thread.buffer;

	ud_packet->lrh.PktLen = ((total_length + 3) & ~3) / 4;
	ud_packet->bth.PadCnt = ud_packet->lrh.PktLen * 4 - total_length;

	total_length = ud_packet->lrh.PktLen * 4;

	if (ud_packet->bth.DestQP == PIB_IB_QP0) {
		struct pib_packet_smp *packet;
		
		packet = (struct pib_packet_smp *)buffer;

		if (packet->smp.mgmt_class == IB_MGMT_CLASS_SUBN_DIRECTED_ROUTE) {
			if (packet->smp.dr_slid == IB_LID_PERMISSIVE)
				ud_packet->lrh.SLID = 0xFFFF;
			if (packet->smp.dr_dlid == IB_LID_PERMISSIVE)
				ud_packet->lrh.DLID = 0xFFFF;
		}
	}

	dev->thread.sockaddr	= sockaddr;
	dev->thread.msg_size    = total_length;
	dev->thread.port_num    = port_num;
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


void pib_receive_ud_qp_SEND_request(struct pib_ib_dev *dev, u8 port_num, struct pib_ib_qp *qp, void *buffer, int size, struct pib_packet_lrh *lrh, struct pib_packet_bth *bth)
{
	struct pib_ib_pd *pd;
	struct pib_ib_recv_wqe *recv_wqe = NULL;
	struct pib_packet_deth *deth;
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
	if (bth->A)
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

	/* BTH: Q_Key check */
	switch (qp->qp_type) {
	case IB_QPT_SMI:
		break;

	case IB_QPT_GSI:
		if (deth->Q_Key != IB_QP1_QKEY)
			goto silently_drop;
		break;

	default:
		if (deth->Q_Key != qp->ib_qp_attr.qkey)
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

	if (!pib_is_recv_ok(qp->state))
		goto silently_drop;

	if (qp->ib_qp_init_attr.srq) {
		recv_wqe = pib_util_get_srq(to_psrq(qp->ib_qp_init_attr.srq));
		if (!recv_wqe)
			goto silently_drop;

	} else {

		if (list_empty(&qp->responder.recv_wqe_head))
			goto silently_drop;

		recv_wqe = list_first_entry(&qp->responder.recv_wqe_head, struct pib_ib_recv_wqe, list);
		list_del_init(&recv_wqe->list);
		qp->responder.nr_recv_wqe--;
	}

	if (recv_wqe->total_length < size)
		goto silently_drop; /* UD don't cause local length error */

	pd = to_ppd(qp->ib_qp.pd);

	spin_lock_irqsave(&pd->lock, flags);
	status = pib_util_mr_copy_data(pd, recv_wqe->sge_array, recv_wqe->num_sge,
				       buffer, 40, size,
				       IB_ACCESS_LOCAL_WRITE,
				       PIB_MR_COPY_TO);
	spin_unlock_irqrestore(&pd->lock, flags);

	if (status != IB_WC_SUCCESS)
		goto completion_error;

	{
		struct ib_wc wc = {
			.wr_id       = recv_wqe->wr_id,
			.status      = IB_WC_SUCCESS,
			.opcode      = IB_WC_RECV,
			.byte_len    = size + 40,
			.qp          = &qp->ib_qp,
			.ex.imm_data = imm_data,
			.src_qp      = deth->SrcQP,
			.slid        = lrh->SLID,
			.wc_flags    = (bth->OpCode == IB_OPCODE_UD_SEND_ONLY_WITH_IMMEDIATE) ? IB_WC_WITH_IMM : 0,
		};

		int ret;

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
	/* qp->ib_qp_attr.rq_psn++; */ /* @todo エラー時も PSN をまわすのか？ */

	pib_util_free_recv_wqe(qp, recv_wqe);
}
