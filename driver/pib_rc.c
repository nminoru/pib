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
 *  Requester: Generating Request Packets
 */
static enum ib_wc_status process_SEND_or_RDMA_WRITE_request(struct pib_ib_dev *dev, struct pib_ib_qp *qp, struct pib_ib_send_wqe *send_wqe, void *buffer, int with_reth, int with_imm);
static enum ib_wc_status process_RDMA_READ_request(struct pib_ib_dev *dev, struct pib_ib_qp *qp, struct pib_ib_send_wqe *send_wqe, void *buffer);
static enum ib_wc_status process_Atomic_request(struct pib_ib_dev *dev, struct pib_ib_qp *qp, struct pib_ib_send_wqe *send_wqe, void *buffer);

/*
 *  Responder: Receiving Inbound Request Packets
 */
static void receive_request(struct pib_ib_dev *dev, u8 port_num, struct pib_ib_qp *qp, void *buffer, int size, struct pib_packet_lrh *lrh, struct pib_packet_bth *bth);
static int receive_SEND_request(struct pib_ib_dev *dev, u8 port_num, u32 psn, int OpCode, struct pib_ib_qp *qp, void *buffer, int size, struct pib_packet_lrh *lrh);
static int receive_RDMA_WRITE_request(struct pib_ib_dev *dev, u8 port_num, u32 psn, int OpCode, struct pib_ib_qp *qp, void *buffer, int size, struct pib_packet_lrh *lrh);
static int receive_RDMA_READ_request(struct pib_ib_dev *dev, u8 port_num, u32 psn, struct pib_ib_qp *qp, void *buffer, int siz, int new_request, int slot_index);
static int receive_Atomic_request(struct pib_ib_dev *dev, u8 port_num, u32 psn, int OpCode, struct pib_ib_qp *qp,  void *buffer, int size);
static void push_acknowledge(struct pib_ib_qp *qp, u32 psn, enum pib_ib_syndrome syndrome);
static void push_rdma_read_acknowledge(struct pib_ib_qp *qp, u32 psn, u32 expected_psn, u64 vaddress, u32 rkey, u32 size, int retried);
static void push_atomic_acknowledge(struct pib_ib_qp *qp, u32 psn, u64 res);

/*
 * Responder: Generating Acknowledge Packets
 */
static int generate_Normal_or_Atomic_acknowledge(struct pib_ib_dev *dev, u8 port_num, struct pib_ib_qp *qp, struct pib_ib_ack *ack, struct sockaddr *sockaddr);
static int generate_RDMA_READ_response(struct pib_ib_dev *dev, u8 port_num, struct pib_ib_qp *qp, struct pib_ib_ack *ack, struct sockaddr *sockaddr);
static int pack_acknowledge_packet(struct pib_ib_dev *dev, u8 port_num, struct pib_ib_qp *qp, int OpCode, u32 psn, int with_aeth, enum pib_ib_syndrome syndrome, int with_atomiceth, u64 res);

/*
 *  Requester: Receiving Responses
 */
static int receive_response(struct pib_ib_dev *dev, u8 port_num, struct pib_ib_qp *qp, void *buffer, int size, struct pib_packet_lrh *lrh, struct pib_packet_bth *bth);
static int receive_ACK_response(struct pib_ib_dev *dev, u8 port_num, struct pib_ib_qp *qp, u32 psn);
static int process_acknowledge(struct pib_ib_dev *dev, struct pib_ib_qp *qp, struct pib_ib_send_wqe *send_wqe, u32 psn, int *nr_swqe_p);
static void set_send_wqe_to_error(struct pib_ib_qp *qp, u32 psn, enum ib_wc_status status);
static int receive_RDMA_READ_response(struct pib_ib_dev *dev, u8 port_num, struct pib_ib_qp *qp, u32 psn, void *buffer, int size);
static int receive_Atomic_response(struct pib_ib_dev *dev, u8 port_num, struct pib_ib_qp *qp, u32 psn, void *buffer, int size);

/*
 *  Helper functions
 */
static void insert_async_qp_error(struct pib_ib_dev *dev, struct pib_ib_qp *qp, enum ib_event_type event);
static void abort_active_rwqe(struct pib_ib_dev *dev, struct pib_ib_qp *qp);
static struct pib_ib_send_wqe *match_send_wqe(struct pib_ib_qp *qp, u32 psn, int *first_send_wqe_p, int **nr_swqe_pp);
static void issue_comm_est(struct pib_ib_qp *qp);


/******************************************************************************/

static s32 get_psn_diff(u32 psn, u32 based_psn)
{
	return ((s32)((psn - based_psn) << 8)) >> 8;
}


static enum pib_ib_syndrome get_resources_not_ready(struct pib_ib_qp *qp)
{
	return PIB_IB_RNR_NAK_CODE | (qp->ib_qp_attr.min_rnr_timer & 0x1F);
}


/******************************************************************************/
/* Requester: Generating Request Packets                                      */
/******************************************************************************/

int pib_process_rc_qp_request(struct pib_ib_dev *dev, struct pib_ib_qp *qp, struct pib_ib_send_wqe *send_wqe)
{
	int ret;
	int with_reth = 0;
	int with_imm = 0;
	struct pib_ib_pd *pd;
	void *buffer;
	struct msghdr msghdr;
	struct kvec iov;
	u8 port_num;
	struct ib_ah_attr ah_attr;
	struct sockaddr *sockaddr;
	struct pib_packet_rc_request *rc_packet;
	enum ib_wc_status status;

	/*
	 *  A work request with the fence attribute set shall block
	 *  until all prior RDMA READ and Atomic WRs have completed.
	 *  
	 */
	if (send_wqe->send_flags & IB_SEND_FENCE)
		if (0 < qp->requester.nr_rd_atomic)
			return -1;

	if (send_wqe->processing.retry_cnt < 0) {
		status = IB_WC_RETRY_EXC_ERR;
		goto completion_error;
	}

	if (send_wqe->processing.rnr_retry < 0) {
		status = IB_WC_RNR_RETRY_EXC_ERR;
		goto completion_error;
	}

	port_num = qp->ib_qp_attr.port_num;
	ah_attr  = qp->ib_qp_attr.ah_attr;

	sockaddr = dev->ports[port_num - 1].lid_table[ah_attr.dlid];

	if (!sockaddr) {
		debug_printk("Not found the destination address in ld_table (ah.dlid=%u)", ah_attr.dlid);
		return 0;
	}

	pd = to_ppd(qp->ib_qp.pd);

	buffer = dev->thread.buffer;

	/* write IB Packet Header (LRH, BTH) */
	rc_packet = (struct pib_packet_rc_request*)buffer;

	rc_packet->lrh.VL     = 0;
	rc_packet->lrh.LVer   = 0;
	rc_packet->lrh.SL     = ah_attr.sl;
	rc_packet->lrh.LNH    = 1; /* Transport: IBA & Next Header: BTH */
	rc_packet->lrh.DLID   = ah_attr.dlid;
	rc_packet->lrh.SLID   = dev->ports[port_num - 1].ib_port_attr.lid;

	rc_packet->bth.SE     = 0; /* @todo */
	rc_packet->bth.M      = 0;
	rc_packet->bth.TVer   = 0;
	rc_packet->bth.P_Key  = qp->ib_qp_attr.pkey_index;
	rc_packet->bth.DestQP = qp->ib_qp_attr.dest_qp_num;
	rc_packet->bth.A      = 0;
	rc_packet->bth.PSN    = send_wqe->processing.based_psn + send_wqe->processing.sent_packets;

	switch (send_wqe->opcode) {

	case IB_WR_SEND:
		if (send_wqe->processing.all_packets == 1)
			rc_packet->bth.OpCode = IB_OPCODE_RC_SEND_ONLY;
		else if (send_wqe->processing.sent_packets == 0)
			rc_packet->bth.OpCode = IB_OPCODE_RC_SEND_FIRST;
		else if (send_wqe->processing.all_packets == send_wqe->processing.sent_packets + 1)
			rc_packet->bth.OpCode = IB_OPCODE_RC_SEND_LAST;
		else
			rc_packet->bth.OpCode = IB_OPCODE_RC_SEND_MIDDLE;
		goto send_or_rdma_write;

	case IB_WR_SEND_WITH_IMM:
		if (send_wqe->processing.all_packets == 1) {
			rc_packet->bth.OpCode = IB_OPCODE_RC_SEND_ONLY_WITH_IMMEDIATE;
			with_imm = 1;
		} else if (send_wqe->processing.sent_packets == 0) {
			rc_packet->bth.OpCode = IB_OPCODE_RC_SEND_FIRST;
		} else if (send_wqe->processing.all_packets == send_wqe->processing.sent_packets + 1) {
			rc_packet->bth.OpCode = IB_OPCODE_RC_SEND_LAST_WITH_IMMEDIATE;
			with_imm = 1;
		} else
			rc_packet->bth.OpCode = IB_OPCODE_RC_SEND_MIDDLE;
		goto send_or_rdma_write;

	case IB_WR_RDMA_WRITE:
		if (send_wqe->processing.all_packets == 1) {
			rc_packet->bth.OpCode = IB_OPCODE_RC_RDMA_WRITE_ONLY;
			with_reth = 1;
		} else if (send_wqe->processing.sent_packets == 0) {
			rc_packet->bth.OpCode = IB_OPCODE_RC_RDMA_WRITE_FIRST;
			with_reth = 1;
		} else if (send_wqe->processing.all_packets == send_wqe->processing.sent_packets + 1)
			rc_packet->bth.OpCode = IB_OPCODE_RC_RDMA_WRITE_LAST;
		else
			rc_packet->bth.OpCode = IB_OPCODE_RC_RDMA_WRITE_MIDDLE;
		goto send_or_rdma_write;

	case IB_WR_RDMA_WRITE_WITH_IMM:
		if (send_wqe->processing.all_packets == 1) {
			rc_packet->bth.OpCode = IB_OPCODE_RC_RDMA_WRITE_ONLY_WITH_IMMEDIATE;
			with_reth = 1;
			with_imm  = 1;
		} else if (send_wqe->processing.sent_packets == 0) {
			rc_packet->bth.OpCode = IB_OPCODE_RC_RDMA_WRITE_FIRST;
			with_reth = 1;
		} else if (send_wqe->processing.all_packets == send_wqe->processing.sent_packets + 1) {
			rc_packet->bth.OpCode = IB_OPCODE_RC_RDMA_WRITE_LAST_WITH_IMMEDIATE;
			with_imm  = 1;
		} else
			rc_packet->bth.OpCode = IB_OPCODE_RC_RDMA_WRITE_MIDDLE;

		goto send_or_rdma_write;

	send_or_rdma_write:
		status = process_SEND_or_RDMA_WRITE_request(dev, qp, send_wqe, buffer, with_reth, with_imm);
		break;

	case IB_WR_RDMA_READ:
		rc_packet->bth.OpCode = IB_OPCODE_RC_RDMA_READ_REQUEST;
		status = process_RDMA_READ_request(dev, qp, send_wqe, buffer);
		break;

	case IB_WR_ATOMIC_CMP_AND_SWP:
		rc_packet->bth.OpCode = IB_OPCODE_RC_COMPARE_SWAP;
		status = process_Atomic_request(dev, qp, send_wqe, buffer);
		break;

	case IB_WR_ATOMIC_FETCH_AND_ADD:
		rc_packet->bth.OpCode = IB_OPCODE_RC_FETCH_ADD;
		status = process_Atomic_request(dev, qp, send_wqe, buffer);
		break;

	default:
		/* Unsupported Opcode */
		status = IB_WC_LOC_QP_OP_ERR;
		break;
	}

	if (status != IB_WC_SUCCESS)
		goto completion_error;

	memset(&msghdr, 0, sizeof(msghdr));
	
	msghdr.msg_name    = sockaddr;
	msghdr.msg_namelen = (sockaddr->sa_family == AF_INET6) ?
		sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);

	iov.iov_base = dev->thread.buffer;
	iov.iov_len  = rc_packet->lrh.PktLen * 4;

	ret = kernel_sendmsg(dev->ports[port_num - 1].socket, &msghdr, &iov, 1, iov.iov_len);
	if (ret < 0)
		return ret;

	if (send_wqe->opcode != IB_WR_RDMA_READ) {
		send_wqe->processing.sent_packets++;
		if (send_wqe->processing.sent_packets < send_wqe->processing.all_packets) {
			/* Send WQE にはまだ送信すべきパケットが残っている。 */
			return 0;
		}
	}

	send_wqe->processing.list_type = PIB_SWQE_WAITING;

	/* Calucate the next time in jififes to resend this request by local ACK timer */
	send_wqe->processing.local_ack_time =
		jiffies + pib_get_local_ack_time(qp->ib_qp_attr.timeout);

	return 0;

completion_error:
	/* ここで completion error は作成しない */
	send_wqe->processing.status = status;

	return -1;
}


static enum ib_wc_status
process_SEND_or_RDMA_WRITE_request(struct pib_ib_dev *dev, struct pib_ib_qp *qp, struct pib_ib_send_wqe *send_wqe, void *buffer, int with_reth, int with_imm)
{
	struct pib_packet_rc_request *rc_packet;
	struct pib_ib_pd *pd;
	u64 mr_offset;
	u32 payload_size;
	u32 packet_length;
	enum ib_wc_status status;
	unsigned long flags;

	if (PIB_IB_MAX_PAYLOAD_LEN <= send_wqe->total_length)
		return IB_WC_LOC_LEN_ERR;

	rc_packet = (struct pib_packet_rc_request*)buffer;
	buffer   += sizeof(struct pib_packet_rc_request);

	if (with_reth) {
		struct pib_packet_reth *reth;
		
		reth = (struct pib_packet_reth*)buffer;
		
		reth->VA_hi  = (send_wqe->wr.rdma.remote_addr >> 32);
		reth->VA_lo  = send_wqe->wr.rdma.remote_addr;
		reth->R_Key  = send_wqe->wr.rdma.rkey;
		reth->DMALen = send_wqe->total_length;

		buffer += sizeof(struct pib_packet_reth);
	}

	if (with_imm) {
		*(__be32*)buffer = send_wqe->imm_data;
		buffer += 4;
	}

	mr_offset = send_wqe->processing.sent_packets * 128U << qp->ib_qp_attr.path_mtu;

	if (send_wqe->processing.all_packets - send_wqe->processing.sent_packets == 1)
		payload_size = send_wqe->total_length - mr_offset;
	else
		payload_size = (128U << qp->ib_qp_attr.path_mtu);

	pd = to_ppd(qp->ib_qp.pd);

	spin_lock_irqsave(&pd->lock, flags);
	status = pib_util_mr_copy_data(pd, send_wqe->sge_array, send_wqe->num_sge,
				       buffer, mr_offset, payload_size,
				       0,
				       PIB_MR_COPY_FROM);
	spin_unlock_irqrestore(&pd->lock, flags);

	if (status != IB_WC_SUCCESS)
		return status;

	buffer += payload_size;

	/* calculate packet length & pad count */
	packet_length = buffer - dev->thread.buffer;

	rc_packet->lrh.PktLen = ((packet_length + 3) & ~3) / 4;
	rc_packet->bth.PadCnt = rc_packet->lrh.PktLen * 4 - packet_length;

	return IB_WC_SUCCESS;
}


static enum ib_wc_status
process_RDMA_READ_request(struct pib_ib_dev *dev, struct pib_ib_qp *qp, struct pib_ib_send_wqe *send_wqe, void *buffer)
{
	struct pib_packet_rc_request *rc_packet;
	struct pib_packet_reth *reth;
	u32 packet_length;
	u64 remote_addr;
	u32 dmalen, offset;

	if (PIB_IB_MAX_PAYLOAD_LEN <= send_wqe->total_length)
		return IB_WC_LOC_LEN_ERR;

	remote_addr = send_wqe->wr.rdma.remote_addr;
	dmalen      = send_wqe->total_length;

	offset      = (128U << qp->ib_qp_attr.path_mtu) * send_wqe->processing.sent_packets;

	if (0 < offset) {
		/*
		 * Resend a partial RDMA READ Request again
		 *
		 * IBA Spec. Vol.1 9.4.4 states states the following sentence
		 *
		 * - Retried RDMA READ Requests need not start at the smame
		 *   address nor have the same length as the original RDMA READ.
		 *   The retried request may only reread those portions that
		 *   were not successfully responded to the first time.
		 *
		 * - The PSN of the retried RDMA READ request need not be the
		 *   same as the PSN of the original RDMA READ request.
		 *   Any retried request must correspond exactly to a subset of
		 *   the original RDMA READ request in such a manner that all
		 *   potential duplicate response packets must have identical
		 *   payload data and PSNs regardless of whether it is a response
		 *   to the original request or a retried request.
		 */
		remote_addr -= offset;
		dmalen      -= offset;
	}

	rc_packet = (struct pib_packet_rc_request*)buffer;
	buffer   += sizeof(struct pib_packet_rc_request);

	reth = (struct pib_packet_reth*)buffer;
		
	reth->VA_hi  = (remote_addr >> 32);
	reth->VA_lo  = remote_addr;
	reth->R_Key  = send_wqe->wr.rdma.rkey;
	reth->DMALen = dmalen;

	buffer   += sizeof(struct pib_packet_reth);

	/* calculate packet length & pad count */
	packet_length = buffer - dev->thread.buffer;

	rc_packet->lrh.PktLen = ((packet_length + 3) & ~3) / 4;
	rc_packet->bth.PadCnt = rc_packet->lrh.PktLen * 4 - packet_length;

	return IB_WC_SUCCESS;
}


static enum ib_wc_status
process_Atomic_request(struct pib_ib_dev *dev, struct pib_ib_qp *qp, struct pib_ib_send_wqe *send_wqe, void *buffer)
{
	struct pib_packet_rc_request *rc_packet;
	struct pib_packet_atomiceth *atomiceth;
	u32 packet_length;

	rc_packet = (struct pib_packet_rc_request*)buffer;
	buffer   += sizeof(struct pib_packet_rc_request);

	atomiceth = (struct pib_packet_atomiceth*)buffer;

	atomiceth->VA_hi     = (send_wqe->wr.atomic.remote_addr >> 32);
	atomiceth->VA_lo     = (send_wqe->wr.atomic.remote_addr >>  0);
	atomiceth->R_Key     = send_wqe->wr.atomic.rkey;
	atomiceth->SwapDt_hi = (send_wqe->wr.atomic.swap        >> 32);
	atomiceth->SwapDt_lo = (send_wqe->wr.atomic.swap        >>  0);
	atomiceth->CmpDt_hi  = (send_wqe->wr.atomic.compare_add >> 32);
	atomiceth->CmpDt_lo  = (send_wqe->wr.atomic.compare_add >>  0);
	
	buffer   += sizeof(struct pib_packet_atomiceth);

	/* calculate packet length & pad count */
	packet_length = buffer - dev->thread.buffer;

	rc_packet->lrh.PktLen = ((packet_length + 3) & ~3) / 4;
	rc_packet->bth.PadCnt = rc_packet->lrh.PktLen * 4 - packet_length;

	return IB_WC_SUCCESS;
}


/******************************************************************************/
/* Receiving Any Packets As Responder or Requester                            */
/******************************************************************************/

void pib_receive_rc_qp_incoming_message(struct pib_ib_dev *dev, u8 port_num, struct pib_ib_qp *qp, void *buffer, int size, struct pib_packet_lrh *lrh, struct pib_packet_bth *bth)
{
	if (!pib_is_recv_ok(qp->state))
		/* silently drop */
		/* @todo これでいいんだっけ？ */
		return;

	if (qp->ib_qp_attr.port_num != port_num)
		/* silently drop */
		return;

	if (pib_opcode_is_acknowledge(bth->OpCode)) {
		/* Acknowledge to requester */
		receive_response(dev, port_num, qp, buffer, size, lrh, bth);
	} else {
		/* Request to responder */
		receive_request(dev, port_num, qp, buffer, size, lrh, bth);
	}
}


/******************************************************************************/
/* Responder: Receiving Inbound Request Packets                               */
/******************************************************************************/

static void
receive_request(struct pib_ib_dev *dev, u8 port_num, struct pib_ib_qp *qp, void *buffer, int size, struct pib_packet_lrh *lrh, struct pib_packet_bth *bth)
{
	int ret;
	s32 psn_diff;
	int OpCode;
	u32 psn;

	OpCode = bth->OpCode;
	psn    = bth->PSN;

	issue_comm_est(qp);

	psn_diff = get_psn_diff(psn, qp->responder.psn);

	if (0 < psn_diff) {
		/* Out of Sequence Request Packet */
		push_acknowledge(qp, psn, PIB_IB_NAK_CODE_PSN_SEQ_ERR);
		/* @todo NAK の時の PSN はこれでいいのか？ */
		return;
	}

	if (psn_diff < 0) {
		int i;
		struct pib_ib_rd_atom_slot slot;

		switch (OpCode) {
		case IB_OPCODE_RC_RDMA_READ_REQUEST:
		case IB_OPCODE_RC_COMPARE_SWAP:
		case IB_OPCODE_RC_FETCH_ADD:
			for (i=1 ; i <= qp->ib_qp_attr.max_dest_rd_atomic ; i++) {
				slot = qp->responder.slots[((unsigned int)(qp->responder.slot_index - i)) % PIB_IB_MAX_RD_ATOM];

				if ((slot.OpCode != OpCode) ||
				    (get_psn_diff(psn, slot.psn)          <   0) ||
				    (get_psn_diff(psn, slot.expected_psn) >=  0))
					continue;

				if (OpCode == IB_OPCODE_RC_RDMA_READ_REQUEST)
					receive_RDMA_READ_request(dev, port_num, psn, qp, buffer, size,
								   0, i);
				else
					push_atomic_acknowledge(qp, psn, slot.data.atomic.res);

				return; 
			}
			
			/* Too many RDMA READ or ATOMIC Requests */
			push_acknowledge(qp, psn, PIB_IB_NAK_CODE_INV_REQ_ERR);
			insert_async_qp_error(dev, qp, IB_EVENT_QP_ACCESS_ERR);
			return;

		default:
			break;
		}

		/* Resend response for duplicated packet */
		push_acknowledge(qp, psn, PIB_IB_ACK_CODE);
		return;
	}

	if (!pib_opcode_is_in_order_sequence(OpCode, qp->responder.last_OpCode)) {
		/* Out of sequence OpCode */

		/* Invalid Request Local Work Queue Error */
		push_acknowledge(qp, psn, PIB_IB_NAK_CODE_INV_REQ_ERR);
		insert_async_qp_error(dev, qp, IB_EVENT_QP_REQ_ERR);
		return;
	}

	switch (OpCode) {

	case IB_OPCODE_RC_SEND_FIRST:
	case IB_OPCODE_RC_SEND_MIDDLE:
	case IB_OPCODE_RC_SEND_LAST:
	case IB_OPCODE_RC_SEND_ONLY:
	case IB_OPCODE_RC_SEND_LAST_WITH_IMMEDIATE:
	case IB_OPCODE_RC_SEND_ONLY_WITH_IMMEDIATE:
		ret = receive_SEND_request(dev, port_num, psn, OpCode, qp, buffer, size, lrh);
		break;

	case IB_OPCODE_RC_RDMA_WRITE_FIRST:
	case IB_OPCODE_RC_RDMA_WRITE_MIDDLE:
	case IB_OPCODE_RC_RDMA_WRITE_LAST:
	case IB_OPCODE_RC_RDMA_WRITE_LAST_WITH_IMMEDIATE:
	case IB_OPCODE_RC_RDMA_WRITE_ONLY:
	case IB_OPCODE_RC_RDMA_WRITE_ONLY_WITH_IMMEDIATE:
		ret = receive_RDMA_WRITE_request(dev, port_num, psn, OpCode, qp, buffer, size, lrh);
		break;

	case IB_OPCODE_RC_RDMA_READ_REQUEST:
		ret = receive_RDMA_READ_request(dev, port_num, psn, qp, buffer, size, 1, 0 /* ignore */);
		break;

	case IB_OPCODE_RC_COMPARE_SWAP:
		ret = receive_Atomic_request(dev, port_num, psn, IB_OPCODE_RC_COMPARE_SWAP, qp, buffer, size);
		break;

	case IB_OPCODE_RC_FETCH_ADD:
		ret = receive_Atomic_request(dev, port_num, psn, IB_OPCODE_RC_FETCH_ADD, qp, buffer, size);
		break;

	default:
		BUG();
	}

	if (ret >= 0) {
		qp->responder.psn += ret;
		qp->responder.last_OpCode = OpCode;
	}
}


static int
receive_SEND_request(struct pib_ib_dev *dev, u8 port_num, u32 psn, int OpCode, struct pib_ib_qp *qp, void *buffer, int size, struct pib_packet_lrh *lrh)
{
	int init = 0;
	int finit = 0;
	int with_imm = 0;
	int pmtu, min, max;
	__be32 imm_data = 0;
	struct pib_ib_recv_wqe *recv_wqe = NULL;
	struct pib_ib_pd *pd;
	enum ib_wc_status status = IB_WC_SUCCESS;
	enum pib_ib_syndrome syndrome;
	unsigned long flags;

	pmtu = (128U << qp->ib_qp_attr.path_mtu);

	switch (OpCode) {

	case IB_OPCODE_RC_SEND_ONLY_WITH_IMMEDIATE:
		with_imm = 1;
		/* pass through */

	case IB_OPCODE_RC_SEND_ONLY:
		init  = 1;
		finit = 1;
		min   = 0;
		max   = pmtu;
		break;

	case IB_OPCODE_RC_SEND_FIRST:
		init  = 1;
		min   = pmtu;
		max   = pmtu;
		break;

	case IB_OPCODE_RC_SEND_LAST_WITH_IMMEDIATE:
		with_imm = 1;
		/* pass through */

	case IB_OPCODE_RC_SEND_LAST:
		finit = 1;
		min   = 1;
		max   = pmtu;
		break;

	case IB_OPCODE_RC_SEND_MIDDLE:
		min   = pmtu;
		max   = pmtu;
		break;

	default:
		BUG();
	}

	if (init) {
		qp->responder.offset = 0;

		if (qp->ib_qp_init_attr.srq) {
			/* To simplify implementation, move one RWQE from SRQ to RQ */
			recv_wqe = pib_util_get_srq(to_psrq(qp->ib_qp_init_attr.srq));

			if (recv_wqe) {
				list_add_tail(&recv_wqe->list, &qp->responder.recv_wqe_head);
				qp->responder.nr_recv_wqe++;
			}
		}
	}

	if (list_empty(&qp->responder.recv_wqe_head))
		goto resources_not_ready;

	if (with_imm) {
		if (size < 4)
			goto nak_invalid_request;

		imm_data = *(__be32*)buffer;

		buffer += 4;
		size   -= 4;
	}

	if ((size < min) || (max < size))
		goto nak_invalid_request;

	recv_wqe = list_first_entry(&qp->responder.recv_wqe_head, struct pib_ib_recv_wqe, list);

	/* @todo offset 超過もチェックを */

	pd = to_ppd(qp->ib_qp.pd);

	spin_lock_irqsave(&pd->lock, flags);
	status = pib_util_mr_copy_data(pd, recv_wqe->sge_array, recv_wqe->num_sge,
				       buffer, qp->responder.offset, size,
				       IB_ACCESS_LOCAL_WRITE,
				       PIB_MR_COPY_TO);
	spin_unlock_irqrestore(&pd->lock, flags);

	switch (status) {
	case IB_WC_SUCCESS:
		break;

	case IB_WC_LOC_LEN_ERR:
		syndrome = PIB_IB_NAK_CODE_INV_REQ_ERR;
		goto completion_error;

	default:
		syndrome = PIB_IB_NAK_CODE_REM_OP_ERR;
		goto completion_error;
	}

	qp->responder.offset += size;

	if (finit) {
		struct ib_wc wc = {
			.wr_id       = recv_wqe->wr_id,
			.status      = IB_WC_SUCCESS,
			.opcode      = IB_WC_RECV,
			.byte_len    = qp->responder.offset,
			.qp          = &qp->ib_qp,
			.ex.imm_data = imm_data,
			.src_qp      = 0,
			.slid        = lrh->SLID,
			.wc_flags    = with_imm ? IB_WC_WITH_IMM : 0,
		};

		int ret;

		ret = pib_util_insert_wc_success(qp->recv_cq, &wc); /* @todo */

		qp->push_rcqe = 1;
		
		list_del_init(&recv_wqe->list);
		qp->responder.nr_recv_wqe--;

		pib_util_free_recv_wqe(qp, recv_wqe);
	}

	push_acknowledge(qp, psn, PIB_IB_ACK_CODE);

	return 1; /* 1 packet */

resources_not_ready:
	push_acknowledge(qp, psn, get_resources_not_ready(qp));

	return -1;

nak_invalid_request:
	push_acknowledge(qp, psn, PIB_IB_NAK_CODE_INV_REQ_ERR);

	/* Invalid Request Local Work Queue Error */
	insert_async_qp_error(dev, qp, IB_EVENT_QP_REQ_ERR);

	return -1;

completion_error:
	pib_util_insert_wc_error(qp->recv_cq, qp, recv_wqe->wr_id, status,
				 IB_WC_RECV);

	qp->push_rcqe = 1;

	list_del_init(&recv_wqe->list);
	qp->responder.nr_recv_wqe--;
	pib_util_free_recv_wqe(qp, recv_wqe);

	push_acknowledge(qp, psn, syndrome);

	qp->state = IB_QPS_ERR;
	pib_util_flush_qp(qp, 0);

	return -1;
}


static int
receive_RDMA_WRITE_request(struct pib_ib_dev *dev, u8 port_num, u32 psn, int OpCode, struct pib_ib_qp *qp, void *buffer, int size, struct pib_packet_lrh *lrh)
{
	int init = 0;
	int finit = 0;
	int with_reth = 0;
	int with_imm = 0;
	int pmtu, min, max;
	__be32 imm_data = 0;
	struct pib_ib_recv_wqe *recv_wqe = NULL;
	struct pib_ib_pd *pd;
	enum ib_wc_status status = IB_WC_SUCCESS;
	unsigned long flags;

	pmtu = (128U << qp->ib_qp_attr.path_mtu);

	switch (OpCode) {

	case IB_OPCODE_RC_RDMA_WRITE_ONLY_WITH_IMMEDIATE:
		with_imm = 1;
		/* pass through */

	case IB_OPCODE_RC_RDMA_WRITE_ONLY:
		with_reth = 1;
		init  = 1;
		finit = 1;
		min   = 0;
		max   = pmtu;
		break;

	case IB_OPCODE_RC_RDMA_WRITE_FIRST:
		with_reth = 1;
		init  = 1;
		min   = pmtu;
		max   = pmtu;
		break;

	case IB_OPCODE_RC_RDMA_WRITE_LAST_WITH_IMMEDIATE:
		with_imm  = 1;
		/* pass through */

	case IB_OPCODE_RC_RDMA_WRITE_LAST:
		finit = 1;
		min   = 1;
		max   = pmtu;
		break;

	case IB_OPCODE_RC_RDMA_WRITE_MIDDLE:
		min   = pmtu;
		max   = pmtu;
		break;

	default:
		BUG();
	}

	if (init) {
		struct pib_packet_reth *reth;

		if (size < sizeof(struct pib_packet_reth))
			goto nak_invalid_request;

		reth = (struct pib_packet_reth*)buffer;

		buffer += sizeof(struct pib_packet_reth);
		size   -= sizeof(struct pib_packet_reth);

		qp->responder.offset            = 0;
		qp->responder.rdma_write.vaddr  = ((u64)reth->VA_hi << 32) | reth->VA_lo;
		qp->responder.rdma_write.rkey   = reth->R_Key;
		qp->responder.rdma_write.dmalen = reth->DMALen;
	}

	if (with_imm) {
		if (qp->ib_qp_init_attr.srq) {
			/* To simplify implementation, move one RWQE from SRQ to RQ */
			recv_wqe = pib_util_get_srq(to_psrq(qp->ib_qp_init_attr.srq));

			if (recv_wqe) {
				list_add_tail(&recv_wqe->list, &qp->responder.recv_wqe_head);
				qp->responder.nr_recv_wqe++;
			}
		}

		if (list_empty(&qp->responder.recv_wqe_head))
			goto resources_not_ready;

		recv_wqe = list_first_entry(&qp->responder.recv_wqe_head, struct pib_ib_recv_wqe, list);

		if (size < 4)
			goto nak_invalid_request;

		imm_data = *(__be32*)buffer;

		buffer += 4;
		size   -= 4;
	}

	if ((size < min) || (max < size))
		goto nak_invalid_request;

	if (qp->responder.rdma_write.dmalen < qp->responder.offset + size)
		goto nak_invalid_request;

	if (finit && (qp->responder.rdma_write.dmalen != qp->responder.offset + size))
		goto nak_invalid_request;

	if (PIB_IB_MAX_PAYLOAD_LEN <= qp->responder.rdma_write.dmalen) {
		status = IB_WC_LOC_LEN_ERR;
		goto skip;
	}

	pd = to_ppd(qp->ib_qp.pd);

	spin_lock_irqsave(&pd->lock, flags);
	status = pib_util_mr_copy_data_with_rkey(pd, qp->responder.rdma_write.rkey,
						 buffer,
						 qp->responder.rdma_write.vaddr + qp->responder.offset,
						 size,
						 IB_ACCESS_LOCAL_WRITE | IB_ACCESS_REMOTE_WRITE,
						 PIB_MR_COPY_TO);
	spin_unlock_irqrestore(&pd->lock, flags);

	/*
	 * IBA Spec. Vol.1 10.7.2.2 states the following sentence
	 *
	 *   C10-87: The responder’s Receive Queue shall not consume a Work
	 *           Request when Immediate Data is not specified in an incoming
	 *           RDMA Write or the incoming RDMA Write was not successfully
	 *           completed.
	 *
	 * But the behavior of Mellanox's HCAs is that an error may generate a
	 * completion error on a receive queue.
	 */
	if (status != IB_WC_SUCCESS) {
	skip:		
		if (with_imm && !pib_ib_get_behavior(dev, PIB_BEHAVIOR_RDMA_WRITE_WITH_IMM_ALWAYS_ASYNC_ERR))
			goto completion_error;
		else
			goto asynchronous_error;
	}

	qp->responder.offset += size;

	if (finit && with_imm) {
		int ret;
		struct ib_wc wc = {
			.wr_id       = recv_wqe->wr_id,
			.status      = IB_WC_SUCCESS,
			.opcode      = IB_WC_RECV_RDMA_WITH_IMM,
			.byte_len    = qp->responder.offset,
			.qp          = &qp->ib_qp,
			.ex.imm_data = imm_data,
			.src_qp      = 0,
			.slid        = lrh->SLID,
			.wc_flags    = IB_WC_WITH_IMM,
		};

		ret = pib_util_insert_wc_success(qp->recv_cq, &wc); /* @todo */

		qp->push_rcqe = 1;
		
		list_del_init(&recv_wqe->list);
		qp->responder.nr_recv_wqe--;

		pib_util_free_recv_wqe(qp, recv_wqe);
	}

	push_acknowledge(qp, psn, PIB_IB_ACK_CODE);

	return 1; /* 1 packet */

resources_not_ready:
	push_acknowledge(qp, psn, get_resources_not_ready(qp));

	return -1;

nak_invalid_request:
	/* Invalid Request Local Work Queue Error */
	push_acknowledge(qp, psn, PIB_IB_NAK_CODE_INV_REQ_ERR);
	insert_async_qp_error(dev, qp, IB_EVENT_QP_REQ_ERR);

	return -1;

asynchronous_error:
	pib_util_insert_async_qp_error(qp, IB_EVENT_QP_ACCESS_ERR);

	abort_active_rwqe(dev, qp);

	goto common_error;

completion_error:
	pib_util_insert_wc_error(qp->recv_cq, qp, recv_wqe->wr_id, status,
				 IB_WC_RECV_RDMA_WITH_IMM);

	qp->push_rcqe = 1;

	list_del_init(&recv_wqe->list);
	qp->responder.nr_recv_wqe--;
	pib_util_free_recv_wqe(qp, recv_wqe);

common_error:
	switch (status) {
	case IB_WC_LOC_LEN_ERR:
		push_acknowledge(qp, psn, PIB_IB_NAK_CODE_INV_REQ_ERR);
		break;

	default:
		push_acknowledge(qp, psn, PIB_IB_NAK_CODE_REM_ACCESS_ERR);
		break;
	}

	qp->state = IB_QPS_ERR;
	pib_util_flush_qp(qp, 0);

	return -1;
}


static int
receive_Atomic_request(struct pib_ib_dev *dev, u8 port_num, u32 psn, int OpCode, struct pib_ib_qp *qp, void *buffer, int size)
{
	struct pib_packet_atomiceth *atomiceth;
	struct pib_ib_pd *pd;
	enum ib_wc_status status;
	struct pib_ib_rd_atom_slot slot;
	u64 vaddr;
	u64 result;
	unsigned long flags;

	if (size != sizeof(struct pib_packet_atomiceth)) {
		/* Invalid Request Local Work Queue Error */
		push_acknowledge(qp, psn, PIB_IB_NAK_CODE_INV_REQ_ERR);
		insert_async_qp_error(dev, qp, IB_EVENT_QP_REQ_ERR);
		return -1;
	}

	atomiceth  = (struct pib_packet_atomiceth *)buffer;

	vaddr = ((u64)atomiceth->VA_hi << 32) | atomiceth->VA_lo;

	if ((vaddr % 8) != 0) {
		/* Local Access Violation Work Queue Error */
		push_acknowledge(qp, psn, PIB_IB_NAK_CODE_INV_REQ_ERR);
		insert_async_qp_error(dev, qp, IB_EVENT_QP_ACCESS_ERR);
		return -1;
	}

	if (qp->ib_qp_attr.max_dest_rd_atomic <= qp->responder.nr_rd_atomic) {
		push_acknowledge(qp, psn, PIB_IB_NAK_CODE_INV_REQ_ERR);
		insert_async_qp_error(dev, qp, IB_EVENT_QP_ACCESS_ERR);
		return -1;
	}

	pd = to_ppd(qp->ib_qp.pd);

	spin_lock_irqsave(&pd->lock, flags);
	status = pib_util_mr_atomic(pd, atomiceth->R_Key, vaddr,
				    ((u64)atomiceth->SwapDt_hi << 32) | atomiceth->SwapDt_lo,
				    ((u64)atomiceth->CmpDt_hi  << 32) | atomiceth->CmpDt_lo,
				    &result,
				    (OpCode == IB_WR_ATOMIC_CMP_AND_SWP) ? PIB_MR_CAS : PIB_MR_FETCHADD);
	spin_unlock_irqrestore(&pd->lock, flags);

	if (status != IB_WC_SUCCESS) {
		/* Local Access Violation Work Queue Error */
		push_acknowledge(qp, psn, PIB_IB_NAK_CODE_REM_ACCESS_ERR);
		insert_async_qp_error(dev, qp, IB_EVENT_QP_ACCESS_ERR);
		return -1;
	}

	slot.OpCode          = OpCode;
	slot.psn             = qp->responder.psn;
	slot.expected_psn    = qp->responder.psn + 1;
	slot.data.atomic.res = result;

	qp->responder.slots[(qp->responder.slot_index++) % PIB_IB_MAX_RD_ATOM] = slot;

	push_atomic_acknowledge(qp, psn, result);

	return 1; /* 1 packet */
}


static int
receive_RDMA_READ_request(struct pib_ib_dev *dev, u8 port_num, u32 psn, struct pib_ib_qp *qp, void *buffer, int size, int new_request, int slot_index)
{
	int ret;
	struct pib_packet_reth *reth;
	u64 remote_addr;
	u32 rkey;
	u32 dmalen;
	u32 num_packets;
	struct pib_ib_rd_atom_slot slot;
	struct pib_ib_pd *pd;
	enum ib_wc_status status = IB_WC_SUCCESS;
	unsigned long flags;

	if (size != sizeof(struct pib_packet_reth))
		goto nak_invalid_request;

	reth    = (struct pib_packet_reth*)buffer;

	remote_addr = ((u64)reth->VA_hi << 32) | reth->VA_lo;
	rkey        = reth->R_Key;
	dmalen      = reth->DMALen;

	/* Check */
	if (PIB_IB_MAX_PAYLOAD_LEN <= dmalen)
		goto legth_error_or_too_many_rdma_read;

	if (qp->ib_qp_attr.max_dest_rd_atomic <= qp->responder.nr_rd_atomic)
		goto legth_error_or_too_many_rdma_read;

	pd = to_ppd(qp->ib_qp.pd);

	spin_lock_irqsave(&pd->lock, flags);
	status = pib_util_mr_validate_rkey(pd, rkey, remote_addr, dmalen, IB_ACCESS_REMOTE_READ);
	spin_unlock_irqrestore(&pd->lock, flags);

	if (status != IB_WC_SUCCESS) {
		/* Local Access Violation Work Queue Error */
		push_acknowledge(qp, psn, PIB_IB_NAK_CODE_REM_ACCESS_ERR);
		insert_async_qp_error(dev, qp, IB_EVENT_QP_ACCESS_ERR);
		return -1;
	}

	num_packets = pib_get_num_of_packets(qp, dmalen);

	if (new_request) {
		/* new RMDA READ Request */
		struct pib_ib_rd_atom_slot overwrite_slot;

		if (qp->ib_qp_attr.max_dest_rd_atomic <= qp->responder.nr_rd_atomic)
			goto legth_error_or_too_many_rdma_read;

		overwrite_slot = qp->responder.slots[((unsigned int)(qp->responder.slot_index - qp->ib_qp_attr.max_dest_rd_atomic)) % PIB_IB_MAX_RD_ATOM];

		slot.OpCode                  = IB_OPCODE_RC_RDMA_READ_REQUEST;
		slot.psn                     = qp->responder.psn;
		slot.expected_psn            = qp->responder.psn + num_packets;
		slot.data.rdma_read.vaddress = remote_addr;
		slot.data.rdma_read.rkey     = rkey;
		slot.data.rdma_read.dmalen   = dmalen;

		qp->responder.slots[(qp->responder.slot_index++) % PIB_IB_MAX_RD_ATOM] = slot;

		push_rdma_read_acknowledge(qp, psn, slot.expected_psn, remote_addr, rkey, dmalen, 0);

		/* rq_psn は RDMA READ response packets を投げる前に一気に進める */
		ret = num_packets;
		
	} else {
		/* Retried RMDA READ Request */
		u32 offset;

		slot = qp->responder.slots[slot_index];

		offset = (get_psn_diff(psn, slot.psn) * 128U << qp->ib_qp_attr.path_mtu);

		if ((slot.data.rdma_read.rkey != rkey) ||
		    (slot.data.rdma_read.vaddress + offset != remote_addr) ||
		    (slot.data.rdma_read.dmalen   - offset != dmalen))
		    goto nak_invalid_request;

		push_rdma_read_acknowledge(qp, psn, slot.expected_psn, remote_addr, rkey, dmalen, 1);

		ret = 0; /* Don't go ahead of rq_psn */
	}

	return ret;

nak_invalid_request:
	push_acknowledge(qp, psn, PIB_IB_NAK_CODE_INV_REQ_ERR);

	/* Invalid Request Local Work Queue Error */
	insert_async_qp_error(dev, qp, IB_EVENT_QP_REQ_ERR);

	return -1;

legth_error_or_too_many_rdma_read:
	push_acknowledge(qp, psn, PIB_IB_NAK_CODE_INV_REQ_ERR);
	insert_async_qp_error(dev, qp, IB_EVENT_QP_ACCESS_ERR);

	return -1;
}


static void
push_acknowledge(struct pib_ib_qp *qp, u32 psn, enum pib_ib_syndrome syndrome)
{
	struct pib_ib_ack *ack;

	ack = kmem_cache_zalloc(pib_ib_ack_cachep, GFP_ATOMIC);
	if (!ack)
		return;

	ack->type		= PIB_IB_ACK_NORMAL;
	ack->psn		= psn;
	ack->expected_psn	= psn + 1;

	list_add_tail(&ack->list, &qp->responder.ack_head);
}


static void
push_rdma_read_acknowledge(struct pib_ib_qp *qp, u32 psn, u32 expected_psn, u64 vaddress, u32 rkey, u32 size, int retried)
{
	struct pib_ib_ack *ack, *ack_next;

	if (retried) {
		/* @todo 現在の acknowledge を全部破棄する */
		list_for_each_entry_safe_reverse(ack, ack_next, &qp->responder.ack_head, list) {
			list_del_init(&ack->list);
			kmem_cache_free(pib_ib_ack_cachep, ack);
		}
		qp->responder.nr_rd_atomic = 0;
	}

	ack = kmem_cache_zalloc(pib_ib_ack_cachep, GFP_ATOMIC);
	if (!ack)
		return;

	ack->type		= PIB_IB_ACK_RMDA_READ;
	ack->psn		= psn;
	ack->expected_psn	= expected_psn;

	ack->data.rdma_read.vaddress	= vaddress;
	ack->data.rdma_read.rkey	= rkey;
	ack->data.rdma_read.size	= size;

	list_add_tail(&ack->list, &qp->responder.ack_head);

	qp->responder.nr_rd_atomic++;
}


static void
push_atomic_acknowledge(struct pib_ib_qp *qp, u32 psn, u64 res)
{
	struct pib_ib_ack *ack;

	ack = kmem_cache_zalloc(pib_ib_ack_cachep, GFP_ATOMIC);
	if (!ack)
		return;

	ack->type		= PIB_IB_ACK_ATOMIC;
	ack->psn		= psn;
	ack->expected_psn	= psn + 1;

	ack->data.atomic.res	= res;

	list_add_tail(&ack->list, &qp->responder.ack_head);

	qp->responder.nr_rd_atomic++;
}


/******************************************************************************/
/* Responder: Generating Acknowledge Packets                                  */
/******************************************************************************/

void pib_generate_rc_qp_acknowledge(struct pib_ib_dev *dev, struct pib_ib_qp *qp)
{
	u8 port_num;
	u16 dlid;
	struct sockaddr *sockaddr;
	struct pib_ib_ack *ack, *ack_next;

	if (!pib_is_recv_ok(qp->state))
		return;

	port_num = qp->ib_qp_attr.port_num;
	dlid     = qp->ib_qp_attr.ah_attr.dlid;

	sockaddr = dev->ports[port_num - 1].lid_table[dlid];

	if (!sockaddr) {
		debug_printk("Not found the destination address in ld_table (ah.dlid=%u)", dlid);
		return; /* @todo */
	}

restart:
	if (list_empty(&qp->responder.ack_head))
		return;

	/* IBA Spec. Vol.1 9.7.5.1.2. Coalesced Acknowledge Messages */
	ack = list_first_entry(&qp->responder.ack_head, struct pib_ib_ack, list);

	if (ack->type == PIB_IB_ACK_NORMAL && ((ack->syndrome >> 5) == 0)) {
		struct pib_ib_ack ack_tmp = *ack;

		list_for_each_entry_safe(ack, ack_next, &qp->responder.ack_head, list) {
			if (ack->type == PIB_IB_ACK_NORMAL && ((ack->syndrome >> 5) == 0)) {
				list_del_init(&ack->list);
				kmem_cache_free(pib_ib_ack_cachep, ack);
			} else
				break;
		}
		generate_Normal_or_Atomic_acknowledge(dev, port_num, qp, &ack_tmp, sockaddr);

		goto restart;
	}

	/* Other acknowledges */

	switch (ack->type) {

	case PIB_IB_ACK_ATOMIC:
		generate_Normal_or_Atomic_acknowledge(dev, port_num, qp, ack, sockaddr);
		qp->responder.nr_rd_atomic--;
		break;

	case PIB_IB_ACK_NORMAL:
		generate_Normal_or_Atomic_acknowledge(dev, port_num, qp, ack, sockaddr);
		break;

	case PIB_IB_ACK_RMDA_READ:
		do {
			generate_RDMA_READ_response(dev, port_num, qp, ack, sockaddr);
		} while ((ack->data.rdma_read.offset < ack->data.rdma_read.size) &&
			 (dev->thread.flags & PIB_THREAD_READY_TO_DATA) == 0);

		qp->responder.nr_rd_atomic--;
		break;

	default:
		BUG();
	}

	list_del_init(&ack->list);
	kmem_cache_free(pib_ib_ack_cachep, ack);

	goto restart;
}


static int
generate_Normal_or_Atomic_acknowledge(struct pib_ib_dev *dev, u8 port_num, struct pib_ib_qp *qp, struct pib_ib_ack *ack, struct sockaddr *sockaddr)
{
	int ret, size;
	struct msghdr msghdr;
	struct kvec iov;

	if (ack->type == PIB_IB_ACK_NORMAL)
		size = pack_acknowledge_packet(dev, port_num, qp,
					       IB_OPCODE_RC_ACKNOWLEDGE, ack->psn,
					       1, ack->syndrome, 0, 0);
	else
		size = pack_acknowledge_packet(dev, port_num, qp,
					       IB_OPCODE_RC_ATOMIC_ACKNOWLEDGE, ack->psn,
					       1, PIB_IB_ACK_CODE, 1, ack->data.atomic.res);

	memset(&msghdr, 0, sizeof(msghdr));
	
	msghdr.msg_name    = sockaddr;
	msghdr.msg_namelen = (sockaddr->sa_family == AF_INET6) ?
		sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);

	iov.iov_base = dev->thread.buffer;
	iov.iov_len  = size;

	ret = kernel_sendmsg(dev->ports[port_num - 1].socket, &msghdr, &iov, 1, iov.iov_len);

	return ret;
}


static int
generate_RDMA_READ_response(struct pib_ib_dev *dev, u8 port_num, struct pib_ib_qp *qp, struct pib_ib_ack *ack, struct sockaddr *sockaddr)
{
	int ret, pmtu, size;
	int with_aeth = 1;
	u32 psn_offset;
	int OpCode;
	struct pib_ib_pd *pd;
	struct msghdr msghdr;
	struct kvec iov;
	u32 payload_size;
	enum ib_wc_status status;
	unsigned long flags;

	pmtu = (128U << qp->ib_qp_attr.path_mtu);

	psn_offset = ack->data.rdma_read.offset / 128U >> qp->ib_qp_attr.path_mtu;

	if (ack->expected_psn - ack->psn == 1)
		OpCode = IB_OPCODE_RC_RDMA_READ_RESPONSE_ONLY;
	else if (psn_offset == 0)
		OpCode = IB_OPCODE_RC_RDMA_READ_RESPONSE_FIRST;
	else if (ack->expected_psn > ack->psn + psn_offset + 1) {
		OpCode = IB_OPCODE_RC_RDMA_READ_RESPONSE_MIDDLE;
		with_aeth = 0;
	} else 
		OpCode = IB_OPCODE_RC_RDMA_READ_RESPONSE_LAST;

	/* ここからパケット送信 */

	size = pack_acknowledge_packet(dev, port_num, qp, OpCode, ack->psn + psn_offset,
				       with_aeth, PIB_IB_ACK_CODE, 0, 0);

	payload_size = (ack->data.rdma_read.size - ack->data.rdma_read.offset < pmtu) ?
		(ack->data.rdma_read.size - ack->data.rdma_read.offset) : pmtu;

	((struct pib_packet_lrh*)dev->thread.buffer)->PktLen += payload_size / 4;

	pd = to_ppd(qp->ib_qp.pd);

	spin_lock_irqsave(&pd->lock, flags);
	status = pib_util_mr_copy_data_with_rkey(pd,
						 ack->data.rdma_read.rkey,
						 dev->thread.buffer + size,
						 ack->data.rdma_read.vaddress + ack->data.rdma_read.offset,
						 payload_size,
						 IB_ACCESS_REMOTE_READ,
						 PIB_MR_COPY_FROM);
	spin_unlock_irqrestore(&pd->lock, flags);

	if (status != IB_WC_SUCCESS)
		/* receive_RDMA_READ_request でチェックしているから本当はないはず */
		return status;

	memset(&msghdr, 0, sizeof(msghdr));
	
	msghdr.msg_name    = sockaddr;
	msghdr.msg_namelen = (sockaddr->sa_family == AF_INET6) ?
		sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);

	iov.iov_base = dev->thread.buffer;
	iov.iov_len  = size + payload_size;

	ret = kernel_sendmsg(dev->ports[port_num - 1].socket, &msghdr, &iov, 1, iov.iov_len);
	
	ack->data.rdma_read.offset += payload_size;

	return ret;
}


static int
pack_acknowledge_packet(struct pib_ib_dev *dev, u8 port_num, struct pib_ib_qp *qp, int OpCode, u32 psn, int with_aeth, enum pib_ib_syndrome syndrome, int with_atomiceth, u64 res)
{
	int size;
	struct pib_packet_rc_acknowledge *message;

	/* @todo not yet implemented credit count */

	message = (struct pib_packet_rc_acknowledge*)dev->thread.buffer;

	message->lrh.VL       = 0;
	message->lrh.LVer     = 0;
	message->lrh.SL       = qp->ib_qp_attr.ah_attr.sl;
	message->lrh.LNH      = 1; /* Transport: IBA & Next Header: BTH */
	message->lrh.DLID     = qp->ib_qp_attr.ah_attr.dlid;
	message->lrh.SLID     = dev->ports[port_num - 1].ib_port_attr.lid;

	message->bth.OpCode   = OpCode;
	message->bth.SE       = 0;
	message->bth.M        = 0;
	message->bth.TVer     = 0;
	message->bth.P_Key    = qp->ib_qp_attr.pkey_index;
	message->bth.DestQP   = qp->ib_qp_attr.dest_qp_num;
	message->bth.A        = 0;
	message->bth.PadCnt   = 0; 
	message->bth.PSN      = psn;

	size = sizeof(struct pib_packet_lrh) + sizeof(struct pib_packet_bth); 

	if (with_aeth) {
		message->aeth.MSN      = 0; /* @todo */
		message->aeth.Syndrome = syndrome;
		
		size += sizeof(struct pib_packet_aeth);
	} 

	if (with_atomiceth) {
		struct pib_packet_atomicacketh *atomicacketh;
		atomicacketh = (struct pib_packet_atomicacketh*)(dev->thread.buffer + sizeof(struct pib_packet_rc_acknowledge));
		atomicacketh->OrigRemDt_hi = res >> 32;
		atomicacketh->OrigRemDt_lo = res;

		size += sizeof(struct pib_packet_atomicacketh);
	}

	message->lrh.PktLen = size / 4;

	return size;
}


/******************************************************************************/
/* Requester: Receiving Responses                                             */
/******************************************************************************/

static int
receive_response(struct pib_ib_dev *dev, u8 port_num, struct pib_ib_qp *qp, void *buffer, int size, struct pib_packet_lrh *lrh, struct pib_packet_bth *bth)
{
	int ret;
	u32 psn;
	unsigned long rnr_nak_timeout = 0;
	struct pib_packet_aeth *aeth;
	struct pib_ib_send_wqe *send_wqe, *next_send_wqe;

	/* response's PSN */
	psn = bth->PSN;

	if (bth->OpCode == IB_OPCODE_RC_RDMA_READ_RESPONSE_MIDDLE)
		/* RDMA READ response Middle packets have no AETH. */
		goto switch_OpCode;

	if (size < sizeof(struct pib_packet_aeth))
		/* @todo これはエラーにとらないでいいか？ */
		return 0;

	aeth       = (struct pib_packet_aeth*)buffer;
	buffer    += sizeof(struct pib_packet_aeth);
	size      -= sizeof(struct pib_packet_aeth);

	switch (aeth->Syndrome >> 5) {
	case 0:
		/* ACK */
		break;

	case 1:
		/* RNR NAK */
		rnr_nak_timeout = pib_get_rnr_nak_time(aeth->Syndrome & 0x1F);
		goto retry_send;

	case 3:
		/* NAK */
		switch (aeth->Syndrome) {

		case PIB_IB_NAK_CODE_PSN_SEQ_ERR:
			/* PSN Sequence Error */
			/* @todo PSN Sequence Error を RNR NAK と同様に扱ってリトライをかけるが
			   これは正しい仕様か？ */
			goto retry_send;

		case PIB_IB_NAK_CODE_INV_REQ_ERR:
			/* Remote Invalid Request Error */
			set_send_wqe_to_error(qp, psn, IB_WC_REM_INV_REQ_ERR);
			break;

		case PIB_IB_NAK_CODE_REM_ACCESS_ERR:
			/* Remote Access Error */
			set_send_wqe_to_error(qp, psn, IB_WC_REM_ACCESS_ERR);
			break;

		case PIB_IB_NAK_CODE_REM_OP_ERR:
			/* Remote Operational Error */
			set_send_wqe_to_error(qp, psn, IB_WC_REM_OP_ERR);
			break;

		case PIB_IB_NAK_CODE_INV_RD_REQ_ERR:
			/* Invalid RD Request */
			set_send_wqe_to_error(qp, psn, IB_WC_REM_INV_RD_REQ_ERR); /* @todo ? */
			break;
		}
		break;

	default:
		/* silently drop */
		return -1;
	}

switch_OpCode:
	switch (bth->OpCode) {

	case IB_OPCODE_RC_ACKNOWLEDGE:
		ret = receive_ACK_response(dev, port_num, qp, psn);
		break;

	case IB_OPCODE_RC_RDMA_READ_RESPONSE_FIRST:
	case IB_OPCODE_RC_RDMA_READ_RESPONSE_LAST:
	case IB_OPCODE_RC_RDMA_READ_RESPONSE_ONLY:
		ret = receive_RDMA_READ_response(dev, port_num, qp, psn, buffer, size);
		break;

	case IB_OPCODE_RC_RDMA_READ_RESPONSE_MIDDLE:
		ret = receive_RDMA_READ_response(dev, port_num, qp, psn, buffer, size);
		break;

	case IB_OPCODE_RC_ATOMIC_ACKNOWLEDGE:
		ret =receive_Atomic_response(dev, port_num, qp, psn, buffer, size);
		break;

	default:
		BUG();
	}

	if ((qp->state == IB_QPS_SQD) && !qp->issue_sq_drained)
		if (list_empty(&qp->requester.sending_swqe_head) &&
		    list_empty(&qp->requester.waiting_swqe_head)) {
			pib_util_insert_async_qp_event(qp, IB_EVENT_SQ_DRAINED);
			qp->issue_sq_drained = 1;
		}

	return ret;

retry_send:
	/* waiting list から sending list へ戻す */
	list_for_each_entry_safe_reverse(send_wqe, next_send_wqe, &qp->requester.waiting_swqe_head, list) {
		send_wqe->processing.list_type = PIB_SWQE_SENDING;
		list_del_init(&send_wqe->list);
		list_add_tail(&send_wqe->list, &qp->requester.sending_swqe_head);
		qp->requester.nr_waiting_swqe--;
		qp->requester.nr_sending_swqe++;
	}

	/* 送信したパケット数をキャンセルする */
	list_for_each_entry(send_wqe, &qp->requester.sending_swqe_head, list) {
		send_wqe->processing.sent_packets = send_wqe->processing.ack_packets;
	}

	/* 最初の Send WQE が SEND また RDMA WRITE w/Immediate なら rnr_retry を減算する */
	if (rnr_nak_timeout && !list_empty(&qp->requester.sending_swqe_head)) {
		send_wqe = list_first_entry(&qp->requester.sending_swqe_head, struct pib_ib_send_wqe, list);

		switch (send_wqe->opcode) {
		case IB_WR_SEND:
		case IB_WR_SEND_WITH_IMM:
		case IB_WR_RDMA_WRITE_WITH_IMM:
			send_wqe->processing.schedule_time = rnr_nak_timeout;
				
			if (qp->ib_qp_attr.rnr_retry < 7) /* The value of 7 means infinity */
				send_wqe->processing.rnr_retry--;
			break;

		default:
			break;
		}
	}

	return -1;
}


/*
 *  QP 内の送信中の SEND WR から psn にあたるものを status の completion error とする。
 */
static void
set_send_wqe_to_error(struct pib_ib_qp *qp, u32 psn, enum ib_wc_status status)
{
	struct pib_ib_send_wqe *send_wqe;

	list_for_each_entry(send_wqe, &qp->requester.waiting_swqe_head, list) {
		if ((get_psn_diff(psn, send_wqe->processing.based_psn)       >= 0) &&
		    (get_psn_diff(psn, send_wqe->processing.expected_psn) <  0)) {
			send_wqe->processing.status = status;
			return;
		}
	}

	list_for_each_entry(send_wqe, &qp->requester.sending_swqe_head, list) {
		if ((get_psn_diff(psn, send_wqe->processing.based_psn)       >= 0) &&
		    (get_psn_diff(psn, send_wqe->processing.expected_psn) <  0)) {
			send_wqe->processing.status = status;
			return;
		}
	}

	/* silently drop */
}


enum {
	RET_ERROR        = -1,
	RET_CONTINUE     =  0,
	RET_STOP         =  1
};


static int
receive_ACK_response(struct pib_ib_dev *dev, u8 port_num, struct pib_ib_qp *qp, u32 psn)
{
	struct pib_ib_send_wqe *send_wqe, *next_send_wqe;

	/* process_acknowledge */

	list_for_each_entry_safe(send_wqe, next_send_wqe, &qp->requester.waiting_swqe_head, list) {

		switch (process_acknowledge(dev, qp, send_wqe, psn, &qp->requester.nr_waiting_swqe)) {

		case RET_ERROR:
			list_del_init(&send_wqe->list);
			qp->requester.nr_waiting_swqe--;
			goto completion_error;
			
		case RET_CONTINUE:
			list_del_init(&send_wqe->list);
			qp->requester.nr_waiting_swqe--;
			pib_util_free_send_wqe(qp, send_wqe);
			break;

		case RET_STOP:
			return -1;
		}
	}

	list_for_each_entry_safe(send_wqe, next_send_wqe, &qp->requester.sending_swqe_head, list) {

		switch (process_acknowledge(dev, qp, send_wqe, psn, &qp->requester.nr_sending_swqe)) {

		case RET_ERROR:
			list_del_init(&send_wqe->list);
			qp->requester.nr_sending_swqe--;
			goto completion_error;
			
		case RET_CONTINUE:
			list_del_init(&send_wqe->list);
			qp->requester.nr_sending_swqe--;
			pib_util_free_send_wqe(qp, send_wqe);
			break;

		case RET_STOP:
			return -1;
		}
	}

	/* @todo check out of sequence ? */

	/* @todo QP を再 enqueue する条件を考えよ */

	return -1;

completion_error:
	pib_util_insert_wc_error(qp->send_cq, qp, send_wqe->wr_id,
				 send_wqe->processing.status, send_wqe->opcode);

	pib_util_free_send_wqe(qp, send_wqe);

	qp->state = IB_QPS_ERR;
	pib_util_flush_qp(qp, 0);

	return -1;
}


/*
 *
 */
static int
process_acknowledge(struct pib_ib_dev *dev, struct pib_ib_qp *qp, struct pib_ib_send_wqe *send_wqe, u32 psn, int *nr_swqe_p)
{
	u32 no_packets;
	s32 psn_diff;

	if (send_wqe->processing.status != IB_WC_SUCCESS)
		return RET_ERROR;

	psn_diff = get_psn_diff(psn, send_wqe->processing.based_psn);

	if (psn_diff < 0)
		/* Ignore ghost acknowledge */
		return RET_STOP;

	no_packets = send_wqe->processing.all_packets - psn_diff;
		
	if (no_packets < send_wqe->processing.ack_packets)
		/* Ignore duplicated acknowledge */
		return RET_STOP;

	switch (send_wqe->opcode) {

	case IB_WR_RDMA_READ:
	case IB_WR_ATOMIC_CMP_AND_SWP:
	case IB_WR_ATOMIC_FETCH_AND_ADD:
		send_wqe->processing.status = IB_WC_BAD_RESP_ERR;
		return RET_ERROR;

	default:
		break;
	}

	if (no_packets < send_wqe->processing.all_packets) {
		/* Left packets to send */
		send_wqe->processing.ack_packets = no_packets;
		return RET_STOP;
	}

	/* Complete to send */

	if ((qp->ib_qp_init_attr.sq_sig_type == IB_SIGNAL_ALL_WR) || 
	    (send_wqe->send_flags & IB_SEND_SIGNALED)) {
		int ret;
		struct ib_wc wc = {
			.wr_id    = send_wqe->wr_id,
			.status   = IB_WC_SUCCESS,
			.opcode   = pib_convert_wr_opcode_to_wc_opcode(send_wqe->opcode),
			.qp       = &qp->ib_qp,
		};

		ret = pib_util_insert_wc_success(qp->send_cq, &wc);
	}

	qp->requester.psn = send_wqe->processing.expected_psn;

	return RET_CONTINUE;
}


static int
receive_RDMA_READ_response(struct pib_ib_dev *dev, u8 port_num, struct pib_ib_qp *qp, u32 psn, void *buffer, int size)
{
	struct pib_ib_send_wqe *send_wqe;
	int first_send_wqe = 1;
	int *nr_swqe_p;
	struct pib_ib_pd *pd;
	enum ib_wc_status status;
	unsigned long flags;

	send_wqe = match_send_wqe(qp, psn, &first_send_wqe, &nr_swqe_p);

	if (send_wqe == NULL)
		return 0;

	if (send_wqe->opcode != IB_WR_RDMA_READ) {
		send_wqe->processing.status = IB_WC_BAD_RESP_ERR;		
		return 0;
	}

	if (!first_send_wqe || (send_wqe->processing.based_psn + send_wqe->processing.sent_packets != psn))
		/* 前にある Send WQE を飛ばして ACK が返ってきた */
		return 0;

	if (!pib_is_recv_ok(qp->state))
		return 0;

	pd = to_ppd(qp->ib_qp.pd);

	spin_lock_irqsave(&pd->lock, flags);
	status = pib_util_mr_copy_data(pd, send_wqe->sge_array, send_wqe->num_sge,
				       buffer,
				       send_wqe->processing.sent_packets * 128U << qp->ib_qp_attr.path_mtu,
				       size,
				       IB_ACCESS_LOCAL_WRITE,
				       PIB_MR_COPY_TO);
	spin_unlock_irqrestore(&pd->lock, flags);

	if (status != IB_WC_SUCCESS) {
		send_wqe->processing.status = status;
		return 0;
	}

	send_wqe->processing.sent_packets++;

	if (send_wqe->processing.sent_packets < send_wqe->processing.all_packets)
		return 0;

	/* Completed RDMA READ operation */

	if ((qp->ib_qp_init_attr.sq_sig_type == IB_SIGNAL_ALL_WR) || 
	    (send_wqe->send_flags & IB_SEND_SIGNALED)) {
		int ret;
		struct ib_wc wc = {
			.wr_id    = send_wqe->wr_id,
			.status   = IB_WC_SUCCESS,
			.opcode   = IB_WC_RDMA_READ,
			.qp       = &qp->ib_qp,
		};

		ret = pib_util_insert_wc_success(qp->send_cq, &wc);
	}

	qp->requester.nr_rd_atomic--;
	BUG_ON(qp->requester.nr_rd_atomic < 0);

	qp->requester.psn = send_wqe->processing.expected_psn;

	(*nr_swqe_p)--;

	list_del_init(&send_wqe->list);
	pib_util_free_send_wqe(qp, send_wqe);

	return 0;
}


static int
receive_Atomic_response(struct pib_ib_dev *dev, u8 port_num, struct pib_ib_qp *qp, u32 psn, void *buffer, int size)
{
	struct pib_packet_atomicacketh *atomicacketh;
	struct pib_ib_send_wqe *send_wqe;
	int first_send_wqe = 1;
	int *nr_swqe_p;
	struct pib_ib_pd *pd;
	enum ib_wc_status status;
	u64 res;
	unsigned long flags;

	if (size !=  sizeof(struct pib_packet_atomicacketh))
		/* @todo これはエラーにとらないでいいか？ */
		return 0;

	atomicacketh  = (struct pib_packet_atomicacketh*)buffer;
	buffer       += sizeof(struct pib_packet_atomicacketh);
	size         -= sizeof(struct pib_packet_atomicacketh);

	res = ((u64)atomicacketh->OrigRemDt_hi << 32) | atomicacketh->OrigRemDt_lo;

	send_wqe = match_send_wqe(qp, psn, &first_send_wqe, &nr_swqe_p);

	if (send_wqe == NULL)
		return 0;

	if ((send_wqe->opcode != IB_WR_ATOMIC_CMP_AND_SWP) &&
	    (send_wqe->opcode != IB_WR_ATOMIC_FETCH_AND_ADD)) {
		send_wqe->processing.status = IB_WC_BAD_RESP_ERR;
		return 0;
	}

	if (!first_send_wqe || (send_wqe->processing.based_psn != psn))
		/* 前にある Send WQE を飛ばして ACK が返ってきた */
		return 0;

	if (!pib_is_recv_ok(qp->state))
		return 0;

	pd = to_ppd(qp->ib_qp.pd);

	spin_lock_irqsave(&pd->lock, flags);
	status = pib_util_mr_copy_data(pd, send_wqe->sge_array, send_wqe->num_sge,
				       (void*)&res, 0, sizeof(res),
				       IB_ACCESS_LOCAL_WRITE,
				       PIB_MR_COPY_TO);
	spin_unlock_irqrestore(&pd->lock, flags);

	if (status != IB_WC_SUCCESS) {
		send_wqe->processing.status = status;
		return 0;
	}

	if ((qp->ib_qp_init_attr.sq_sig_type == IB_SIGNAL_ALL_WR) || 
	    (send_wqe->send_flags & IB_SEND_SIGNALED)) {
		int ret;
		struct ib_wc wc = {
			.wr_id    = send_wqe->wr_id,
			.status   = IB_WC_SUCCESS,
			.opcode   = pib_convert_wr_opcode_to_wc_opcode(send_wqe->opcode),
			.qp       = &qp->ib_qp,
		};

		ret = pib_util_insert_wc_success(qp->send_cq, &wc);
	}

	qp->requester.nr_rd_atomic--;
	BUG_ON(qp->requester.nr_rd_atomic < 0);

	qp->requester.psn = send_wqe->processing.expected_psn;

	(*nr_swqe_p)--;

	list_del_init(&send_wqe->list);
	pib_util_free_send_wqe(qp, send_wqe);

	return 0;
}


/******************************************************************************/
/* Helper functions                                                           */
/******************************************************************************/

static void
insert_async_qp_error(struct pib_ib_dev *dev, struct pib_ib_qp *qp, enum ib_event_type event)
{
	pib_util_insert_async_qp_error(qp, event);

	abort_active_rwqe(dev, qp);

	qp->state = IB_QPS_ERR;
	pib_util_flush_qp(qp, 0);
}


/*
 *  Abort active receive WQE is completed in error
 */
static void
abort_active_rwqe(struct pib_ib_dev *dev, struct pib_ib_qp *qp)
{
	struct pib_ib_recv_wqe *recv_wqe;

	if (list_empty(&qp->responder.recv_wqe_head) || qp->responder.offset == 0)
		return;

	recv_wqe = list_first_entry(&qp->responder.recv_wqe_head, struct pib_ib_recv_wqe, list);

	pib_util_insert_wc_error(qp->recv_cq, qp, recv_wqe->wr_id, IB_WC_GENERAL_ERR, IB_WC_RECV);

	qp->push_rcqe = 1;

	list_del_init(&recv_wqe->list);
	qp->responder.nr_recv_wqe--;

	pib_util_free_recv_wqe(qp, recv_wqe);
}


static struct pib_ib_send_wqe *
match_send_wqe(struct pib_ib_qp *qp, u32 psn, int *first_send_wqe_p, int **nr_swqe_pp)
{
	int first_send_wqe = 1;
	struct pib_ib_send_wqe *send_wqe;

	list_for_each_entry(send_wqe, &qp->requester.waiting_swqe_head, list) {
		if ((get_psn_diff(psn, send_wqe->processing.based_psn)    >= 0) &&
		    (get_psn_diff(psn, send_wqe->processing.expected_psn) <  0)) {
			*first_send_wqe_p = first_send_wqe;
			*nr_swqe_pp       = &qp->requester.nr_waiting_swqe;
			return send_wqe;
		}
		first_send_wqe = 0;
	}

	list_for_each_entry(send_wqe, &qp->requester.sending_swqe_head, list) {
		if ((get_psn_diff(psn, send_wqe->processing.based_psn)    >= 0) &&
		    (get_psn_diff(psn, send_wqe->processing.expected_psn) <  0)) {
			*first_send_wqe_p = first_send_wqe;
			*nr_swqe_pp       = &qp->requester.nr_sending_swqe;
			return send_wqe;
		}
		first_send_wqe = 0;
	}

	return NULL;
}


static void
issue_comm_est(struct pib_ib_qp *qp)
{
	if ((qp->state != IB_QPS_RTR) || (qp->issue_comm_est != 0))
		return;

	pib_util_insert_async_qp_event(qp, IB_EVENT_COMM_EST);

	qp->issue_comm_est = 1;
}
