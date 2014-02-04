/*
 * pib_trace.h - Execution trace
 *
 * Copyright (c) 2013,2014 Minoru NAKAMURA <nminoru@nminoru.jp>
 *
 * This code is licenced under the GPL version 2 or BSD license.
 */
#ifndef PIB_TRACE_H
#define PIB_TRACE_H

#include <linux/module.h>
#include <linux/init.h>
#include <rdma/ib_user_verbs.h>


#define PIB_TRACE_MAX_ENTRIES	(65536)


enum {
	PIB_USER_VERBS_CMD_DEALLOC_CONTEXT = 52, /* IB_USER_VERBS_CMD_THRESHOLD */
	PIB_USER_VERBS_CMD_MODIFY_DEVICE,
	PIB_USER_VERBS_CMD_MODIFY_PORT,
	PIB_USER_VERBS_CMD_MODIFY_CQ
};


enum pib_trace_act {
	PIB_TRACE_ACT_NONE,
	PIB_TRACE_ACT_API,
	PIB_TRACE_ACT_SEND,
	PIB_TRACE_ACT_RECV,
	PIB_TRACE_ACT_RECV_OK,
	PIB_TRACE_ACT_ASYNC
};


struct pib_dev;


struct pib_trace_entry {
	u8	act;
	u8	op;
	u8	port;

	u16	data; /* pktlen */
	u16	slid;
	u16	dlid;

	u32	oid;  /* sqpn   */
	u32	dqpn;
	u32	psn;

	u64	timestamp;
};


extern void pib_trace_api(struct pib_dev *dev, u8 op, u32 oid);
extern void pib_trace_send(struct pib_dev *dev, u8 port_num, int size);
extern void pib_trace_recv(struct pib_dev *dev, u8 port_num, u8 opcode, u32 psn, int size, u16 slid, u16 dlid, u32 dqpn);
extern void pib_trace_recv_ok(struct pib_dev *dev, u8 port_num, u8 opcode, u32 psn, u32 sqpn, u32 data);
extern void pib_trace_async(struct pib_dev *dev, u8 op, u32 id);


#endif /* PIB_TRACE_H */
