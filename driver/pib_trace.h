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


struct pib_dev;

extern void pib_trace_api(struct pib_dev *dev, int cmd, u32 oid);
extern void pib_trace_send(struct pib_dev *dev, u8 port_num, int size);
extern void pib_trace_recv(struct pib_dev *dev, u8 port_num, u8 opcode, u32 psn, int size, u16 slid, u16 dlid, u32 dqpn);
extern void pib_trace_recv_ok(struct pib_dev *dev, u8 port_num, u8 opcode, u32 psn, u32 sqpn, u32 data);
extern void pib_trace_retry(struct pib_dev *dev, u8 port_num, struct pib_send_wqe *send_wqe);
extern void pib_trace_comp(struct pib_dev *dev, struct pib_cq *cq, const struct ib_wc *wc);
extern void pib_trace_async(struct pib_dev *dev, enum ib_event_type type, u32 oid);


#endif /* PIB_TRACE_H */
