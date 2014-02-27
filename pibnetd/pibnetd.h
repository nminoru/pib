/*
 * pibnetd.h
 *
 * Copyright (c) 2014 Minoru NAKAMURA <nminoru@nminoru.jp>
 *
 * This code is licenced under the GPL version 2 or BSD license.
 */
#ifndef _PIBNETD_H_
#define _PIBNETD_H_

#include <arpa/inet.h>
#include <netinet/in.h>
#include <infiniband/verbs.h>
#include "byteorder.h"


#define PIB_SWITCH_DESCRIPTION	"Pseudo InfiniBand HCA switch"

#define PIB_VERSION_MAJOR	0
#define PIB_VERSION_MINOR	3
#define PIB_VERSION_REVISION	1
#define PIB_DRIVER_VERSION 	"0.3.1"

#define PIB_DRIVER_FW_VERSION \
	(((u64)PIB_VERSION_MAJOR << 32) | ((u64)PIB_VERSION_MINOR << 16) | PIB_VERSION_REVISION)

#define PIB_DRIVER_DEVICE_ID	(1)
#define PIB_DRIVER_REVISION	(1)

#define PIB_NETD_DEFAULT_PORT	        (8432)

#define PIB_MAX_PORTS		        (32 + 1)

#define PIB_MAX_LID			(0x10000)
#define PIB_MCAST_LID_BASE		(0x0C000)

#define PIB_QP0				(0)
#define PIB_QP1				(1)

#define PIB_QPN_MASK			(0xFFFFFF)
#define PIB_PSN_MASK			(0xFFFFFF)
#define PIB_PACKET_BUFFER		(8192)
#define PIB_GID_PER_PORT		(16)
#define PIB_MAX_PAYLOAD_LEN	        (0x40000000)
#define PIB_MULTICAST_QPN		(0xFFFFFF)

#define PIB_PKEY_PER_BLOCK              (32)
#define PIB_PKEY_TABLE_LEN              (PIB_PKEY_PER_BLOCK * 1)

#define PIB_MCAST_QP_ATTACH             (128)
#define PIB_LID_PERMISSIVE		(0xFFFF)

#define PIB_DEFAULT_PKEY_FULL		(0xFFFF)

#define PIB_DEVICE_CAP_FLAGS		(IBV_DEVICE_CHANGE_PHY_PORT |\
					 IBV_DEVICE_SYS_IMAGE_GUID  |\
					 IBV_DEVICE_RC_RNR_NAK_GEN)

#define PIB_PORT_CAP_FLAGS		(PIB_PORT_TRAP_SUP|PIB_PORT_SYS_IMAGE_GUID_SUP|PIB_PORT_CM_SUP)

#define PIB_LINK_WIDTH_SUPPORTED	(PIB_WIDTH_1X | PIB_WIDTH_4X | PIB_WIDTH_8X | PIB_WIDTH_12X)
#define PIB_LINK_SPEED_SUPPORTED	(7) /* 2.5 or 5.0 or 10.0 Gbps */

#define PIB_PACKET_BUFFER		(8192)
#define PIB_GID_PER_PORT		(16)
#define PIB_PKEY_PER_BLOCK              (32)
#define PIB_PKEY_TABLE_LEN              (PIB_PKEY_PER_BLOCK * 1)


enum pib_link_cmd {
	PIB_LINK_CMD_CONNECT	= 1,
	PIB_LINK_CMD_CONNECT_ACK,
	PIB_LINK_CMD_DISCONNECT,
	PIB_LINK_CMD_DISCONNECT_ACK,
	PIB_LINK_SHUTDOWN,
};


enum pib_hys_port_state_{
	PIB_PHYS_PORT_SLEEP    = 1,
	PIB_PHYS_PORT_POLLING  = 2,
	PIB_PHYS_PORT_DISABLED = 3,
	PIB_PHYS_PORT_PORT_CONFIGURATION_TRAINNING = 4,
	PIB_PHYS_PORT_LINK_UP  = 5,
	PIB_PHYS_PORT_LINK_ERROR_RECOVERY = 6,
	PIB_PHYS_PORT_PHY_TEST = 7
};


enum pib_port_type {
	PIB_PORT_CA = 1,
	PIB_PORT_SW_EXT,
	PIB_PORT_BASE_SP0,
	PIB_PORT_ENH_SP0
};


enum pib_port_cap_flags {
	PIB_PORT_SM				= 1 <<  1,
	PIB_PORT_NOTICE_SUP			= 1 <<  2,
	PIB_PORT_TRAP_SUP			= 1 <<  3,
	PIB_PORT_OPT_IPD_SUP                    = 1 <<  4,
	PIB_PORT_AUTO_MIGR_SUP			= 1 <<  5,
	PIB_PORT_SL_MAP_SUP			= 1 <<  6,
	PIB_PORT_MKEY_NVRAM			= 1 <<  7,
	PIB_PORT_PKEY_NVRAM			= 1 <<  8,
	PIB_PORT_LED_INFO_SUP			= 1 <<  9,
	PIB_PORT_SM_DISABLED			= 1 << 10,
	PIB_PORT_SYS_IMAGE_GUID_SUP		= 1 << 11,
	PIB_PORT_PKEY_SW_EXT_PORT_TRAP_SUP	= 1 << 12,
	PIB_PORT_EXTENDED_SPEEDS_SUP            = 1 << 14,
	PIB_PORT_CM_SUP				= 1 << 16,
	PIB_PORT_SNMP_TUNNEL_SUP		= 1 << 17,
	PIB_PORT_REINIT_SUP			= 1 << 18,
	PIB_PORT_DEVICE_MGMT_SUP		= 1 << 19,
	PIB_PORT_VENDOR_CLASS_SUP		= 1 << 20,
	PIB_PORT_DR_NOTICE_SUP			= 1 << 21,
	PIB_PORT_CAP_MASK_NOTICE_SUP		= 1 << 22,
	PIB_PORT_BOOT_MGMT_SUP			= 1 << 23,
	PIB_PORT_LINK_LATENCY_SUP		= 1 << 24,
	PIB_PORT_CLIENT_REG_SUP			= 1 << 25
};


enum pib_port_speed {
	PIB_SPEED_SDR	=  1,
	PIB_SPEED_DDR	=  2,
	PIB_SPEED_QDR	=  4,
	PIB_SPEED_FDR10	=  8,
	PIB_SPEED_FDR	= 16,
	PIB_SPEED_EDR	= 32
};


enum pib_port_width {
	PIB_WIDTH_1X	= 1,
	PIB_WIDTH_4X	= 2,
	PIB_WIDTH_8X	= 4,
	PIB_WIDTH_12X	= 8
};


struct pib_port_perf {
	uint8_t			OpCode; /* all 0xFF */
	uint16_t		tag;
	uint16_t		counter_select[16];
	uint64_t		counter[16];
	uint64_t		symbol_error_counter;
	uint64_t		link_error_recovery_counter;
	uint64_t		link_downed_counter;
	uint64_t		rcv_errors;
	uint64_t		rcv_remphys_errors;
	uint64_t		rcv_switch_relay_errors;
	uint64_t		xmit_discards;
	uint64_t		xmit_constraint_errors;
	uint64_t		rcv_constraint_errors;
	uint64_t		local_link_integrity_errors;
	uint64_t		excessive_buffer_overrun_errors;
	uint64_t		vl15_dropped;
	uint64_t		xmit_data;
	uint64_t		rcv_data;
	uint64_t		xmit_packets;
	uint64_t		rcv_packets;
	uint64_t		xmit_wait;
	uint64_t		unicast_xmit_packets;
	uint64_t		unicast_rcv_packets;
	uint64_t		multicast_xmit_packets;
	uint64_t		multicast_rcv_packets;
};


struct pib_port {
	uint8_t			port_num;
	struct ibv_port_attr	ibv_port_attr;

	uint8_t			mkey;
	uint8_t			mkeyprot;
	uint16_t		mkey_lease_period;
	uint8_t			link_down_default_state;
	uint8_t			link_width_enabled;
	uint8_t			link_speed_enabled;
	uint8_t			master_smsl;
	uint8_t			client_reregister;
	uint8_t			subnet_timeout;
	uint8_t			local_phy_errors;
	uint8_t			overrun_errors;

	struct pib_port_perf	perf;

	union ibv_gid		gid[PIB_GID_PER_PORT];
	uint16_t		pkey_table[PIB_PKEY_TABLE_LEN];

	uint64_t		port_guid;
	struct sockaddr        *sockaddr;
	socklen_t		socklen;
};


struct pib_port_bits {
	uint16_t		pm_blocks[16]; /* portmask blocks */
};


struct pib_switch {
	void                   *buffer; /* buffer for sendmsg/recvmsg */
	int 			sockfd;
	struct sockaddr        *sockaddr;

	uint8_t                 port_cnt; /* include port 0 */
	struct pib_port	        ports[PIB_MAX_PORTS];

	uint16_t		linear_fdb_top;
	uint8_t			default_port;
	uint8_t			default_mcast_primary_port;
	uint8_t			default_mcast_not_primary_port;
	uint8_t			life_time_value;
	uint8_t			port_state_change;

	uint8_t		       *ucast_fwd_table;
	struct pib_port_bits   *mcast_fwd_table;
};


extern uint64_t pib_hca_guid_base;

struct pib_smp;

extern int pib_process_smp(struct pib_smp *smp, struct pib_switch *sw, uint8_t in_port_num);

#define pib_report_debug(fmt, ...)					\
	do {								\
		__pib_report_debug(__FILE__, __LINE__, fmt, ##__VA_ARGS__); \
	} while(0)

#define pib_report_info(fmt, ...)					\
	do {								\
		__pib_report_info(__FILE__, __LINE__, fmt, ##__VA_ARGS__);	\
	} while(0)

#define pib_report_err(fmt, ...)						\
	do {								\
		__pib_report_err(__FILE__, __LINE__, fmt, ##__VA_ARGS__);	\
	} while(0)

extern void __pib_report_debug(const char *filename, int lineno, const char *format, ...);
extern void __pib_report_info(const char *filename, int lineno, const char *format, ...);
extern void __pib_report_err(const char *filename, int lineno, const char *format, ...);

#endif /* _PIBNETD_H_ */
