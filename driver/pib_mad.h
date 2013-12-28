/*
 * Copyright (c) 2013 Minoru NAKAMURA <nminoru@nminoru.jp>
 *
 * This code is licenced under the GPL version 2 or BSD license.
 */
#ifndef PIB_MAD_H
#define PIB_MAD_H

#include <linux/module.h>
#include <linux/init.h>


#define IB_SMP_UNSUP_VERSION    cpu_to_be16(0x0004)
#define IB_SMP_UNSUP_METHOD     cpu_to_be16(0x0008)
#define IB_SMP_UNSUP_METH_ATTR  cpu_to_be16(0x000C)
#define IB_SMP_INVALID_FIELD    cpu_to_be16(0x001C)

#define IB_MGMT_CLASS_VERSION	(1)


struct pib_mad_node_info {
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


struct pib_mad_switch_info {
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


#endif /* PIB_MAD_H */
