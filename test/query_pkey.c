/*
 * Copyright (c) 2014 Minoru NAKAMURA <nminoru@nminoru.jp>
 */

#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <assert.h>
#include <infiniband/verbs.h>
#include <infiniband/arch.h>

int main(int argc, char **argv)
{
	struct ibv_device      **dev_list;

	dev_list = ibv_get_device_list(NULL);

	for (; *dev_list ; dev_list++) {
		int ret, port_index;
		struct ibv_context *context;

		printf("%s\n", ibv_get_device_name(*dev_list));

		context = ibv_open_device(*dev_list);
		assert(context != NULL);

		struct ibv_device_attr device_attr;
		ret = ibv_query_device(context, &device_attr);
		assert(ret == 0);

		for (port_index = 0 ; port_index < device_attr.phys_port_cnt ; port_index++) { 
			int i, snip;
			struct ibv_port_attr port_attr;

			printf("\tport_num = %d\n", port_index + 1);

			ret = ibv_query_port(context, port_index + 1, &port_attr);
			assert(ret == 0);

			assert(port_attr.pkey_tbl_len > 0);
			assert(port_attr.gid_tbl_len  > 0);

			uint16_t pkey, prev_pkey;

			ret = ibv_query_pkey(context, port_index + 1, 0, &pkey);
			assert(ret == 0);
			printf("\t\tindex = %3d, pkey = %4x\n", 0, pkey);
            
			snip = 0;
			for (i = 1 ; i < port_attr.pkey_tbl_len ; i++) {
				prev_pkey = pkey;
				ret = ibv_query_pkey(context, port_index + 1, i, &pkey);
				if ((pkey != prev_pkey) || (i == port_attr.pkey_tbl_len - 1)) {
					printf("\t\tindex = %3d, pkey = %4x\n", i, pkey);
					snip = 0;
				} else if (snip == 0) {
					printf("\t\t\t(snip)\n");
					snip = 1;
				}
			}
			printf("\n");

			union ibv_gid gid, prev_gid;
			ret = ibv_query_gid(context, port_index + 1, 0, &gid);
			assert(ret == 0);

			printf("\t\tindex = %3d, GID: %016" PRIx64 ":%016" PRIx64 "\n",
			       0, ntohll(gid.global.subnet_prefix), ntohll(gid.global.interface_id));

			snip = 0;
			for (i = 1 ; i < port_attr.gid_tbl_len ; i++) {
				prev_gid = gid;

				ret = ibv_query_gid(context, port_index + 1, i, &gid);
				assert(ret == 0);
                
				if ((memcmp(&gid, &prev_gid, sizeof(gid)) != 0) ||
				    (i == port_attr.gid_tbl_len - 1)) {
					printf("\t\tindex = %3d, GID: %016" PRIx64 ":%016" PRIx64 "\n",
					       i, ntohll(gid.global.subnet_prefix), ntohll(gid.global.interface_id));
					snip = 0;
				} else if (snip == 0) {
					printf("\t\t\t(snip)\n");
					snip = 1;
				}
			}
			printf("\n");
		}

		ret = ibv_close_device(context);
		assert(ret == 0);
	}

	return 0;
}
