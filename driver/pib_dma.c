/*
 * Copyright (c) 2013 Minoru NAKAMURA <nminoru@nminoru.jp>
 *
 * This code is licenced under the GPL version 2 or BSD license.
 *
 * Original sources from driver/infiniband/hw/qib/qib_dma.c
 *                  (c) 2006, 2009, 2010 QLogic, Corporation.
 */
#include <linux/module.h>
#include <linux/init.h>
#include <linux/device.h>
#include <linux/mm.h>
#include <linux/dma-mapping.h>
#include <linux/scatterlist.h>

#include "pib.h"


#define BAD_DMA_ADDRESS ((u64) 0)


static int pib_dma_mapping_error(struct ib_device *dev, u64 dma_addr)
{
	return dma_addr == BAD_DMA_ADDRESS;
}


static u64 pib_dma_map_single(struct ib_device *dev, void *cpu_addr,
			      size_t size, enum dma_data_direction direction)
{
	return (u64)cpu_addr;
}


static void pib_dma_unmap_single(struct ib_device *dev, u64 addr, size_t size,
				 enum dma_data_direction direction)
{
}


static u64 pib_dma_map_page(struct ib_device *dev, struct page *page,
			    unsigned long offset, size_t size,
			    enum dma_data_direction direction)
{
	u64 addr;

	if (offset + size > PAGE_SIZE) {
		addr = BAD_DMA_ADDRESS;
		goto done;
	}

	addr = (u64)page_address(page);
	if (addr)
		addr += offset;

	/* @todo handle highmem pages */

done:
	return addr;
}


static void pib_dma_unmap_page(struct ib_device *dev, u64 addr, size_t size,
			       enum dma_data_direction direction)
{
}

static int pib_dma_map_sg(struct ib_device *dev, struct scatterlist *sgl,
			  int nents, enum dma_data_direction direction)
{
	struct scatterlist *sg;
	u64 addr;
	int i;
	int ret = nents;

	debug_printk("pib_dma_map_sg\n");

	for_each_sg(sgl, sg, nents, i) {
		addr = (u64) page_address(sg_page(sg));
		/* TODO: handle highmem pages */
		if (!addr) {
			ret = 0;
			break;
		}
	}
	return ret;
}


static void pib_dma_unmap_sg(struct ib_device *dev,
			 struct scatterlist *sg, int nents,
			 enum dma_data_direction direction)
{
	debug_printk("pib_dma_unmap_sg\n");
}


static u64 pib_dma_address(struct ib_device *dev, struct scatterlist *sg)
{
	u64 addr;

	debug_printk("pib_dma_address\n");

	addr = (u64) page_address(sg_page(sg));

	if (addr)
		addr += sg->offset;

	return addr;
}

static unsigned int pib_dma_len(struct ib_device *dev,
				struct scatterlist *sg)
{
	debug_printk("pib_dma_address\n");

	return sg->length;
}

static void pib_dma_sync_single_for_cpu(struct ib_device *dev, u64 addr,
					size_t size, enum dma_data_direction dir)
{
	debug_printk("pib_dma_sync_single_for_cpu: addr=%llx, size=%zu\n", (unsigned long long)addr, size);
}

static void pib_dma_sync_single_for_device(struct ib_device *dev, u64 addr,
					   size_t size,
					   enum dma_data_direction dir)
{
	debug_printk("pib_dma_sync_single_for_device: addr=%llx, size=%zu\n", (unsigned long long)addr, size);
}

static void *pib_dma_alloc_coherent(struct ib_device *dev, size_t size,
				    u64 *dma_handle, gfp_t flag)
{
	struct page *p;
	void *addr = NULL;

	debug_printk("pib_dma_alloc_coherent: size=%zu\n", size);

	p = alloc_pages(flag, get_order(size));
	if (p)
		addr = page_address(p);
	if (dma_handle)
		*dma_handle = (u64) addr;

	return addr;
}

static void pib_dma_free_coherent(struct ib_device *dev, size_t size,
				  void *cpu_addr, u64 dma_handle)
{
	debug_printk("pib_dma_free_coherent: size=%zu\n", size);

	free_pages((unsigned long) cpu_addr, get_order(size));
}


struct ib_dma_mapping_ops pib_dma_mapping_ops = {
	.mapping_error	= pib_dma_mapping_error,
	.map_single	= pib_dma_map_single,
	.unmap_single	= pib_dma_unmap_single,
	.map_page	= pib_dma_map_page,
	.unmap_page	= pib_dma_unmap_page,
	.map_sg		= pib_dma_map_sg,
	.unmap_sg	= pib_dma_unmap_sg,
	.dma_address	= pib_dma_address,
	.dma_len	= pib_dma_len,
	.sync_single_for_cpu	= pib_dma_sync_single_for_cpu,
	.sync_single_for_device	= pib_dma_sync_single_for_device,
	.alloc_coherent	= pib_dma_alloc_coherent,
	.free_coherent	= pib_dma_free_coherent
};
