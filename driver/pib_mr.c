/*
 * Copyright (c) 2013 Minoru NAKAMURA <nminoru@nminoru.jp>
 *
 * This code is licenced under the GPL version 2 or BSD license.
 */
#include <linux/module.h>
#include <linux/init.h>
#include <asm/atomic.h>


#include "pib.h"


static enum ib_wc_status copy_data_with_rkey(struct pib_ib_pd *pd, u32 rkey, void *buffer, u64 address, u64 size, int access_flags, enum pib_mr_direction direction, int check_only);
static int mr_copy_data(struct pib_ib_mr *mr, void *buffer, u64 offset, u64 size, u64 swap, u64 compare, enum pib_mr_direction direction);


static int reg_mr(struct pib_ib_pd *pd, struct pib_ib_mr *mr)
{
	int i;

	/* find an empty slot in mr_table[] */
	down_write(&pd->rwsem);
	for (i=0 ; i<PIB_IB_MAX_MR_PER_PD ; i++)
		if (pd->mr_table[i] == NULL)
			goto found;
	up_write(&pd->rwsem);

	return -1;

found:
	pd->mr_table[i] = mr;

	mr->lkey_prefix = pib_random() * PIB_IB_MAX_MR_PER_PD;
	mr->rkey_prefix = pib_random() * PIB_IB_MAX_MR_PER_PD;

	mr->ib_mr.lkey = (u32)i | mr->lkey_prefix;
	mr->ib_mr.rkey = (u32)i | mr->rkey_prefix;

	pd->nr_mr++;

	up_write(&pd->rwsem);

	return 0;
}


struct ib_mr *
pib_ib_get_dma_mr(struct ib_pd *ibpd, int acc)
{
	struct pib_ib_pd *pd;
	struct pib_ib_mr *mr;

	if (!ibpd)
		return ERR_PTR(-EINVAL);

	pd = to_ppd(ibpd);

	mr = kmem_cache_zalloc(pib_ib_mr_cachep, GFP_KERNEL);
	if (!mr) {
		return ERR_PTR(-ENOMEM);
	}

	if (reg_mr(pd, mr)) {
		kmem_cache_free(pib_ib_mr_cachep, mr);
		return ERR_PTR(-ENOMEM);
	}

	mr->is_dma = 1;
	mr->acc    = acc;

	return &mr->ib_mr;
}


struct ib_mr *
pib_ib_reg_user_mr(struct ib_pd *ibpd, u64 start, u64 length,
		   u64 virt_addr, int access_flags,
		   struct ib_udata *udata)
{
	struct pib_ib_pd *pd;
	struct pib_ib_mr *mr;
	struct ib_umem *umem;
	int ret;

	debug_printk("pib_ib_reg_user_mr: start=%llx, length=%llu, virt_addr=%llx, accesss_flags=%u\n",
		     (unsigned long long)start,
		     (unsigned long long)length,
		     (unsigned long long)virt_addr, access_flags);

	if (!ibpd)
		return ERR_PTR(-EINVAL);

	pd = to_ppd(ibpd);

	umem = ib_umem_get(ibpd->uobject->context, start, length,
			   access_flags, 0);
	if (IS_ERR(umem))
		return (struct ib_mr *)umem;

	mr = kmem_cache_zalloc(pib_ib_mr_cachep, GFP_KERNEL);
	if (!mr) {
		ret = -ENOMEM;
		goto err_alloc_mr;
	}

	mr->start        = start;
	mr->length       = length;
	mr->virt_addr    = virt_addr;
	mr->access_flags = access_flags;
	mr->ib_umem      = umem;

	if (reg_mr(pd, mr)) {
		ret = -ENOMEM;
		goto err_alloc_mr;
	}

	return &mr->ib_mr;

err_alloc_mr:
	kmem_cache_free(pib_ib_mr_cachep, mr);

	ib_umem_release(umem);

	return ERR_PTR(ret);
}


int pib_ib_dereg_mr(struct ib_mr *ibmr)
{
	struct pib_ib_mr *mr;
	struct pib_ib_pd *pd;

	debug_printk("pib_ib_dereg_mr\n");

	if (!ibmr)
		return -EINVAL;

	mr  = to_pmr(ibmr);
	pd  = to_ppd(ibmr->pd);

	down_write(&pd->rwsem);
	pd->mr_table[mr->lkey_prefix & PIB_IB_MR_INDEX_MASK] = NULL;
	pd->nr_mr--;
	up_write(&pd->rwsem);

	if (mr->ib_umem)
		ib_umem_release(mr->ib_umem);

	kmem_cache_free(pib_ib_mr_cachep, mr);

	return 0;
}


struct ib_mr *
pib_ib_alloc_fast_reg_mr(struct ib_pd *ibpd,
			 int max_page_list_len)
{
	debug_printk("pib_ib_alloc_fast_reg_mr\n");

	return ERR_PTR(-ENOMEM);
}


struct ib_fast_reg_page_list *
pib_ib_alloc_fast_reg_page_list(struct ib_device *ibdev,
				int page_list_len)
{
	debug_printk("pib_ib_alloc_fast_reg_page_list\n");
	return ERR_PTR(-ENOMEM);
}


void pib_ib_free_fast_reg_page_list(struct ib_fast_reg_page_list *page_list)
{
	debug_printk("pib_ib_free_fast_reg_page_list\n");
}


enum ib_wc_status
pib_util_mr_copy_data(struct pib_ib_pd *pd, struct ib_sge *sge_array, int num_sge, void *buffer, u64 offset, u64 size, int access_flags, enum pib_mr_direction direction)
{
	int i;

	for (i=0 ; i<num_sge ; i++) {
		struct ib_sge sge = sge_array[i];
		struct pib_ib_mr *mr;
		u64 range;

		mr = pd->mr_table[sge.lkey & PIB_IB_MR_INDEX_MASK];

		if (!mr)
			return IB_WC_LOC_PROT_ERR;

		if ((sge.lkey & ~PIB_IB_MR_INDEX_MASK) != mr->lkey_prefix)
			return IB_WC_LOC_PROT_ERR;

		if ((mr->access_flags & access_flags) != access_flags)
			return IB_WC_LOC_PROT_ERR;

#if 1
		/* Mellanox */
		if (sge.length == 0)
			return IB_WC_LOC_LEN_ERR;
#endif

		range = min_t(u64, sge.length, offset + size);

		if ((sge.addr         <  mr->start) || (mr->start + mr->length <= sge.addr) ||
		    (sge.addr + range <= mr->start) || (mr->start + mr->length <  sge.addr + range))
			continue;

		if (offset < range) {
			mr_copy_data(mr, buffer, offset, range - offset, 0, 0, direction);
			size -= range - offset;
		}

		offset -= range;

		if (size == 0)
			return IB_WC_SUCCESS;
	}

	return IB_WC_LOC_PROT_ERR;
}


enum ib_wc_status
pib_util_mr_validate_rkey(struct pib_ib_pd *pd, u32 rkey, void *buffer, u64 address, u64 size, int access_flags, enum pib_mr_direction direction)
{
	return copy_data_with_rkey(pd, rkey, buffer, address, size, access_flags, direction, 1);
}


enum ib_wc_status
pib_util_mr_copy_data_with_rkey(struct pib_ib_pd *pd, u32 rkey, void *buffer, u64 address, u64 size, int access_flags, enum pib_mr_direction direction)
{
	return copy_data_with_rkey(pd, rkey, buffer, address, size, access_flags, direction, 0);
}


static enum ib_wc_status
copy_data_with_rkey(struct pib_ib_pd *pd, u32 rkey, void *buffer, u64 address, u64 size, int access_flags, enum pib_mr_direction direction, int check_only)
{
	struct pib_ib_mr *mr;

	mr = pd->mr_table[rkey & PIB_IB_MR_INDEX_MASK];

	if (!mr)
		return IB_WC_LOC_PROT_ERR;

	if ((rkey & ~PIB_IB_MR_INDEX_MASK) != mr->rkey_prefix)
		return IB_WC_LOC_PROT_ERR;

	if ((mr->access_flags & access_flags) != access_flags)
		return IB_WC_LOC_PROT_ERR;

	if ((address        <  mr->start) || (mr->start + mr->length <= address) ||
	    (address + size <= mr->start) || (mr->start + mr->length <  address + size))
		return IB_WC_LOC_PROT_ERR;

	if (!check_only) {
		if (mr_copy_data(mr, buffer, address, size, 0, 0, direction))
			return IB_WC_LOC_PROT_ERR;
	}

	return IB_WC_SUCCESS;
}


enum ib_wc_status
pib_util_mr_atomic(struct pib_ib_pd *pd, u32 rkey, u64 address, u64 swap, u64 compare, u64 *result, enum pib_mr_direction direction)
{
	struct pib_ib_mr *mr;

	mr = pd->mr_table[rkey & PIB_IB_MR_INDEX_MASK];

	if (!mr)
		return IB_WC_LOC_PROT_ERR;

	if ((rkey & ~PIB_IB_MR_INDEX_MASK) != mr->rkey_prefix)
		return IB_WC_LOC_PROT_ERR;

	if ((mr->access_flags & IB_ACCESS_REMOTE_ATOMIC) != IB_ACCESS_REMOTE_ATOMIC)
		return IB_WC_LOC_PROT_ERR;

	if ((address     <  mr->start) || (mr->start + 8 <= address) ||
	    (address + 8 <= mr->start) || (mr->start + 8 <  address + 8))
		return IB_WC_LOC_PROT_ERR;

	if (mr_copy_data(mr, result, address, 8, swap, compare,
			 (direction == PIB_MR_FETCHADD) ? PIB_MR_FETCHADD : PIB_MR_CAS))
		return IB_WC_LOC_PROT_ERR;

	return IB_WC_SUCCESS;
}


static int
mr_copy_data(struct pib_ib_mr *mr, void *buffer, u64 offset, u64 size, u64 swap, u64 compare, enum pib_mr_direction direction)
{
	u64 addr;
	struct ib_umem *umem;
	struct ib_umem_chunk *chunk;

	umem = mr->ib_umem;

	offset += umem->offset;

	addr = 0;

	list_for_each_entry(chunk, &umem->chunk_list, list) {
		int i;
		for (i = 0; i < chunk->nents; i++) {
			void *vaddr;

			vaddr = page_address(sg_page(&chunk->page_list[i]));
			if (!vaddr)
				return -EINVAL;

			if ((addr <= offset) && (offset < addr + umem->page_size)) {
				u64 range;
				void *target_vaddr;

				range = min_t(u64, (addr + umem->page_size - offset), size);

				target_vaddr = vaddr + (offset & (umem->page_size - 1));

				switch (direction) {

				case PIB_MR_COPY_FROM:
					memcpy(buffer, target_vaddr, range);
					break;

				case PIB_MR_COPY_TO:
					memcpy(target_vaddr, buffer, range);
					break;

				case PIB_MR_CAS:
					*(u64*)buffer = atomic64_cmpxchg((atomic64_t*)target_vaddr, compare, swap);
					return 0;

				case PIB_MR_FETCHADD:
					*(u64*)buffer = atomic64_add_return(swap, (atomic64_t*)target_vaddr);
					return 0;
				}

				offset += range;
				buffer += range;
				size   -= range;
			}

			if (size == 0)
				return 0;

			addr  += umem->page_size;
		}
	}

	return 0;
}
