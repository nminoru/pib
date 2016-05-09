/*
 * pib_mr.c - Memory Region(MR) functions
 *
 * Copyright (c) 2013-2015 Minoru NAKAMURA <nminoru@nminoru.jp>
 *
 * This code is licenced under the GPL version 2 or BSD license.
 */
#include <linux/module.h>
#include <linux/init.h>
#include <asm/atomic.h>


#include "pib.h"
#include "pib_spinlock.h"
#include "pib_trace.h"


static struct pib_mr *create_mr(struct pib_dev *dev, struct pib_pd *pd, enum pib_mr_state init_state, bool fast_reg_mr, int max_page_list_len);
static enum ib_wc_status copy_data_with_rkey(struct pib_pd *pd, u32 rkey, void *buffer, u64 address, u64 size, int access_flags, enum pib_mr_direction direction, bool check_only);
static int mr_copy_data(struct pib_mr *mr, void *buffer, u64 offset, u64 size, u64 swap, u64 compare, enum pib_mr_direction direction);
static bool mr_copy_data_sub(void *buffer, void *target_vaddr, u64 range, u64 swap, u64 compare, enum pib_mr_direction direction);


static int
reg_mr(struct pib_pd *pd, struct pib_mr *mr)
{
	int i;
	unsigned long flags;

	/* find an empty slot in mr_table[] */
	spin_lock_irqsave(&pd->lock, flags);
	for (i=0 ; i<PIB_MAX_MR_PER_PD ; i++)
		if (pd->mr_table[i] == NULL)
			goto generate_new_key;
	spin_unlock_irqrestore(&pd->lock, flags);

	return -1;

generate_new_key:
	mr->ib_mr.lkey = (i + pib_random() * PIB_MAX_MR_PER_PD) << PIB_MR_INDEX_SHIFT;
	mr->ib_mr.rkey = (i + pib_random() * PIB_MAX_MR_PER_PD) << PIB_MR_INDEX_SHIFT;

	if (mr->ib_mr.lkey == PIB_LOCAL_DMA_LKEY)
		goto generate_new_key;

#ifdef PIB_HACK_IMM_DATA_LKEY 
	if (mr->ib_mr.lkey == PIB_IMM_DATA_LKEY)
		goto generate_new_key;
#endif

	pd->mr_table[i] = mr;

	pd->nr_mr++;

	spin_unlock_irqrestore(&pd->lock, flags);

	return 0;
}


struct ib_mr *
pib_get_dma_mr(struct ib_pd *ibpd, int access_flags)
{
	struct pib_dev *dev;
	struct pib_pd *pd;
	struct pib_mr *mr;

	if (!ibpd)
		return ERR_PTR(-EINVAL);

	dev = to_pdev(ibpd->device);
	pd = to_ppd(ibpd);

	mr = create_mr(dev, pd, PIB_MR_VALID, false, 0);
	if (IS_ERR(mr))
		return (struct ib_mr *)mr;

	mr->start	= 0;
	mr->length	= (u64)-1;
	mr->virt_addr	= 0;
	mr->access_flags = access_flags;
	mr->is_dma	= 1;

	pib_trace_api(dev, IB_USER_VERBS_CMD_REG_MR, mr->mr_num);

	return &mr->ib_mr;
}


struct ib_mr *
pib_reg_user_mr(struct ib_pd *ibpd, u64 start, u64 length,
		u64 virt_addr, int access_flags,
		struct ib_udata *udata)
{
	struct pib_dev *dev;
	struct pib_pd *pd;
	struct ib_umem *umem;
	struct pib_mr *mr;

	if (!ibpd)
		return ERR_PTR(-EINVAL);

	pd = to_ppd(ibpd);
	dev = to_pdev(ibpd->device);

	umem = ib_umem_get(ibpd->uobject->context, start, length,
			   access_flags, 0);
	if (IS_ERR(umem))
		return (struct ib_mr *)umem;
	
	mr = create_mr(dev, pd, PIB_MR_VALID, false, 0);
	if (IS_ERR(mr))
		goto err_alloc_mr;

	mr->start	= start;
	mr->length	= length;
	mr->virt_addr	= virt_addr;
	mr->access_flags = access_flags;
	mr->ib_umem	= umem;

	pib_trace_api(dev, IB_USER_VERBS_CMD_REG_MR, mr->mr_num);

	return &mr->ib_mr;

err_alloc_mr:
	ib_umem_release(umem);

	return ERR_PTR(-ENOMEM);
}


static struct pib_mr *
create_mr(struct pib_dev *dev, struct pib_pd *pd, enum pib_mr_state init_state,
	  bool fast_reg_mr, int max_page_list_len)
{
	struct pib_mr *mr;
	unsigned long flags;
	u32 mr_num;
	void *page_list = NULL;

	mr = kmem_cache_zalloc(pib_mr_cachep, GFP_KERNEL);
	if (!mr)
		return ERR_PTR(-ENOMEM);

	if (fast_reg_mr && max_page_list_len > 0) {
		page_list = kzalloc(sizeof(void *) * max_page_list_len, GFP_KERNEL);
		if (!page_list)
			goto err_alloc_mr_num;
	}

	INIT_LIST_HEAD(&mr->list);
	getnstimeofday(&mr->creation_time);

	spin_lock_irqsave(&dev->lock, flags);
	mr_num = pib_alloc_obj_num(dev, PIB_BITMAP_MR_START, PIB_MAX_MR, &dev->last_mr_num);
	if (mr_num == (u32)-1) {
		spin_unlock_irqrestore(&dev->lock, flags);
		goto err_alloc_page_list;
	}
	dev->nr_mr++;
	list_add_tail(&mr->list, &dev->mr_head);
	mr->mr_num = mr_num;
	spin_unlock_irqrestore(&dev->lock, flags);

	if (reg_mr(pd, mr))
		goto err_reg_mr;

	mr->state = init_state;

	mr->page_list = page_list;
	mr->max_page_list_len = max_page_list_len;

	return mr;

err_reg_mr:
	spin_lock_irqsave(&dev->lock, flags);
	list_del(&mr->list);
	dev->nr_mr--;
	pib_dealloc_obj_num(dev, PIB_BITMAP_MR_START, mr_num);
	spin_unlock_irqrestore(&dev->lock, flags);

err_alloc_page_list:
	if (page_list)
		kfree(page_list);

err_alloc_mr_num:
	kmem_cache_free(pib_mr_cachep, mr);

	return ERR_PTR(-ENOMEM);
}


int
pib_dereg_mr(struct ib_mr *ibmr)
{
	int ret = 0;
	struct pib_dev *dev;
	struct pib_mr *mr, *mr_comp;
	struct pib_pd *pd;
	unsigned long flags;
	u32 lkey;

	if (!ibmr)
		return -EINVAL;

	dev = to_pdev(ibmr->device);
	mr  = to_pmr(ibmr);
	pd  = to_ppd(ibmr->pd);

	pib_trace_api(dev, IB_USER_VERBS_CMD_DEREG_MR, mr->mr_num);

	spin_lock_irqsave(&pd->lock, flags);
	lkey = (mr->ib_mr.lkey & PIB_MR_INDEX_MASK) >> PIB_MR_INDEX_SHIFT;
	mr_comp = pd->mr_table[lkey];
	if (mr == mr_comp) {
		pd->mr_table[lkey] = NULL;
		pd->nr_mr--;
	} else {
		pr_err("pib: MR(%u) don't be registered in PD(%u) (pib_dereg_mr)\n",
		       mr->mr_num, pd->pd_num);
		ret = -ENOENT;
	}
	spin_unlock_irqrestore(&pd->lock, flags);

	if (mr->ib_umem)
		ib_umem_release(mr->ib_umem);

	spin_lock_irqsave(&dev->lock, flags);
	list_del(&mr->list);
	dev->nr_mr--;
	pib_dealloc_obj_num(dev, PIB_BITMAP_MR_START, mr->mr_num);
	spin_unlock_irqrestore(&dev->lock, flags);

	if (mr->page_list)
		kfree(mr->page_list);

	kmem_cache_free(pib_mr_cachep, mr);

	return ret;
}

#ifdef PIB_FAST_REG_MR_SUPPORT
struct ib_mr *
pib_alloc_fast_reg_mr(struct ib_pd *ibpd,
		      int max_page_list_len)
{
	struct pib_dev *dev;
	struct pib_pd *pd;
	struct pib_mr *mr;

	if (!ibpd)
		return ERR_PTR(-EINVAL);

	dev = to_pdev(ibpd->device);
	pd = to_ppd(ibpd);

	mr = create_mr(dev, pd, PIB_MR_FREE, true, max_page_list_len);
	if (IS_ERR(mr))
		return (struct ib_mr *)mr;

	mr->start	= 0;
	mr->length	= (u64)-1;
	mr->virt_addr	= 0;
	mr->access_flags = 0;

	pib_trace_api(dev, PIB_USER_VERBS_CMD_ALLOC_FAST_REG_MR, mr->mr_num);

	return &mr->ib_mr;
}
#endif /* PIB_FAST_REG_MR_SUPPORT */

struct ib_fast_reg_page_list *
pib_alloc_fast_reg_page_list(struct ib_device *ibdev,
			     int page_list_len)
{
	struct pib_dev *dev;
	size_t size;
	struct ib_fast_reg_page_list *page_list;

	dev = to_pdev(ibdev);

	size = page_list_len * sizeof(u64);

	if (size > PAGE_SIZE)
		return ERR_PTR(-EINVAL);

	page_list = kzalloc(sizeof *page_list, GFP_KERNEL);
	if (!page_list)
		return ERR_PTR(-ENOMEM);

	page_list->page_list = kzalloc(size, GFP_KERNEL);
	if (!page_list->page_list)
		goto err_free;

	page_list->device = ibdev;
	page_list->max_page_list_len = page_list_len;

	pib_trace_api(dev, PIB_USER_VERBS_CMD_ALLOC_FAST_REG_PAGE_LIST, 0);

	return page_list;

err_free:
	kfree(page_list);

	return ERR_PTR(-ENOMEM);
}


void
pib_free_fast_reg_page_list(struct ib_fast_reg_page_list *page_list)
{
	struct pib_dev *dev;

	if (!page_list)
		return;

	dev = to_pdev(page_list->device);

	pib_trace_api(dev, PIB_USER_VERBS_CMD_FREE_FAST_REG_PAGE_LIST, 0);

	kfree(page_list->page_list);
	kfree(page_list);
}


enum ib_wc_status
pib_util_mr_copy_data(struct pib_pd *pd, struct ib_sge *sge_array, int num_sge, void *buffer, u64 offset, u64 size, int access_flags, enum pib_mr_direction direction)
{
	int i;

	if (PIB_MAX_PAYLOAD_LEN < size)
		return IB_WC_LOC_LEN_ERR;

	for (i=0 ; i<num_sge ; i++) {
		struct ib_sge sge = sge_array[i];
		struct pib_mr *mr;
		u64 range, mr_base, offset_tmp;

		mr = pd->mr_table[(sge.lkey & PIB_MR_INDEX_MASK) >> PIB_MR_INDEX_SHIFT];

		if (!mr)
			return IB_WC_LOC_PROT_ERR;

		if (mr->state != PIB_MR_VALID)
			return IB_WC_LOC_PROT_ERR; /* @todo */

		if (sge.lkey != mr->ib_mr.lkey)
			return IB_WC_LOC_PROT_ERR;

		if ((mr->access_flags & access_flags) != access_flags)
			return IB_WC_LOC_PROT_ERR;

		range = min_t(u64, sge.length, offset + size);

		offset_tmp = offset;

		if (0 < offset)
			offset = (sge.length < offset) ? (offset - sge.length) : 0;

		if ((sge.addr         <  mr->start) || (mr->start + mr->length <= sge.addr) ||
		    (sge.addr + range <= mr->start) || (mr->start + mr->length <  sge.addr + range))
			continue;

		mr_base = sge.addr - mr->start;

		if (offset_tmp < range) {
			u64 chunk_size = range - offset_tmp;
			mr_copy_data(mr, buffer, mr_base + offset_tmp, chunk_size, 0, 0, direction);
			buffer += chunk_size;
			size   -= chunk_size;
		}

		if (size == 0)
			return IB_WC_SUCCESS;
	}

	return IB_WC_LOC_PROT_ERR;
}


enum ib_wc_status
pib_util_mr_verify_rkey_validation(struct pib_pd *pd, u32 rkey, u64 address, u64 size, int access_flags)
{
	return copy_data_with_rkey(pd, rkey, NULL, address, size, access_flags, PIB_MR_CHECK, true);
}


enum ib_wc_status
pib_util_mr_copy_data_with_rkey(struct pib_pd *pd, u32 rkey, void *buffer, u64 address, u64 size, int access_flags, enum pib_mr_direction direction)
{
	return copy_data_with_rkey(pd, rkey, buffer, address, size, access_flags, direction, false);
}


static enum ib_wc_status
copy_data_with_rkey(struct pib_pd *pd, u32 rkey, void *buffer, u64 address, u64 size, int access_flags, enum pib_mr_direction direction, bool check_only)
{
	struct pib_mr *mr;

	if (PIB_MAX_PAYLOAD_LEN < size)
		return IB_WC_LOC_LEN_ERR;

	mr = pd->mr_table[(rkey & PIB_MR_INDEX_MASK) >> PIB_MR_INDEX_SHIFT];

	if (!mr)
		return IB_WC_LOC_PROT_ERR;

	if (mr->state != PIB_MR_VALID)
		return IB_WC_LOC_PROT_ERR; /* @todo */

	if (rkey != mr->ib_mr.rkey)
		return IB_WC_LOC_PROT_ERR;

	if ((mr->access_flags & access_flags) != access_flags)
		return IB_WC_LOC_PROT_ERR;

	if (mr->is_dma) {
		pr_err("pib: Can't use DMA MR in copy_data_with_rkey\n"); /* @todo */
		return IB_WC_LOC_PROT_ERR;
	}

	if ((address        <  mr->start) || (mr->start + mr->length <= address) ||
	    (address + size <= mr->start) || (mr->start + mr->length <  address + size))
		return IB_WC_LOC_PROT_ERR;

	if (!check_only) {
		if (mr_copy_data(mr, buffer, address - mr->start, size, 0, 0, direction))
			return IB_WC_LOC_PROT_ERR;
	}

	return IB_WC_SUCCESS;
}


enum ib_wc_status
pib_util_mr_atomic(struct pib_pd *pd, u32 rkey, u64 address, u64 swap, u64 compare, u64 *result, enum pib_mr_direction direction)
{
	struct pib_mr *mr;

	mr = pd->mr_table[(rkey & PIB_MR_INDEX_MASK) >> PIB_MR_INDEX_SHIFT];

	if (!mr)
		return IB_WC_LOC_PROT_ERR;

	if (mr->state != PIB_MR_VALID)
		return IB_WC_LOC_PROT_ERR; /* @todo */

	if (rkey != mr->ib_mr.rkey)
		return IB_WC_LOC_PROT_ERR;

	if ((mr->access_flags & IB_ACCESS_REMOTE_ATOMIC) != IB_ACCESS_REMOTE_ATOMIC)
		return IB_WC_LOC_PROT_ERR;

	if ((address     <  mr->start) || (mr->start + mr->length <= address) ||
	    (address + 8 <= mr->start) || (mr->start + mr->length <  address + 8))
		return IB_WC_LOC_PROT_ERR;

	if (mr_copy_data(mr, result, address - mr->start, 8, swap, compare,
			 (direction == PIB_MR_FETCHADD) ? PIB_MR_FETCHADD : PIB_MR_CAS))
		return IB_WC_LOC_PROT_ERR;

	return IB_WC_SUCCESS;
}

#ifndef PIB_NO_NEED_TO_DEFINE_IB_UMEM_OFFSET
static inline int ib_umem_offset(struct ib_umem *umem)
{
	return umem->offset;
}
#endif

static int
mr_copy_data(struct pib_mr *mr, void *buffer, u64 offset, u64 size, u64 swap, u64 compare, enum pib_mr_direction direction)
{
	u64 addr;
	struct ib_umem *umem;
#if PIB_IB_DMA_MAPPING_VERSION >= 1 
	struct scatterlist *sg;
	int entry;
#else
	struct ib_umem_chunk *chunk;
#endif

	if (mr->state != PIB_MR_VALID)
		return -EPERM;

	if (mr->is_dma)
		goto dma;

	if (size == 0)
		return 0;

	umem = mr->ib_umem;

	offset += ib_umem_offset(umem);

	addr = 0;

	if (mr->is_fast_reg_mr)
		goto fast_reg_mr;

#if PIB_IB_DMA_MAPPING_VERSION >= 1
	for_each_sg(umem->sg_head.sgl, sg, umem->nmap, entry) {
		void *vaddr;

		vaddr = page_address(sg_page(sg));
		if (!vaddr)
			return -EINVAL;

		if ((addr <= offset) && (offset < addr + umem->page_size)) {
			u64 range;
			void *target_vaddr;

			range = min_t(u64, (addr + umem->page_size - offset), size);
			target_vaddr = vaddr + (offset & (umem->page_size - 1));

			if (mr_copy_data_sub(buffer, target_vaddr, range, swap, compare, direction))
				return 0;

			offset += range;
			buffer += range;
			size   -= range;
		}

		if (size == 0)
			return 0;

		addr  += umem->page_size;
	}
#else
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

				if (mr_copy_data_sub(buffer, target_vaddr, range, swap, compare, direction))
					return 0;

				offset += range;
				buffer += range;
				size   -= range;
			}

			if (size == 0)
				return 0;

			addr  += umem->page_size;
		}
	}
#endif

	return 0;

fast_reg_mr:
	{
		int i;
		size_t page_size = 1UL << mr->page_shift;

		for (i = 0 ; i < mr->page_list_len ; i++) {
			void *vaddr;

			vaddr = mr->page_list[i];

			if ((addr <= offset) && (offset < addr + page_size)) {
				u64 range;
				void *target_vaddr;

				range = min_t(u64, (addr + page_size - offset), size);
				target_vaddr = vaddr + (offset & (page_size - 1));

				if (mr_copy_data_sub(buffer, target_vaddr, range, swap, compare, direction))
					return 0;

				offset += range;
				buffer += range;
				size   -= range;
			}

			if (size == 0)
				return 0;

			addr  += page_size;
		}
	}

	return 0;

dma:
	mr_copy_data_sub(buffer, (void*)(uintptr_t)offset, size, swap, compare, direction);

	return 0;
}

static bool
mr_copy_data_sub(void *buffer, void *target_vaddr, u64 range, u64 swap, u64 compare, enum pib_mr_direction direction)
{
	u64 res;

	switch (direction) {

	case PIB_MR_COPY_FROM:
		memcpy(buffer, target_vaddr, range);
		break;
		
	case PIB_MR_COPY_TO:
		memcpy(target_vaddr, buffer, range);
		break;

	case PIB_MR_CAS:
		*(u64*)buffer = atomic64_cmpxchg((atomic64_t*)target_vaddr, compare, swap);
		return true; /* return function */

	case PIB_MR_FETCHADD:
		res = atomic64_add_return(compare, (atomic64_t*)target_vaddr);
		*(u64*)buffer = res - compare;
		return true; /* return function */

	default:
		BUG();
	}

	return false;
}

enum ib_wc_status
pib_util_mr_invalidate(struct pib_pd *pd, u32 rkey)
{
	struct pib_mr *mr;

	mr = pd->mr_table[(rkey & PIB_MR_INDEX_MASK) >> PIB_MR_INDEX_SHIFT];

	if (!mr)
		return IB_WC_MW_BIND_ERR;

	if (mr->state == PIB_MR_INVALID)
		return IB_WC_MW_BIND_ERR;

#if 0
	if (!mr->is_dma)
		return IB_WC_MW_BIND_ERR;
#endif

	if (!mr->is_fast_reg_mr) {
		pr_err("pib: Invalidate operation must perform only MR generated by alloc_fast_reg_mr\n");
		return IB_WC_MW_BIND_ERR;
	}

	if (rkey != mr->ib_mr.rkey)
		return IB_WC_MW_BIND_ERR;

	mr->state = PIB_MR_FREE;

	return IB_WC_SUCCESS;
}

enum ib_wc_status
pib_util_mr_fast_reg_pmr(struct pib_pd *pd, u32 rkey, u64 iova_start, struct ib_fast_reg_page_list *page_list, unsigned int page_shift, unsigned int page_list_len, u32 length, int access_flags)
{
	int i;
	struct pib_mr *mr;
	size_t ps;

	mr = pd->mr_table[(rkey & PIB_MR_INDEX_MASK) >> PIB_MR_INDEX_SHIFT];

	if (!mr)
		return IB_WC_MW_BIND_ERR;

	if ((mr->state == PIB_MR_INVALID) || (mr->state == PIB_MR_VALID))
		return IB_WC_MW_BIND_ERR;

#if 0
	if (!mr->is_dma)
		return IB_WC_MW_BIND_ERR;
#endif

	if (!mr->is_fast_reg_mr) {
		pr_err("pib: Fast Register PMR operation must perform only MR generated by alloc_fast_reg_mr\n");
		return IB_WC_MW_BIND_ERR;
	}

	if (rkey != mr->ib_mr.rkey)
		return IB_WC_MW_BIND_ERR;

	ps = 1UL << page_shift;

	if (page_list_len > mr->max_page_list_len)
		return IB_WC_MW_BIND_ERR;

	if (page_list_len > page_list->max_page_list_len)
		return IB_WC_MW_BIND_ERR;

	if (length > ps * page_list_len)
		return IB_WC_MW_BIND_ERR;

	mr->start	= iova_start;
	mr->virt_addr	= iova_start;
	/* mr->lkey = rkey; */
	mr->length	= length;
	mr->access_flags = access_flags;

	mr->page_list_len = page_list_len;
	mr->page_shift	= page_shift;

	for (i = 0 ; i < page_list_len ; i++)
		mr->page_list[i] = (void *) page_list->page_list[i];

	return IB_WC_SUCCESS;	
}
