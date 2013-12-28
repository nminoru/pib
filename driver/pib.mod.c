#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0xfdde424b, __VMLINUX_SYMBOL_STR(module_layout) },
	{ 0x96a0c8d9, __VMLINUX_SYMBOL_STR(alloc_pages_current) },
	{ 0x8d698f72, __VMLINUX_SYMBOL_STR(release_sock) },
	{ 0xb294dd6, __VMLINUX_SYMBOL_STR(kmem_cache_destroy) },
	{ 0xaba1ecfe, __VMLINUX_SYMBOL_STR(device_remove_file) },
	{ 0x3f862391, __VMLINUX_SYMBOL_STR(kmalloc_caches) },
	{ 0x65e75cb6, __VMLINUX_SYMBOL_STR(__list_del_entry) },
	{ 0xf5893abf, __VMLINUX_SYMBOL_STR(up_read) },
	{ 0x9906418b, __VMLINUX_SYMBOL_STR(kernel_sendmsg) },
	{ 0xd6ee688f, __VMLINUX_SYMBOL_STR(vmalloc) },
	{ 0x46608fa0, __VMLINUX_SYMBOL_STR(getnstimeofday) },
	{ 0xc7a4fbed, __VMLINUX_SYMBOL_STR(rtnl_lock) },
	{ 0x5b32d780, __VMLINUX_SYMBOL_STR(sock_release) },
	{ 0x3fec048f, __VMLINUX_SYMBOL_STR(sg_next) },
	{ 0x593a99b, __VMLINUX_SYMBOL_STR(init_timer_key) },
	{ 0x8a1e82bf, __VMLINUX_SYMBOL_STR(sock_create_kern) },
	{ 0x999e8297, __VMLINUX_SYMBOL_STR(vfree) },
	{ 0x91715312, __VMLINUX_SYMBOL_STR(sprintf) },
	{ 0x18efe8e5, __VMLINUX_SYMBOL_STR(kthread_create_on_node) },
	{ 0x7d11c268, __VMLINUX_SYMBOL_STR(jiffies) },
	{ 0x343a1a8, __VMLINUX_SYMBOL_STR(__list_add) },
	{ 0x57a6ccd0, __VMLINUX_SYMBOL_STR(down_read) },
	{ 0x808181ff, __VMLINUX_SYMBOL_STR(ib_alloc_device) },
	{ 0x11f8f394, __VMLINUX_SYMBOL_STR(ib_dealloc_device) },
	{ 0xece784c2, __VMLINUX_SYMBOL_STR(rb_first) },
	{ 0xf432dd3d, __VMLINUX_SYMBOL_STR(__init_waitqueue_head) },
	{ 0xfe7c4287, __VMLINUX_SYMBOL_STR(nr_cpu_ids) },
	{ 0xd5f2172f, __VMLINUX_SYMBOL_STR(del_timer_sync) },
	{ 0x8f64aa4, __VMLINUX_SYMBOL_STR(_raw_spin_unlock_irqrestore) },
	{ 0xf95453fb, __VMLINUX_SYMBOL_STR(current_task) },
	{ 0x27e1a049, __VMLINUX_SYMBOL_STR(printk) },
	{ 0x20c55ae0, __VMLINUX_SYMBOL_STR(sscanf) },
	{ 0x2420ea86, __VMLINUX_SYMBOL_STR(kthread_stop) },
	{ 0xc37122bb, __VMLINUX_SYMBOL_STR(lock_sock_nested) },
	{ 0x15ddbdc, __VMLINUX_SYMBOL_STR(wait_for_completion_interruptible) },
	{ 0x4d9b652b, __VMLINUX_SYMBOL_STR(rb_erase) },
	{ 0x9166fada, __VMLINUX_SYMBOL_STR(strncpy) },
	{ 0xb4390f9a, __VMLINUX_SYMBOL_STR(mcount) },
	{ 0x5792f848, __VMLINUX_SYMBOL_STR(strlcpy) },
	{ 0xc9409b91, __VMLINUX_SYMBOL_STR(kmem_cache_free) },
	{ 0x92cdcc1b, __VMLINUX_SYMBOL_STR(ib_umem_get) },
	{ 0x68aca4ad, __VMLINUX_SYMBOL_STR(down) },
	{ 0x154a170f, __VMLINUX_SYMBOL_STR(kernel_getsockname) },
	{ 0x6b4c3c1d, __VMLINUX_SYMBOL_STR(device_create) },
	{ 0x3b4ceb4a, __VMLINUX_SYMBOL_STR(up_write) },
	{ 0xea62bb65, __VMLINUX_SYMBOL_STR(init_net) },
	{ 0xe6e3b875, __VMLINUX_SYMBOL_STR(down_write) },
	{ 0xf5479a4b, __VMLINUX_SYMBOL_STR(device_create_file) },
	{ 0x3ff62317, __VMLINUX_SYMBOL_STR(local_bh_disable) },
	{ 0x40a9b349, __VMLINUX_SYMBOL_STR(vzalloc) },
	{ 0x51bc3a46, __VMLINUX_SYMBOL_STR(kmem_cache_alloc) },
	{ 0xf0fdf6cb, __VMLINUX_SYMBOL_STR(__stack_chk_fail) },
	{ 0x76a495c1, __VMLINUX_SYMBOL_STR(cpu_possible_mask) },
	{ 0x25d52c63, __VMLINUX_SYMBOL_STR(ib_register_device) },
	{ 0x1000e51, __VMLINUX_SYMBOL_STR(schedule) },
	{ 0x799aca4, __VMLINUX_SYMBOL_STR(local_bh_enable) },
	{ 0x69ddaa71, __VMLINUX_SYMBOL_STR(ib_unregister_device) },
	{ 0x263122f8, __VMLINUX_SYMBOL_STR(wait_for_completion_interruptible_timeout) },
	{ 0x89d0963c, __VMLINUX_SYMBOL_STR(wake_up_process) },
	{ 0xcd758037, __VMLINUX_SYMBOL_STR(kmem_cache_alloc_trace) },
	{ 0xd52bf1ce, __VMLINUX_SYMBOL_STR(_raw_spin_lock) },
	{ 0x9327f5ce, __VMLINUX_SYMBOL_STR(_raw_spin_lock_irqsave) },
	{ 0xa5526619, __VMLINUX_SYMBOL_STR(rb_insert_color) },
	{ 0x67cc86e8, __VMLINUX_SYMBOL_STR(kmem_cache_create) },
	{ 0x857c8282, __VMLINUX_SYMBOL_STR(kernel_recvmsg) },
	{ 0x4302d0eb, __VMLINUX_SYMBOL_STR(free_pages) },
	{ 0xb3f7646e, __VMLINUX_SYMBOL_STR(kthread_should_stop) },
	{ 0x37a0cba, __VMLINUX_SYMBOL_STR(kfree) },
	{ 0x69acdf38, __VMLINUX_SYMBOL_STR(memcpy) },
	{ 0x71e3cecb, __VMLINUX_SYMBOL_STR(up) },
	{ 0x8a9bd4be, __VMLINUX_SYMBOL_STR(kernel_bind) },
	{ 0x1fe23f81, __VMLINUX_SYMBOL_STR(ib_modify_qp_is_ok) },
	{ 0xa591456, __VMLINUX_SYMBOL_STR(class_destroy) },
	{ 0x4cbbd171, __VMLINUX_SYMBOL_STR(__bitmap_weight) },
	{ 0x66c5583d, __VMLINUX_SYMBOL_STR(device_unregister) },
	{ 0x4b06d2e7, __VMLINUX_SYMBOL_STR(complete) },
	{ 0x47c8baf4, __VMLINUX_SYMBOL_STR(param_ops_uint) },
	{ 0xb7e9243c, __VMLINUX_SYMBOL_STR(__class_create) },
	{ 0x2a6e6109, __VMLINUX_SYMBOL_STR(__init_rwsem) },
	{ 0x6e720ff2, __VMLINUX_SYMBOL_STR(rtnl_unlock) },
	{ 0xcddfa464, __VMLINUX_SYMBOL_STR(ib_umem_release) },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=ib_core";


MODULE_INFO(srcversion, "3012304BBCECED857B78799");
