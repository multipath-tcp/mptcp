/*
 * Kernel-based Virtual Machine driver for Linux
 *
 * This module enables machines with Intel VT-x extensions to run virtual
 * machines without emulation or binary translation.
 *
 * Copyright (C) 2006 Qumranet, Inc.
 * Copyright 2010 Red Hat, Inc. and/or its affiliates.
 *
 * Authors:
 *   Avi Kivity   <avi@qumranet.com>
 *   Yaniv Kamay  <yaniv@qumranet.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 */

#include "irq.h"
#include "mmu.h"
#include "cpuid.h"
#include "lapic.h"

#include <linux/kvm_host.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/sched.h>
#include <linux/sched/smt.h>
#include <linux/moduleparam.h>
#include <linux/mod_devicetable.h>
#include <linux/trace_events.h>
#include <linux/slab.h>
#include <linux/tboot.h>
#include <linux/hrtimer.h>
#include <linux/frame.h>
#include <linux/nospec.h>
#include "kvm_cache_regs.h"
#include "x86.h"

#include <asm/asm.h>
#include <asm/cpu.h>
#include <asm/cpu_device_id.h>
#include <asm/io.h>
#include <asm/desc.h>
#include <asm/vmx.h>
#include <asm/virtext.h>
#include <asm/mce.h>
#include <asm/fpu/internal.h>
#include <asm/perf_event.h>
#include <asm/debugreg.h>
#include <asm/kexec.h>
#include <asm/apic.h>
#include <asm/irq_remapping.h>
#include <asm/mmu_context.h>
#include <asm/spec-ctrl.h>
#include <asm/mshyperv.h>

#include "trace.h"
#include "pmu.h"
#include "vmx_evmcs.h"

#define __ex(x) __kvm_handle_fault_on_reboot(x)
#define __ex_clear(x, reg) \
	____kvm_handle_fault_on_reboot(x, "xor " reg " , " reg)

MODULE_AUTHOR("Qumranet");
MODULE_LICENSE("GPL");

static const struct x86_cpu_id vmx_cpu_id[] = {
	X86_FEATURE_MATCH(X86_FEATURE_VMX),
	{}
};
MODULE_DEVICE_TABLE(x86cpu, vmx_cpu_id);

static bool __read_mostly enable_vpid = 1;
module_param_named(vpid, enable_vpid, bool, 0444);

static bool __read_mostly enable_vnmi = 1;
module_param_named(vnmi, enable_vnmi, bool, S_IRUGO);

static bool __read_mostly flexpriority_enabled = 1;
module_param_named(flexpriority, flexpriority_enabled, bool, S_IRUGO);

static bool __read_mostly enable_ept = 1;
module_param_named(ept, enable_ept, bool, S_IRUGO);

static bool __read_mostly enable_unrestricted_guest = 1;
module_param_named(unrestricted_guest,
			enable_unrestricted_guest, bool, S_IRUGO);

static bool __read_mostly enable_ept_ad_bits = 1;
module_param_named(eptad, enable_ept_ad_bits, bool, S_IRUGO);

static bool __read_mostly emulate_invalid_guest_state = true;
module_param(emulate_invalid_guest_state, bool, S_IRUGO);

static bool __read_mostly fasteoi = 1;
module_param(fasteoi, bool, S_IRUGO);

static bool __read_mostly enable_apicv = 1;
module_param(enable_apicv, bool, S_IRUGO);

static bool __read_mostly enable_shadow_vmcs = 1;
module_param_named(enable_shadow_vmcs, enable_shadow_vmcs, bool, S_IRUGO);
/*
 * If nested=1, nested virtualization is supported, i.e., guests may use
 * VMX and be a hypervisor for its own guests. If nested=0, guests may not
 * use VMX instructions.
 */
static bool __read_mostly nested = 0;
module_param(nested, bool, S_IRUGO);

static u64 __read_mostly host_xss;

static bool __read_mostly enable_pml = 1;
module_param_named(pml, enable_pml, bool, S_IRUGO);

#define MSR_TYPE_R	1
#define MSR_TYPE_W	2
#define MSR_TYPE_RW	3

#define MSR_BITMAP_MODE_X2APIC		1
#define MSR_BITMAP_MODE_X2APIC_APICV	2

#define KVM_VMX_TSC_MULTIPLIER_MAX     0xffffffffffffffffULL

/* Guest_tsc -> host_tsc conversion requires 64-bit division.  */
static int __read_mostly cpu_preemption_timer_multi;
static bool __read_mostly enable_preemption_timer = 1;
#ifdef CONFIG_X86_64
module_param_named(preemption_timer, enable_preemption_timer, bool, S_IRUGO);
#endif

#define KVM_GUEST_CR0_MASK (X86_CR0_NW | X86_CR0_CD)
#define KVM_VM_CR0_ALWAYS_ON_UNRESTRICTED_GUEST X86_CR0_NE
#define KVM_VM_CR0_ALWAYS_ON				\
	(KVM_VM_CR0_ALWAYS_ON_UNRESTRICTED_GUEST | 	\
	 X86_CR0_WP | X86_CR0_PG | X86_CR0_PE)
#define KVM_CR4_GUEST_OWNED_BITS				      \
	(X86_CR4_PVI | X86_CR4_DE | X86_CR4_PCE | X86_CR4_OSFXSR      \
	 | X86_CR4_OSXMMEXCPT | X86_CR4_LA57 | X86_CR4_TSD)

#define KVM_VM_CR4_ALWAYS_ON_UNRESTRICTED_GUEST X86_CR4_VMXE
#define KVM_PMODE_VM_CR4_ALWAYS_ON (X86_CR4_PAE | X86_CR4_VMXE)
#define KVM_RMODE_VM_CR4_ALWAYS_ON (X86_CR4_VME | X86_CR4_PAE | X86_CR4_VMXE)

#define RMODE_GUEST_OWNED_EFLAGS_BITS (~(X86_EFLAGS_IOPL | X86_EFLAGS_VM))

#define VMX_MISC_EMULATED_PREEMPTION_TIMER_RATE 5

/*
 * Hyper-V requires all of these, so mark them as supported even though
 * they are just treated the same as all-context.
 */
#define VMX_VPID_EXTENT_SUPPORTED_MASK		\
	(VMX_VPID_EXTENT_INDIVIDUAL_ADDR_BIT |	\
	VMX_VPID_EXTENT_SINGLE_CONTEXT_BIT |	\
	VMX_VPID_EXTENT_GLOBAL_CONTEXT_BIT |	\
	VMX_VPID_EXTENT_SINGLE_NON_GLOBAL_BIT)

/*
 * These 2 parameters are used to config the controls for Pause-Loop Exiting:
 * ple_gap:    upper bound on the amount of time between two successive
 *             executions of PAUSE in a loop. Also indicate if ple enabled.
 *             According to test, this time is usually smaller than 128 cycles.
 * ple_window: upper bound on the amount of time a guest is allowed to execute
 *             in a PAUSE loop. Tests indicate that most spinlocks are held for
 *             less than 2^12 cycles
 * Time is measured based on a counter that runs at the same rate as the TSC,
 * refer SDM volume 3b section 21.6.13 & 22.1.3.
 */
static unsigned int ple_gap = KVM_DEFAULT_PLE_GAP;
module_param(ple_gap, uint, 0444);

static unsigned int ple_window = KVM_VMX_DEFAULT_PLE_WINDOW;
module_param(ple_window, uint, 0444);

/* Default doubles per-vcpu window every exit. */
static unsigned int ple_window_grow = KVM_DEFAULT_PLE_WINDOW_GROW;
module_param(ple_window_grow, uint, 0444);

/* Default resets per-vcpu window every exit to ple_window. */
static unsigned int ple_window_shrink = KVM_DEFAULT_PLE_WINDOW_SHRINK;
module_param(ple_window_shrink, uint, 0444);

/* Default is to compute the maximum so we can never overflow. */
static unsigned int ple_window_max        = KVM_VMX_DEFAULT_PLE_WINDOW_MAX;
module_param(ple_window_max, uint, 0444);

extern const ulong vmx_return;

static DEFINE_STATIC_KEY_FALSE(vmx_l1d_should_flush);
static DEFINE_STATIC_KEY_FALSE(vmx_l1d_flush_cond);
static DEFINE_MUTEX(vmx_l1d_flush_mutex);

/* Storage for pre module init parameter parsing */
static enum vmx_l1d_flush_state __read_mostly vmentry_l1d_flush_param = VMENTER_L1D_FLUSH_AUTO;

static const struct {
	const char *option;
	bool for_parse;
} vmentry_l1d_param[] = {
	[VMENTER_L1D_FLUSH_AUTO]	 = {"auto", true},
	[VMENTER_L1D_FLUSH_NEVER]	 = {"never", true},
	[VMENTER_L1D_FLUSH_COND]	 = {"cond", true},
	[VMENTER_L1D_FLUSH_ALWAYS]	 = {"always", true},
	[VMENTER_L1D_FLUSH_EPT_DISABLED] = {"EPT disabled", false},
	[VMENTER_L1D_FLUSH_NOT_REQUIRED] = {"not required", false},
};

#define L1D_CACHE_ORDER 4
static void *vmx_l1d_flush_pages;

/* Control for disabling CPU Fill buffer clear */
static bool __read_mostly vmx_fb_clear_ctrl_available;

static int vmx_setup_l1d_flush(enum vmx_l1d_flush_state l1tf)
{
	struct page *page;
	unsigned int i;

	if (!enable_ept) {
		l1tf_vmx_mitigation = VMENTER_L1D_FLUSH_EPT_DISABLED;
		return 0;
	}

	if (boot_cpu_has(X86_FEATURE_ARCH_CAPABILITIES)) {
		u64 msr;

		rdmsrl(MSR_IA32_ARCH_CAPABILITIES, msr);
		if (msr & ARCH_CAP_SKIP_VMENTRY_L1DFLUSH) {
			l1tf_vmx_mitigation = VMENTER_L1D_FLUSH_NOT_REQUIRED;
			return 0;
		}
	}

	/* If set to auto use the default l1tf mitigation method */
	if (l1tf == VMENTER_L1D_FLUSH_AUTO) {
		switch (l1tf_mitigation) {
		case L1TF_MITIGATION_OFF:
			l1tf = VMENTER_L1D_FLUSH_NEVER;
			break;
		case L1TF_MITIGATION_FLUSH_NOWARN:
		case L1TF_MITIGATION_FLUSH:
		case L1TF_MITIGATION_FLUSH_NOSMT:
			l1tf = VMENTER_L1D_FLUSH_COND;
			break;
		case L1TF_MITIGATION_FULL:
		case L1TF_MITIGATION_FULL_FORCE:
			l1tf = VMENTER_L1D_FLUSH_ALWAYS;
			break;
		}
	} else if (l1tf_mitigation == L1TF_MITIGATION_FULL_FORCE) {
		l1tf = VMENTER_L1D_FLUSH_ALWAYS;
	}

	if (l1tf != VMENTER_L1D_FLUSH_NEVER && !vmx_l1d_flush_pages &&
	    !boot_cpu_has(X86_FEATURE_FLUSH_L1D)) {
		page = alloc_pages(GFP_KERNEL, L1D_CACHE_ORDER);
		if (!page)
			return -ENOMEM;
		vmx_l1d_flush_pages = page_address(page);

		/*
		 * Initialize each page with a different pattern in
		 * order to protect against KSM in the nested
		 * virtualization case.
		 */
		for (i = 0; i < 1u << L1D_CACHE_ORDER; ++i) {
			memset(vmx_l1d_flush_pages + i * PAGE_SIZE, i + 1,
			       PAGE_SIZE);
		}
	}

	l1tf_vmx_mitigation = l1tf;

	if (l1tf != VMENTER_L1D_FLUSH_NEVER)
		static_branch_enable(&vmx_l1d_should_flush);
	else
		static_branch_disable(&vmx_l1d_should_flush);

	if (l1tf == VMENTER_L1D_FLUSH_COND)
		static_branch_enable(&vmx_l1d_flush_cond);
	else
		static_branch_disable(&vmx_l1d_flush_cond);
	return 0;
}

static int vmentry_l1d_flush_parse(const char *s)
{
	unsigned int i;

	if (s) {
		for (i = 0; i < ARRAY_SIZE(vmentry_l1d_param); i++) {
			if (vmentry_l1d_param[i].for_parse &&
			    sysfs_streq(s, vmentry_l1d_param[i].option))
				return i;
		}
	}
	return -EINVAL;
}

static int vmentry_l1d_flush_set(const char *s, const struct kernel_param *kp)
{
	int l1tf, ret;

	l1tf = vmentry_l1d_flush_parse(s);
	if (l1tf < 0)
		return l1tf;

	if (!boot_cpu_has(X86_BUG_L1TF))
		return 0;

	/*
	 * Has vmx_init() run already? If not then this is the pre init
	 * parameter parsing. In that case just store the value and let
	 * vmx_init() do the proper setup after enable_ept has been
	 * established.
	 */
	if (l1tf_vmx_mitigation == VMENTER_L1D_FLUSH_AUTO) {
		vmentry_l1d_flush_param = l1tf;
		return 0;
	}

	mutex_lock(&vmx_l1d_flush_mutex);
	ret = vmx_setup_l1d_flush(l1tf);
	mutex_unlock(&vmx_l1d_flush_mutex);
	return ret;
}

static int vmentry_l1d_flush_get(char *s, const struct kernel_param *kp)
{
	if (WARN_ON_ONCE(l1tf_vmx_mitigation >= ARRAY_SIZE(vmentry_l1d_param)))
		return sprintf(s, "???\n");

	return sprintf(s, "%s\n", vmentry_l1d_param[l1tf_vmx_mitigation].option);
}

static const struct kernel_param_ops vmentry_l1d_flush_ops = {
	.set = vmentry_l1d_flush_set,
	.get = vmentry_l1d_flush_get,
};
module_param_cb(vmentry_l1d_flush, &vmentry_l1d_flush_ops, NULL, 0644);

enum ept_pointers_status {
	EPT_POINTERS_CHECK = 0,
	EPT_POINTERS_MATCH = 1,
	EPT_POINTERS_MISMATCH = 2
};

struct kvm_vmx {
	struct kvm kvm;

	unsigned int tss_addr;
	bool ept_identity_pagetable_done;
	gpa_t ept_identity_map_addr;

	enum ept_pointers_status ept_pointers_match;
	spinlock_t ept_pointer_lock;
};

#define NR_AUTOLOAD_MSRS 8

struct vmcs_hdr {
	u32 revision_id:31;
	u32 shadow_vmcs:1;
};

struct vmcs {
	struct vmcs_hdr hdr;
	u32 abort;
	char data[0];
};

/*
 * vmcs_host_state tracks registers that are loaded from the VMCS on VMEXIT
 * and whose values change infrequently, but are not constant.  I.e. this is
 * used as a write-through cache of the corresponding VMCS fields.
 */
struct vmcs_host_state {
	unsigned long cr3;	/* May not match real cr3 */
	unsigned long cr4;	/* May not match real cr4 */
	unsigned long gs_base;
	unsigned long fs_base;

	u16           fs_sel, gs_sel, ldt_sel;
#ifdef CONFIG_X86_64
	u16           ds_sel, es_sel;
#endif
};

/*
 * Track a VMCS that may be loaded on a certain CPU. If it is (cpu!=-1), also
 * remember whether it was VMLAUNCHed, and maintain a linked list of all VMCSs
 * loaded on this CPU (so we can clear them if the CPU goes down).
 */
struct loaded_vmcs {
	struct vmcs *vmcs;
	struct vmcs *shadow_vmcs;
	int cpu;
	bool launched;
	bool nmi_known_unmasked;
	bool hv_timer_armed;
	/* Support for vnmi-less CPUs */
	int soft_vnmi_blocked;
	ktime_t entry_time;
	s64 vnmi_blocked_time;
	unsigned long *msr_bitmap;
	struct list_head loaded_vmcss_on_cpu_link;
	struct vmcs_host_state host_state;
};

struct shared_msr_entry {
	unsigned index;
	u64 data;
	u64 mask;
};

/*
 * struct vmcs12 describes the state that our guest hypervisor (L1) keeps for a
 * single nested guest (L2), hence the name vmcs12. Any VMX implementation has
 * a VMCS structure, and vmcs12 is our emulated VMX's VMCS. This structure is
 * stored in guest memory specified by VMPTRLD, but is opaque to the guest,
 * which must access it using VMREAD/VMWRITE/VMCLEAR instructions.
 * More than one of these structures may exist, if L1 runs multiple L2 guests.
 * nested_vmx_run() will use the data here to build the vmcs02: a VMCS for the
 * underlying hardware which will be used to run L2.
 * This structure is packed to ensure that its layout is identical across
 * machines (necessary for live migration).
 *
 * IMPORTANT: Changing the layout of existing fields in this structure
 * will break save/restore compatibility with older kvm releases. When
 * adding new fields, either use space in the reserved padding* arrays
 * or add the new fields to the end of the structure.
 */
typedef u64 natural_width;
struct __packed vmcs12 {
	/* According to the Intel spec, a VMCS region must start with the
	 * following two fields. Then follow implementation-specific data.
	 */
	struct vmcs_hdr hdr;
	u32 abort;

	u32 launch_state; /* set to 0 by VMCLEAR, to 1 by VMLAUNCH */
	u32 padding[7]; /* room for future expansion */

	u64 io_bitmap_a;
	u64 io_bitmap_b;
	u64 msr_bitmap;
	u64 vm_exit_msr_store_addr;
	u64 vm_exit_msr_load_addr;
	u64 vm_entry_msr_load_addr;
	u64 tsc_offset;
	u64 virtual_apic_page_addr;
	u64 apic_access_addr;
	u64 posted_intr_desc_addr;
	u64 ept_pointer;
	u64 eoi_exit_bitmap0;
	u64 eoi_exit_bitmap1;
	u64 eoi_exit_bitmap2;
	u64 eoi_exit_bitmap3;
	u64 xss_exit_bitmap;
	u64 guest_physical_address;
	u64 vmcs_link_pointer;
	u64 guest_ia32_debugctl;
	u64 guest_ia32_pat;
	u64 guest_ia32_efer;
	u64 guest_ia32_perf_global_ctrl;
	u64 guest_pdptr0;
	u64 guest_pdptr1;
	u64 guest_pdptr2;
	u64 guest_pdptr3;
	u64 guest_bndcfgs;
	u64 host_ia32_pat;
	u64 host_ia32_efer;
	u64 host_ia32_perf_global_ctrl;
	u64 vmread_bitmap;
	u64 vmwrite_bitmap;
	u64 vm_function_control;
	u64 eptp_list_address;
	u64 pml_address;
	u64 padding64[3]; /* room for future expansion */
	/*
	 * To allow migration of L1 (complete with its L2 guests) between
	 * machines of different natural widths (32 or 64 bit), we cannot have
	 * unsigned long fields with no explict size. We use u64 (aliased
	 * natural_width) instead. Luckily, x86 is little-endian.
	 */
	natural_width cr0_guest_host_mask;
	natural_width cr4_guest_host_mask;
	natural_width cr0_read_shadow;
	natural_width cr4_read_shadow;
	natural_width cr3_target_value0;
	natural_width cr3_target_value1;
	natural_width cr3_target_value2;
	natural_width cr3_target_value3;
	natural_width exit_qualification;
	natural_width guest_linear_address;
	natural_width guest_cr0;
	natural_width guest_cr3;
	natural_width guest_cr4;
	natural_width guest_es_base;
	natural_width guest_cs_base;
	natural_width guest_ss_base;
	natural_width guest_ds_base;
	natural_width guest_fs_base;
	natural_width guest_gs_base;
	natural_width guest_ldtr_base;
	natural_width guest_tr_base;
	natural_width guest_gdtr_base;
	natural_width guest_idtr_base;
	natural_width guest_dr7;
	natural_width guest_rsp;
	natural_width guest_rip;
	natural_width guest_rflags;
	natural_width guest_pending_dbg_exceptions;
	natural_width guest_sysenter_esp;
	natural_width guest_sysenter_eip;
	natural_width host_cr0;
	natural_width host_cr3;
	natural_width host_cr4;
	natural_width host_fs_base;
	natural_width host_gs_base;
	natural_width host_tr_base;
	natural_width host_gdtr_base;
	natural_width host_idtr_base;
	natural_width host_ia32_sysenter_esp;
	natural_width host_ia32_sysenter_eip;
	natural_width host_rsp;
	natural_width host_rip;
	natural_width paddingl[8]; /* room for future expansion */
	u32 pin_based_vm_exec_control;
	u32 cpu_based_vm_exec_control;
	u32 exception_bitmap;
	u32 page_fault_error_code_mask;
	u32 page_fault_error_code_match;
	u32 cr3_target_count;
	u32 vm_exit_controls;
	u32 vm_exit_msr_store_count;
	u32 vm_exit_msr_load_count;
	u32 vm_entry_controls;
	u32 vm_entry_msr_load_count;
	u32 vm_entry_intr_info_field;
	u32 vm_entry_exception_error_code;
	u32 vm_entry_instruction_len;
	u32 tpr_threshold;
	u32 secondary_vm_exec_control;
	u32 vm_instruction_error;
	u32 vm_exit_reason;
	u32 vm_exit_intr_info;
	u32 vm_exit_intr_error_code;
	u32 idt_vectoring_info_field;
	u32 idt_vectoring_error_code;
	u32 vm_exit_instruction_len;
	u32 vmx_instruction_info;
	u32 guest_es_limit;
	u32 guest_cs_limit;
	u32 guest_ss_limit;
	u32 guest_ds_limit;
	u32 guest_fs_limit;
	u32 guest_gs_limit;
	u32 guest_ldtr_limit;
	u32 guest_tr_limit;
	u32 guest_gdtr_limit;
	u32 guest_idtr_limit;
	u32 guest_es_ar_bytes;
	u32 guest_cs_ar_bytes;
	u32 guest_ss_ar_bytes;
	u32 guest_ds_ar_bytes;
	u32 guest_fs_ar_bytes;
	u32 guest_gs_ar_bytes;
	u32 guest_ldtr_ar_bytes;
	u32 guest_tr_ar_bytes;
	u32 guest_interruptibility_info;
	u32 guest_activity_state;
	u32 guest_sysenter_cs;
	u32 host_ia32_sysenter_cs;
	u32 vmx_preemption_timer_value;
	u32 padding32[7]; /* room for future expansion */
	u16 virtual_processor_id;
	u16 posted_intr_nv;
	u16 guest_es_selector;
	u16 guest_cs_selector;
	u16 guest_ss_selector;
	u16 guest_ds_selector;
	u16 guest_fs_selector;
	u16 guest_gs_selector;
	u16 guest_ldtr_selector;
	u16 guest_tr_selector;
	u16 guest_intr_status;
	u16 host_es_selector;
	u16 host_cs_selector;
	u16 host_ss_selector;
	u16 host_ds_selector;
	u16 host_fs_selector;
	u16 host_gs_selector;
	u16 host_tr_selector;
	u16 guest_pml_index;
};

/*
 * For save/restore compatibility, the vmcs12 field offsets must not change.
 */
#define CHECK_OFFSET(field, loc)				\
	BUILD_BUG_ON_MSG(offsetof(struct vmcs12, field) != (loc),	\
		"Offset of " #field " in struct vmcs12 has changed.")

static inline void vmx_check_vmcs12_offsets(void) {
	CHECK_OFFSET(hdr, 0);
	CHECK_OFFSET(abort, 4);
	CHECK_OFFSET(launch_state, 8);
	CHECK_OFFSET(io_bitmap_a, 40);
	CHECK_OFFSET(io_bitmap_b, 48);
	CHECK_OFFSET(msr_bitmap, 56);
	CHECK_OFFSET(vm_exit_msr_store_addr, 64);
	CHECK_OFFSET(vm_exit_msr_load_addr, 72);
	CHECK_OFFSET(vm_entry_msr_load_addr, 80);
	CHECK_OFFSET(tsc_offset, 88);
	CHECK_OFFSET(virtual_apic_page_addr, 96);
	CHECK_OFFSET(apic_access_addr, 104);
	CHECK_OFFSET(posted_intr_desc_addr, 112);
	CHECK_OFFSET(ept_pointer, 120);
	CHECK_OFFSET(eoi_exit_bitmap0, 128);
	CHECK_OFFSET(eoi_exit_bitmap1, 136);
	CHECK_OFFSET(eoi_exit_bitmap2, 144);
	CHECK_OFFSET(eoi_exit_bitmap3, 152);
	CHECK_OFFSET(xss_exit_bitmap, 160);
	CHECK_OFFSET(guest_physical_address, 168);
	CHECK_OFFSET(vmcs_link_pointer, 176);
	CHECK_OFFSET(guest_ia32_debugctl, 184);
	CHECK_OFFSET(guest_ia32_pat, 192);
	CHECK_OFFSET(guest_ia32_efer, 200);
	CHECK_OFFSET(guest_ia32_perf_global_ctrl, 208);
	CHECK_OFFSET(guest_pdptr0, 216);
	CHECK_OFFSET(guest_pdptr1, 224);
	CHECK_OFFSET(guest_pdptr2, 232);
	CHECK_OFFSET(guest_pdptr3, 240);
	CHECK_OFFSET(guest_bndcfgs, 248);
	CHECK_OFFSET(host_ia32_pat, 256);
	CHECK_OFFSET(host_ia32_efer, 264);
	CHECK_OFFSET(host_ia32_perf_global_ctrl, 272);
	CHECK_OFFSET(vmread_bitmap, 280);
	CHECK_OFFSET(vmwrite_bitmap, 288);
	CHECK_OFFSET(vm_function_control, 296);
	CHECK_OFFSET(eptp_list_address, 304);
	CHECK_OFFSET(pml_address, 312);
	CHECK_OFFSET(cr0_guest_host_mask, 344);
	CHECK_OFFSET(cr4_guest_host_mask, 352);
	CHECK_OFFSET(cr0_read_shadow, 360);
	CHECK_OFFSET(cr4_read_shadow, 368);
	CHECK_OFFSET(cr3_target_value0, 376);
	CHECK_OFFSET(cr3_target_value1, 384);
	CHECK_OFFSET(cr3_target_value2, 392);
	CHECK_OFFSET(cr3_target_value3, 400);
	CHECK_OFFSET(exit_qualification, 408);
	CHECK_OFFSET(guest_linear_address, 416);
	CHECK_OFFSET(guest_cr0, 424);
	CHECK_OFFSET(guest_cr3, 432);
	CHECK_OFFSET(guest_cr4, 440);
	CHECK_OFFSET(guest_es_base, 448);
	CHECK_OFFSET(guest_cs_base, 456);
	CHECK_OFFSET(guest_ss_base, 464);
	CHECK_OFFSET(guest_ds_base, 472);
	CHECK_OFFSET(guest_fs_base, 480);
	CHECK_OFFSET(guest_gs_base, 488);
	CHECK_OFFSET(guest_ldtr_base, 496);
	CHECK_OFFSET(guest_tr_base, 504);
	CHECK_OFFSET(guest_gdtr_base, 512);
	CHECK_OFFSET(guest_idtr_base, 520);
	CHECK_OFFSET(guest_dr7, 528);
	CHECK_OFFSET(guest_rsp, 536);
	CHECK_OFFSET(guest_rip, 544);
	CHECK_OFFSET(guest_rflags, 552);
	CHECK_OFFSET(guest_pending_dbg_exceptions, 560);
	CHECK_OFFSET(guest_sysenter_esp, 568);
	CHECK_OFFSET(guest_sysenter_eip, 576);
	CHECK_OFFSET(host_cr0, 584);
	CHECK_OFFSET(host_cr3, 592);
	CHECK_OFFSET(host_cr4, 600);
	CHECK_OFFSET(host_fs_base, 608);
	CHECK_OFFSET(host_gs_base, 616);
	CHECK_OFFSET(host_tr_base, 624);
	CHECK_OFFSET(host_gdtr_base, 632);
	CHECK_OFFSET(host_idtr_base, 640);
	CHECK_OFFSET(host_ia32_sysenter_esp, 648);
	CHECK_OFFSET(host_ia32_sysenter_eip, 656);
	CHECK_OFFSET(host_rsp, 664);
	CHECK_OFFSET(host_rip, 672);
	CHECK_OFFSET(pin_based_vm_exec_control, 744);
	CHECK_OFFSET(cpu_based_vm_exec_control, 748);
	CHECK_OFFSET(exception_bitmap, 752);
	CHECK_OFFSET(page_fault_error_code_mask, 756);
	CHECK_OFFSET(page_fault_error_code_match, 760);
	CHECK_OFFSET(cr3_target_count, 764);
	CHECK_OFFSET(vm_exit_controls, 768);
	CHECK_OFFSET(vm_exit_msr_store_count, 772);
	CHECK_OFFSET(vm_exit_msr_load_count, 776);
	CHECK_OFFSET(vm_entry_controls, 780);
	CHECK_OFFSET(vm_entry_msr_load_count, 784);
	CHECK_OFFSET(vm_entry_intr_info_field, 788);
	CHECK_OFFSET(vm_entry_exception_error_code, 792);
	CHECK_OFFSET(vm_entry_instruction_len, 796);
	CHECK_OFFSET(tpr_threshold, 800);
	CHECK_OFFSET(secondary_vm_exec_control, 804);
	CHECK_OFFSET(vm_instruction_error, 808);
	CHECK_OFFSET(vm_exit_reason, 812);
	CHECK_OFFSET(vm_exit_intr_info, 816);
	CHECK_OFFSET(vm_exit_intr_error_code, 820);
	CHECK_OFFSET(idt_vectoring_info_field, 824);
	CHECK_OFFSET(idt_vectoring_error_code, 828);
	CHECK_OFFSET(vm_exit_instruction_len, 832);
	CHECK_OFFSET(vmx_instruction_info, 836);
	CHECK_OFFSET(guest_es_limit, 840);
	CHECK_OFFSET(guest_cs_limit, 844);
	CHECK_OFFSET(guest_ss_limit, 848);
	CHECK_OFFSET(guest_ds_limit, 852);
	CHECK_OFFSET(guest_fs_limit, 856);
	CHECK_OFFSET(guest_gs_limit, 860);
	CHECK_OFFSET(guest_ldtr_limit, 864);
	CHECK_OFFSET(guest_tr_limit, 868);
	CHECK_OFFSET(guest_gdtr_limit, 872);
	CHECK_OFFSET(guest_idtr_limit, 876);
	CHECK_OFFSET(guest_es_ar_bytes, 880);
	CHECK_OFFSET(guest_cs_ar_bytes, 884);
	CHECK_OFFSET(guest_ss_ar_bytes, 888);
	CHECK_OFFSET(guest_ds_ar_bytes, 892);
	CHECK_OFFSET(guest_fs_ar_bytes, 896);
	CHECK_OFFSET(guest_gs_ar_bytes, 900);
	CHECK_OFFSET(guest_ldtr_ar_bytes, 904);
	CHECK_OFFSET(guest_tr_ar_bytes, 908);
	CHECK_OFFSET(guest_interruptibility_info, 912);
	CHECK_OFFSET(guest_activity_state, 916);
	CHECK_OFFSET(guest_sysenter_cs, 920);
	CHECK_OFFSET(host_ia32_sysenter_cs, 924);
	CHECK_OFFSET(vmx_preemption_timer_value, 928);
	CHECK_OFFSET(virtual_processor_id, 960);
	CHECK_OFFSET(posted_intr_nv, 962);
	CHECK_OFFSET(guest_es_selector, 964);
	CHECK_OFFSET(guest_cs_selector, 966);
	CHECK_OFFSET(guest_ss_selector, 968);
	CHECK_OFFSET(guest_ds_selector, 970);
	CHECK_OFFSET(guest_fs_selector, 972);
	CHECK_OFFSET(guest_gs_selector, 974);
	CHECK_OFFSET(guest_ldtr_selector, 976);
	CHECK_OFFSET(guest_tr_selector, 978);
	CHECK_OFFSET(guest_intr_status, 980);
	CHECK_OFFSET(host_es_selector, 982);
	CHECK_OFFSET(host_cs_selector, 984);
	CHECK_OFFSET(host_ss_selector, 986);
	CHECK_OFFSET(host_ds_selector, 988);
	CHECK_OFFSET(host_fs_selector, 990);
	CHECK_OFFSET(host_gs_selector, 992);
	CHECK_OFFSET(host_tr_selector, 994);
	CHECK_OFFSET(guest_pml_index, 996);
}

/*
 * VMCS12_REVISION is an arbitrary id that should be changed if the content or
 * layout of struct vmcs12 is changed. MSR_IA32_VMX_BASIC returns this id, and
 * VMPTRLD verifies that the VMCS region that L1 is loading contains this id.
 *
 * IMPORTANT: Changing this value will break save/restore compatibility with
 * older kvm releases.
 */
#define VMCS12_REVISION 0x11e57ed0

/*
 * VMCS12_SIZE is the number of bytes L1 should allocate for the VMXON region
 * and any VMCS region. Although only sizeof(struct vmcs12) are used by the
 * current implementation, 4K are reserved to avoid future complications.
 */
#define VMCS12_SIZE 0x1000

/*
 * VMCS12_MAX_FIELD_INDEX is the highest index value used in any
 * supported VMCS12 field encoding.
 */
#define VMCS12_MAX_FIELD_INDEX 0x17

struct nested_vmx_msrs {
	/*
	 * We only store the "true" versions of the VMX capability MSRs. We
	 * generate the "non-true" versions by setting the must-be-1 bits
	 * according to the SDM.
	 */
	u32 procbased_ctls_low;
	u32 procbased_ctls_high;
	u32 secondary_ctls_low;
	u32 secondary_ctls_high;
	u32 pinbased_ctls_low;
	u32 pinbased_ctls_high;
	u32 exit_ctls_low;
	u32 exit_ctls_high;
	u32 entry_ctls_low;
	u32 entry_ctls_high;
	u32 misc_low;
	u32 misc_high;
	u32 ept_caps;
	u32 vpid_caps;
	u64 basic;
	u64 cr0_fixed0;
	u64 cr0_fixed1;
	u64 cr4_fixed0;
	u64 cr4_fixed1;
	u64 vmcs_enum;
	u64 vmfunc_controls;
};

/*
 * The nested_vmx structure is part of vcpu_vmx, and holds information we need
 * for correct emulation of VMX (i.e., nested VMX) on this vcpu.
 */
struct nested_vmx {
	/* Has the level1 guest done vmxon? */
	bool vmxon;
	gpa_t vmxon_ptr;
	bool pml_full;

	/* The guest-physical address of the current VMCS L1 keeps for L2 */
	gpa_t current_vmptr;
	/*
	 * Cache of the guest's VMCS, existing outside of guest memory.
	 * Loaded from guest memory during VMPTRLD. Flushed to guest
	 * memory during VMCLEAR and VMPTRLD.
	 */
	struct vmcs12 *cached_vmcs12;
	/*
	 * Cache of the guest's shadow VMCS, existing outside of guest
	 * memory. Loaded from guest memory during VM entry. Flushed
	 * to guest memory during VM exit.
	 */
	struct vmcs12 *cached_shadow_vmcs12;
	/*
	 * Indicates if the shadow vmcs must be updated with the
	 * data hold by vmcs12
	 */
	bool sync_shadow_vmcs;
	bool dirty_vmcs12;

	bool change_vmcs01_virtual_apic_mode;

	/* L2 must run next, and mustn't decide to exit to L1. */
	bool nested_run_pending;

	struct loaded_vmcs vmcs02;

	/*
	 * Guest pages referred to in the vmcs02 with host-physical
	 * pointers, so we must keep them pinned while L2 runs.
	 */
	struct page *apic_access_page;
	struct page *virtual_apic_page;
	struct page *pi_desc_page;
	struct pi_desc *pi_desc;
	bool pi_pending;
	u16 posted_intr_nv;

	struct hrtimer preemption_timer;
	bool preemption_timer_expired;

	/* to migrate it to L2 if VM_ENTRY_LOAD_DEBUG_CONTROLS is off */
	u64 vmcs01_debugctl;
	u64 vmcs01_guest_bndcfgs;

	u16 vpid02;
	u16 last_vpid;

	struct nested_vmx_msrs msrs;

	/* SMM related state */
	struct {
		/* in VMX operation on SMM entry? */
		bool vmxon;
		/* in guest mode on SMM entry? */
		bool guest_mode;
	} smm;
};

#define POSTED_INTR_ON  0
#define POSTED_INTR_SN  1

/* Posted-Interrupt Descriptor */
struct pi_desc {
	u32 pir[8];     /* Posted interrupt requested */
	union {
		struct {
				/* bit 256 - Outstanding Notification */
			u16	on	: 1,
				/* bit 257 - Suppress Notification */
				sn	: 1,
				/* bit 271:258 - Reserved */
				rsvd_1	: 14;
				/* bit 279:272 - Notification Vector */
			u8	nv;
				/* bit 287:280 - Reserved */
			u8	rsvd_2;
				/* bit 319:288 - Notification Destination */
			u32	ndst;
		};
		u64 control;
	};
	u32 rsvd[6];
} __aligned(64);

static bool pi_test_and_set_on(struct pi_desc *pi_desc)
{
	return test_and_set_bit(POSTED_INTR_ON,
			(unsigned long *)&pi_desc->control);
}

static bool pi_test_and_clear_on(struct pi_desc *pi_desc)
{
	return test_and_clear_bit(POSTED_INTR_ON,
			(unsigned long *)&pi_desc->control);
}

static int pi_test_and_set_pir(int vector, struct pi_desc *pi_desc)
{
	return test_and_set_bit(vector, (unsigned long *)pi_desc->pir);
}

static inline void pi_clear_sn(struct pi_desc *pi_desc)
{
	return clear_bit(POSTED_INTR_SN,
			(unsigned long *)&pi_desc->control);
}

static inline void pi_set_sn(struct pi_desc *pi_desc)
{
	return set_bit(POSTED_INTR_SN,
			(unsigned long *)&pi_desc->control);
}

static inline void pi_clear_on(struct pi_desc *pi_desc)
{
	clear_bit(POSTED_INTR_ON,
  		  (unsigned long *)&pi_desc->control);
}

static inline int pi_test_on(struct pi_desc *pi_desc)
{
	return test_bit(POSTED_INTR_ON,
			(unsigned long *)&pi_desc->control);
}

static inline int pi_test_sn(struct pi_desc *pi_desc)
{
	return test_bit(POSTED_INTR_SN,
			(unsigned long *)&pi_desc->control);
}

struct vmx_msrs {
	unsigned int		nr;
	struct vmx_msr_entry	val[NR_AUTOLOAD_MSRS];
};

struct vcpu_vmx {
	struct kvm_vcpu       vcpu;
	unsigned long         host_rsp;
	u8                    fail;
	u8		      msr_bitmap_mode;
	u32                   exit_intr_info;
	u32                   idt_vectoring_info;
	ulong                 rflags;
	struct shared_msr_entry *guest_msrs;
	int                   nmsrs;
	int                   save_nmsrs;
	bool                  guest_msrs_dirty;
	unsigned long	      host_idt_base;
#ifdef CONFIG_X86_64
	u64 		      msr_host_kernel_gs_base;
	u64 		      msr_guest_kernel_gs_base;
#endif

	u64 		      spec_ctrl;

	u32 vm_entry_controls_shadow;
	u32 vm_exit_controls_shadow;
	u32 secondary_exec_control;

	/*
	 * loaded_vmcs points to the VMCS currently used in this vcpu. For a
	 * non-nested (L1) guest, it always points to vmcs01. For a nested
	 * guest (L2), it points to a different VMCS.  loaded_cpu_state points
	 * to the VMCS whose state is loaded into the CPU registers that only
	 * need to be switched when transitioning to/from the kernel; a NULL
	 * value indicates that host state is loaded.
	 */
	struct loaded_vmcs    vmcs01;
	struct loaded_vmcs   *loaded_vmcs;
	struct loaded_vmcs   *loaded_cpu_state;
	bool                  __launched; /* temporary, used in vmx_vcpu_run */
	struct msr_autoload {
		struct vmx_msrs guest;
		struct vmx_msrs host;
	} msr_autoload;

	struct {
		int vm86_active;
		ulong save_rflags;
		struct kvm_segment segs[8];
	} rmode;
	struct {
		u32 bitmask; /* 4 bits per segment (1 bit per field) */
		struct kvm_save_segment {
			u16 selector;
			unsigned long base;
			u32 limit;
			u32 ar;
		} seg[8];
	} segment_cache;
	int vpid;
	bool emulation_required;

	u32 exit_reason;

	/* Posted interrupt descriptor */
	struct pi_desc pi_desc;

	/* Support for a guest hypervisor (nested VMX) */
	struct nested_vmx nested;

	/* Dynamic PLE window. */
	int ple_window;
	bool ple_window_dirty;

	bool req_immediate_exit;

	/* Support for PML */
#define PML_ENTITY_NUM		512
	struct page *pml_pg;

	/* apic deadline value in host tsc */
	u64 hv_deadline_tsc;

	u64 current_tsc_ratio;

	u32 host_pkru;

	unsigned long host_debugctlmsr;

	/*
	 * Only bits masked by msr_ia32_feature_control_valid_bits can be set in
	 * msr_ia32_feature_control. FEATURE_CONTROL_LOCKED is always included
	 * in msr_ia32_feature_control_valid_bits.
	 */
	u64 msr_ia32_feature_control;
	u64 msr_ia32_feature_control_valid_bits;
	u64 ept_pointer;
	u64 msr_ia32_mcu_opt_ctrl;
	bool disable_fb_clear;
};

enum segment_cache_field {
	SEG_FIELD_SEL = 0,
	SEG_FIELD_BASE = 1,
	SEG_FIELD_LIMIT = 2,
	SEG_FIELD_AR = 3,

	SEG_FIELD_NR = 4
};

static inline struct kvm_vmx *to_kvm_vmx(struct kvm *kvm)
{
	return container_of(kvm, struct kvm_vmx, kvm);
}

static inline struct vcpu_vmx *to_vmx(struct kvm_vcpu *vcpu)
{
	return container_of(vcpu, struct vcpu_vmx, vcpu);
}

static struct pi_desc *vcpu_to_pi_desc(struct kvm_vcpu *vcpu)
{
	return &(to_vmx(vcpu)->pi_desc);
}

#define ROL16(val, n) ((u16)(((u16)(val) << (n)) | ((u16)(val) >> (16 - (n)))))
#define VMCS12_OFFSET(x) offsetof(struct vmcs12, x)
#define FIELD(number, name)	[ROL16(number, 6)] = VMCS12_OFFSET(name)
#define FIELD64(number, name)						\
	FIELD(number, name),						\
	[ROL16(number##_HIGH, 6)] = VMCS12_OFFSET(name) + sizeof(u32)


static u16 shadow_read_only_fields[] = {
#define SHADOW_FIELD_RO(x) x,
#include "vmx_shadow_fields.h"
};
static int max_shadow_read_only_fields =
	ARRAY_SIZE(shadow_read_only_fields);

static u16 shadow_read_write_fields[] = {
#define SHADOW_FIELD_RW(x) x,
#include "vmx_shadow_fields.h"
};
static int max_shadow_read_write_fields =
	ARRAY_SIZE(shadow_read_write_fields);

static const unsigned short vmcs_field_to_offset_table[] = {
	FIELD(VIRTUAL_PROCESSOR_ID, virtual_processor_id),
	FIELD(POSTED_INTR_NV, posted_intr_nv),
	FIELD(GUEST_ES_SELECTOR, guest_es_selector),
	FIELD(GUEST_CS_SELECTOR, guest_cs_selector),
	FIELD(GUEST_SS_SELECTOR, guest_ss_selector),
	FIELD(GUEST_DS_SELECTOR, guest_ds_selector),
	FIELD(GUEST_FS_SELECTOR, guest_fs_selector),
	FIELD(GUEST_GS_SELECTOR, guest_gs_selector),
	FIELD(GUEST_LDTR_SELECTOR, guest_ldtr_selector),
	FIELD(GUEST_TR_SELECTOR, guest_tr_selector),
	FIELD(GUEST_INTR_STATUS, guest_intr_status),
	FIELD(GUEST_PML_INDEX, guest_pml_index),
	FIELD(HOST_ES_SELECTOR, host_es_selector),
	FIELD(HOST_CS_SELECTOR, host_cs_selector),
	FIELD(HOST_SS_SELECTOR, host_ss_selector),
	FIELD(HOST_DS_SELECTOR, host_ds_selector),
	FIELD(HOST_FS_SELECTOR, host_fs_selector),
	FIELD(HOST_GS_SELECTOR, host_gs_selector),
	FIELD(HOST_TR_SELECTOR, host_tr_selector),
	FIELD64(IO_BITMAP_A, io_bitmap_a),
	FIELD64(IO_BITMAP_B, io_bitmap_b),
	FIELD64(MSR_BITMAP, msr_bitmap),
	FIELD64(VM_EXIT_MSR_STORE_ADDR, vm_exit_msr_store_addr),
	FIELD64(VM_EXIT_MSR_LOAD_ADDR, vm_exit_msr_load_addr),
	FIELD64(VM_ENTRY_MSR_LOAD_ADDR, vm_entry_msr_load_addr),
	FIELD64(PML_ADDRESS, pml_address),
	FIELD64(TSC_OFFSET, tsc_offset),
	FIELD64(VIRTUAL_APIC_PAGE_ADDR, virtual_apic_page_addr),
	FIELD64(APIC_ACCESS_ADDR, apic_access_addr),
	FIELD64(POSTED_INTR_DESC_ADDR, posted_intr_desc_addr),
	FIELD64(VM_FUNCTION_CONTROL, vm_function_control),
	FIELD64(EPT_POINTER, ept_pointer),
	FIELD64(EOI_EXIT_BITMAP0, eoi_exit_bitmap0),
	FIELD64(EOI_EXIT_BITMAP1, eoi_exit_bitmap1),
	FIELD64(EOI_EXIT_BITMAP2, eoi_exit_bitmap2),
	FIELD64(EOI_EXIT_BITMAP3, eoi_exit_bitmap3),
	FIELD64(EPTP_LIST_ADDRESS, eptp_list_address),
	FIELD64(VMREAD_BITMAP, vmread_bitmap),
	FIELD64(VMWRITE_BITMAP, vmwrite_bitmap),
	FIELD64(XSS_EXIT_BITMAP, xss_exit_bitmap),
	FIELD64(GUEST_PHYSICAL_ADDRESS, guest_physical_address),
	FIELD64(VMCS_LINK_POINTER, vmcs_link_pointer),
	FIELD64(GUEST_IA32_DEBUGCTL, guest_ia32_debugctl),
	FIELD64(GUEST_IA32_PAT, guest_ia32_pat),
	FIELD64(GUEST_IA32_EFER, guest_ia32_efer),
	FIELD64(GUEST_IA32_PERF_GLOBAL_CTRL, guest_ia32_perf_global_ctrl),
	FIELD64(GUEST_PDPTR0, guest_pdptr0),
	FIELD64(GUEST_PDPTR1, guest_pdptr1),
	FIELD64(GUEST_PDPTR2, guest_pdptr2),
	FIELD64(GUEST_PDPTR3, guest_pdptr3),
	FIELD64(GUEST_BNDCFGS, guest_bndcfgs),
	FIELD64(HOST_IA32_PAT, host_ia32_pat),
	FIELD64(HOST_IA32_EFER, host_ia32_efer),
	FIELD64(HOST_IA32_PERF_GLOBAL_CTRL, host_ia32_perf_global_ctrl),
	FIELD(PIN_BASED_VM_EXEC_CONTROL, pin_based_vm_exec_control),
	FIELD(CPU_BASED_VM_EXEC_CONTROL, cpu_based_vm_exec_control),
	FIELD(EXCEPTION_BITMAP, exception_bitmap),
	FIELD(PAGE_FAULT_ERROR_CODE_MASK, page_fault_error_code_mask),
	FIELD(PAGE_FAULT_ERROR_CODE_MATCH, page_fault_error_code_match),
	FIELD(CR3_TARGET_COUNT, cr3_target_count),
	FIELD(VM_EXIT_CONTROLS, vm_exit_controls),
	FIELD(VM_EXIT_MSR_STORE_COUNT, vm_exit_msr_store_count),
	FIELD(VM_EXIT_MSR_LOAD_COUNT, vm_exit_msr_load_count),
	FIELD(VM_ENTRY_CONTROLS, vm_entry_controls),
	FIELD(VM_ENTRY_MSR_LOAD_COUNT, vm_entry_msr_load_count),
	FIELD(VM_ENTRY_INTR_INFO_FIELD, vm_entry_intr_info_field),
	FIELD(VM_ENTRY_EXCEPTION_ERROR_CODE, vm_entry_exception_error_code),
	FIELD(VM_ENTRY_INSTRUCTION_LEN, vm_entry_instruction_len),
	FIELD(TPR_THRESHOLD, tpr_threshold),
	FIELD(SECONDARY_VM_EXEC_CONTROL, secondary_vm_exec_control),
	FIELD(VM_INSTRUCTION_ERROR, vm_instruction_error),
	FIELD(VM_EXIT_REASON, vm_exit_reason),
	FIELD(VM_EXIT_INTR_INFO, vm_exit_intr_info),
	FIELD(VM_EXIT_INTR_ERROR_CODE, vm_exit_intr_error_code),
	FIELD(IDT_VECTORING_INFO_FIELD, idt_vectoring_info_field),
	FIELD(IDT_VECTORING_ERROR_CODE, idt_vectoring_error_code),
	FIELD(VM_EXIT_INSTRUCTION_LEN, vm_exit_instruction_len),
	FIELD(VMX_INSTRUCTION_INFO, vmx_instruction_info),
	FIELD(GUEST_ES_LIMIT, guest_es_limit),
	FIELD(GUEST_CS_LIMIT, guest_cs_limit),
	FIELD(GUEST_SS_LIMIT, guest_ss_limit),
	FIELD(GUEST_DS_LIMIT, guest_ds_limit),
	FIELD(GUEST_FS_LIMIT, guest_fs_limit),
	FIELD(GUEST_GS_LIMIT, guest_gs_limit),
	FIELD(GUEST_LDTR_LIMIT, guest_ldtr_limit),
	FIELD(GUEST_TR_LIMIT, guest_tr_limit),
	FIELD(GUEST_GDTR_LIMIT, guest_gdtr_limit),
	FIELD(GUEST_IDTR_LIMIT, guest_idtr_limit),
	FIELD(GUEST_ES_AR_BYTES, guest_es_ar_bytes),
	FIELD(GUEST_CS_AR_BYTES, guest_cs_ar_bytes),
	FIELD(GUEST_SS_AR_BYTES, guest_ss_ar_bytes),
	FIELD(GUEST_DS_AR_BYTES, guest_ds_ar_bytes),
	FIELD(GUEST_FS_AR_BYTES, guest_fs_ar_bytes),
	FIELD(GUEST_GS_AR_BYTES, guest_gs_ar_bytes),
	FIELD(GUEST_LDTR_AR_BYTES, guest_ldtr_ar_bytes),
	FIELD(GUEST_TR_AR_BYTES, guest_tr_ar_bytes),
	FIELD(GUEST_INTERRUPTIBILITY_INFO, guest_interruptibility_info),
	FIELD(GUEST_ACTIVITY_STATE, guest_activity_state),
	FIELD(GUEST_SYSENTER_CS, guest_sysenter_cs),
	FIELD(HOST_IA32_SYSENTER_CS, host_ia32_sysenter_cs),
	FIELD(VMX_PREEMPTION_TIMER_VALUE, vmx_preemption_timer_value),
	FIELD(CR0_GUEST_HOST_MASK, cr0_guest_host_mask),
	FIELD(CR4_GUEST_HOST_MASK, cr4_guest_host_mask),
	FIELD(CR0_READ_SHADOW, cr0_read_shadow),
	FIELD(CR4_READ_SHADOW, cr4_read_shadow),
	FIELD(CR3_TARGET_VALUE0, cr3_target_value0),
	FIELD(CR3_TARGET_VALUE1, cr3_target_value1),
	FIELD(CR3_TARGET_VALUE2, cr3_target_value2),
	FIELD(CR3_TARGET_VALUE3, cr3_target_value3),
	FIELD(EXIT_QUALIFICATION, exit_qualification),
	FIELD(GUEST_LINEAR_ADDRESS, guest_linear_address),
	FIELD(GUEST_CR0, guest_cr0),
	FIELD(GUEST_CR3, guest_cr3),
	FIELD(GUEST_CR4, guest_cr4),
	FIELD(GUEST_ES_BASE, guest_es_base),
	FIELD(GUEST_CS_BASE, guest_cs_base),
	FIELD(GUEST_SS_BASE, guest_ss_base),
	FIELD(GUEST_DS_BASE, guest_ds_base),
	FIELD(GUEST_FS_BASE, guest_fs_base),
	FIELD(GUEST_GS_BASE, guest_gs_base),
	FIELD(GUEST_LDTR_BASE, guest_ldtr_base),
	FIELD(GUEST_TR_BASE, guest_tr_base),
	FIELD(GUEST_GDTR_BASE, guest_gdtr_base),
	FIELD(GUEST_IDTR_BASE, guest_idtr_base),
	FIELD(GUEST_DR7, guest_dr7),
	FIELD(GUEST_RSP, guest_rsp),
	FIELD(GUEST_RIP, guest_rip),
	FIELD(GUEST_RFLAGS, guest_rflags),
	FIELD(GUEST_PENDING_DBG_EXCEPTIONS, guest_pending_dbg_exceptions),
	FIELD(GUEST_SYSENTER_ESP, guest_sysenter_esp),
	FIELD(GUEST_SYSENTER_EIP, guest_sysenter_eip),
	FIELD(HOST_CR0, host_cr0),
	FIELD(HOST_CR3, host_cr3),
	FIELD(HOST_CR4, host_cr4),
	FIELD(HOST_FS_BASE, host_fs_base),
	FIELD(HOST_GS_BASE, host_gs_base),
	FIELD(HOST_TR_BASE, host_tr_base),
	FIELD(HOST_GDTR_BASE, host_gdtr_base),
	FIELD(HOST_IDTR_BASE, host_idtr_base),
	FIELD(HOST_IA32_SYSENTER_ESP, host_ia32_sysenter_esp),
	FIELD(HOST_IA32_SYSENTER_EIP, host_ia32_sysenter_eip),
	FIELD(HOST_RSP, host_rsp),
	FIELD(HOST_RIP, host_rip),
};

static inline short vmcs_field_to_offset(unsigned long field)
{
	const size_t size = ARRAY_SIZE(vmcs_field_to_offset_table);
	unsigned short offset;
	unsigned index;

	if (field >> 15)
		return -ENOENT;

	index = ROL16(field, 6);
	if (index >= size)
		return -ENOENT;

	index = array_index_nospec(index, size);
	offset = vmcs_field_to_offset_table[index];
	if (offset == 0)
		return -ENOENT;
	return offset;
}

static inline struct vmcs12 *get_vmcs12(struct kvm_vcpu *vcpu)
{
	return to_vmx(vcpu)->nested.cached_vmcs12;
}

static inline struct vmcs12 *get_shadow_vmcs12(struct kvm_vcpu *vcpu)
{
	return to_vmx(vcpu)->nested.cached_shadow_vmcs12;
}

static bool nested_ept_ad_enabled(struct kvm_vcpu *vcpu);
static unsigned long nested_ept_get_cr3(struct kvm_vcpu *vcpu);
static u64 construct_eptp(struct kvm_vcpu *vcpu, unsigned long root_hpa);
static bool vmx_xsaves_supported(void);
static void vmx_set_segment(struct kvm_vcpu *vcpu,
			    struct kvm_segment *var, int seg);
static void vmx_get_segment(struct kvm_vcpu *vcpu,
			    struct kvm_segment *var, int seg);
static bool guest_state_valid(struct kvm_vcpu *vcpu);
static u32 vmx_segment_access_rights(struct kvm_segment *var);
static void copy_shadow_to_vmcs12(struct vcpu_vmx *vmx);
static bool vmx_get_nmi_mask(struct kvm_vcpu *vcpu);
static void vmx_set_nmi_mask(struct kvm_vcpu *vcpu, bool masked);
static bool nested_vmx_is_page_fault_vmexit(struct vmcs12 *vmcs12,
					    u16 error_code);
static void vmx_update_msr_bitmap(struct kvm_vcpu *vcpu);
static __always_inline void vmx_disable_intercept_for_msr(unsigned long *msr_bitmap,
							  u32 msr, int type);

static DEFINE_PER_CPU(struct vmcs *, vmxarea);
static DEFINE_PER_CPU(struct vmcs *, current_vmcs);
/*
 * We maintain a per-CPU linked-list of VMCS loaded on that CPU. This is needed
 * when a CPU is brought down, and we need to VMCLEAR all VMCSs loaded on it.
 */
static DEFINE_PER_CPU(struct list_head, loaded_vmcss_on_cpu);

/*
 * We maintian a per-CPU linked-list of vCPU, so in wakeup_handler() we
 * can find which vCPU should be waken up.
 */
static DEFINE_PER_CPU(struct list_head, blocked_vcpu_on_cpu);
static DEFINE_PER_CPU(spinlock_t, blocked_vcpu_on_cpu_lock);

enum {
	VMX_VMREAD_BITMAP,
	VMX_VMWRITE_BITMAP,
	VMX_BITMAP_NR
};

static unsigned long *vmx_bitmap[VMX_BITMAP_NR];

#define vmx_vmread_bitmap                    (vmx_bitmap[VMX_VMREAD_BITMAP])
#define vmx_vmwrite_bitmap                   (vmx_bitmap[VMX_VMWRITE_BITMAP])

static bool cpu_has_load_ia32_efer;
static bool cpu_has_load_perf_global_ctrl;

static DECLARE_BITMAP(vmx_vpid_bitmap, VMX_NR_VPIDS);
static DEFINE_SPINLOCK(vmx_vpid_lock);

static struct vmcs_config {
	int size;
	int order;
	u32 basic_cap;
	u32 revision_id;
	u32 pin_based_exec_ctrl;
	u32 cpu_based_exec_ctrl;
	u32 cpu_based_2nd_exec_ctrl;
	u32 vmexit_ctrl;
	u32 vmentry_ctrl;
	struct nested_vmx_msrs nested;
} vmcs_config;

static struct vmx_capability {
	u32 ept;
	u32 vpid;
} vmx_capability;

#define VMX_SEGMENT_FIELD(seg)					\
	[VCPU_SREG_##seg] = {                                   \
		.selector = GUEST_##seg##_SELECTOR,		\
		.base = GUEST_##seg##_BASE,		   	\
		.limit = GUEST_##seg##_LIMIT,		   	\
		.ar_bytes = GUEST_##seg##_AR_BYTES,	   	\
	}

static const struct kvm_vmx_segment_field {
	unsigned selector;
	unsigned base;
	unsigned limit;
	unsigned ar_bytes;
} kvm_vmx_segment_fields[] = {
	VMX_SEGMENT_FIELD(CS),
	VMX_SEGMENT_FIELD(DS),
	VMX_SEGMENT_FIELD(ES),
	VMX_SEGMENT_FIELD(FS),
	VMX_SEGMENT_FIELD(GS),
	VMX_SEGMENT_FIELD(SS),
	VMX_SEGMENT_FIELD(TR),
	VMX_SEGMENT_FIELD(LDTR),
};

static u64 host_efer;

static void ept_save_pdptrs(struct kvm_vcpu *vcpu);

/*
 * Keep MSR_STAR at the end, as setup_msrs() will try to optimize it
 * away by decrementing the array size.
 */
static const u32 vmx_msr_index[] = {
#ifdef CONFIG_X86_64
	MSR_SYSCALL_MASK, MSR_LSTAR, MSR_CSTAR,
#endif
	MSR_EFER, MSR_TSC_AUX, MSR_STAR,
};

DEFINE_STATIC_KEY_FALSE(enable_evmcs);

#define current_evmcs ((struct hv_enlightened_vmcs *)this_cpu_read(current_vmcs))

#define KVM_EVMCS_VERSION 1

#if IS_ENABLED(CONFIG_HYPERV)
static bool __read_mostly enlightened_vmcs = true;
module_param(enlightened_vmcs, bool, 0444);

static inline void evmcs_write64(unsigned long field, u64 value)
{
	u16 clean_field;
	int offset = get_evmcs_offset(field, &clean_field);

	if (offset < 0)
		return;

	*(u64 *)((char *)current_evmcs + offset) = value;

	current_evmcs->hv_clean_fields &= ~clean_field;
}

static inline void evmcs_write32(unsigned long field, u32 value)
{
	u16 clean_field;
	int offset = get_evmcs_offset(field, &clean_field);

	if (offset < 0)
		return;

	*(u32 *)((char *)current_evmcs + offset) = value;
	current_evmcs->hv_clean_fields &= ~clean_field;
}

static inline void evmcs_write16(unsigned long field, u16 value)
{
	u16 clean_field;
	int offset = get_evmcs_offset(field, &clean_field);

	if (offset < 0)
		return;

	*(u16 *)((char *)current_evmcs + offset) = value;
	current_evmcs->hv_clean_fields &= ~clean_field;
}

static inline u64 evmcs_read64(unsigned long field)
{
	int offset = get_evmcs_offset(field, NULL);

	if (offset < 0)
		return 0;

	return *(u64 *)((char *)current_evmcs + offset);
}

static inline u32 evmcs_read32(unsigned long field)
{
	int offset = get_evmcs_offset(field, NULL);

	if (offset < 0)
		return 0;

	return *(u32 *)((char *)current_evmcs + offset);
}

static inline u16 evmcs_read16(unsigned long field)
{
	int offset = get_evmcs_offset(field, NULL);

	if (offset < 0)
		return 0;

	return *(u16 *)((char *)current_evmcs + offset);
}

static inline void evmcs_touch_msr_bitmap(void)
{
	if (unlikely(!current_evmcs))
		return;

	if (current_evmcs->hv_enlightenments_control.msr_bitmap)
		current_evmcs->hv_clean_fields &=
			~HV_VMX_ENLIGHTENED_CLEAN_FIELD_MSR_BITMAP;
}

static void evmcs_load(u64 phys_addr)
{
	struct hv_vp_assist_page *vp_ap =
		hv_get_vp_assist_page(smp_processor_id());

	vp_ap->current_nested_vmcs = phys_addr;
	vp_ap->enlighten_vmentry = 1;
}

static void evmcs_sanitize_exec_ctrls(struct vmcs_config *vmcs_conf)
{
	/*
	 * Enlightened VMCSv1 doesn't support these:
	 *
	 *	POSTED_INTR_NV                  = 0x00000002,
	 *	GUEST_INTR_STATUS               = 0x00000810,
	 *	APIC_ACCESS_ADDR		= 0x00002014,
	 *	POSTED_INTR_DESC_ADDR           = 0x00002016,
	 *	EOI_EXIT_BITMAP0                = 0x0000201c,
	 *	EOI_EXIT_BITMAP1                = 0x0000201e,
	 *	EOI_EXIT_BITMAP2                = 0x00002020,
	 *	EOI_EXIT_BITMAP3                = 0x00002022,
	 */
	vmcs_conf->pin_based_exec_ctrl &= ~PIN_BASED_POSTED_INTR;
	vmcs_conf->cpu_based_2nd_exec_ctrl &=
		~SECONDARY_EXEC_VIRTUAL_INTR_DELIVERY;
	vmcs_conf->cpu_based_2nd_exec_ctrl &=
		~SECONDARY_EXEC_VIRTUALIZE_APIC_ACCESSES;
	vmcs_conf->cpu_based_2nd_exec_ctrl &=
		~SECONDARY_EXEC_APIC_REGISTER_VIRT;

	/*
	 *	GUEST_PML_INDEX			= 0x00000812,
	 *	PML_ADDRESS			= 0x0000200e,
	 */
	vmcs_conf->cpu_based_2nd_exec_ctrl &= ~SECONDARY_EXEC_ENABLE_PML;

	/*	VM_FUNCTION_CONTROL             = 0x00002018, */
	vmcs_conf->cpu_based_2nd_exec_ctrl &= ~SECONDARY_EXEC_ENABLE_VMFUNC;

	/*
	 *	EPTP_LIST_ADDRESS               = 0x00002024,
	 *	VMREAD_BITMAP                   = 0x00002026,
	 *	VMWRITE_BITMAP                  = 0x00002028,
	 */
	vmcs_conf->cpu_based_2nd_exec_ctrl &= ~SECONDARY_EXEC_SHADOW_VMCS;

	/*
	 *	TSC_MULTIPLIER                  = 0x00002032,
	 */
	vmcs_conf->cpu_based_2nd_exec_ctrl &= ~SECONDARY_EXEC_TSC_SCALING;

	/*
	 *	PLE_GAP                         = 0x00004020,
	 *	PLE_WINDOW                      = 0x00004022,
	 */
	vmcs_conf->cpu_based_2nd_exec_ctrl &= ~SECONDARY_EXEC_PAUSE_LOOP_EXITING;

	/*
	 *	VMX_PREEMPTION_TIMER_VALUE      = 0x0000482E,
	 */
	vmcs_conf->pin_based_exec_ctrl &= ~PIN_BASED_VMX_PREEMPTION_TIMER;

	/*
	 *      GUEST_IA32_PERF_GLOBAL_CTRL     = 0x00002808,
	 *      HOST_IA32_PERF_GLOBAL_CTRL      = 0x00002c04,
	 */
	vmcs_conf->vmexit_ctrl &= ~VM_EXIT_LOAD_IA32_PERF_GLOBAL_CTRL;
	vmcs_conf->vmentry_ctrl &= ~VM_ENTRY_LOAD_IA32_PERF_GLOBAL_CTRL;

	/*
	 * Currently unsupported in KVM:
	 *	GUEST_IA32_RTIT_CTL		= 0x00002814,
	 */
}

/* check_ept_pointer() should be under protection of ept_pointer_lock. */
static void check_ept_pointer_match(struct kvm *kvm)
{
	struct kvm_vcpu *vcpu;
	u64 tmp_eptp = INVALID_PAGE;
	int i;

	kvm_for_each_vcpu(i, vcpu, kvm) {
		if (!VALID_PAGE(tmp_eptp)) {
			tmp_eptp = to_vmx(vcpu)->ept_pointer;
		} else if (tmp_eptp != to_vmx(vcpu)->ept_pointer) {
			to_kvm_vmx(kvm)->ept_pointers_match
				= EPT_POINTERS_MISMATCH;
			return;
		}
	}

	to_kvm_vmx(kvm)->ept_pointers_match = EPT_POINTERS_MATCH;
}

static int vmx_hv_remote_flush_tlb(struct kvm *kvm)
{
	int ret;

	spin_lock(&to_kvm_vmx(kvm)->ept_pointer_lock);

	if (to_kvm_vmx(kvm)->ept_pointers_match == EPT_POINTERS_CHECK)
		check_ept_pointer_match(kvm);

	if (to_kvm_vmx(kvm)->ept_pointers_match != EPT_POINTERS_MATCH) {
		ret = -ENOTSUPP;
		goto out;
	}

	/*
	 * FLUSH_GUEST_PHYSICAL_ADDRESS_SPACE hypercall needs the address of the
	 * base of EPT PML4 table, strip off EPT configuration information.
	 */
	ret = hyperv_flush_guest_mapping(
			to_vmx(kvm_get_vcpu(kvm, 0))->ept_pointer & PAGE_MASK);

out:
	spin_unlock(&to_kvm_vmx(kvm)->ept_pointer_lock);
	return ret;
}
#else /* !IS_ENABLED(CONFIG_HYPERV) */
static inline void evmcs_write64(unsigned long field, u64 value) {}
static inline void evmcs_write32(unsigned long field, u32 value) {}
static inline void evmcs_write16(unsigned long field, u16 value) {}
static inline u64 evmcs_read64(unsigned long field) { return 0; }
static inline u32 evmcs_read32(unsigned long field) { return 0; }
static inline u16 evmcs_read16(unsigned long field) { return 0; }
static inline void evmcs_load(u64 phys_addr) {}
static inline void evmcs_sanitize_exec_ctrls(struct vmcs_config *vmcs_conf) {}
static inline void evmcs_touch_msr_bitmap(void) {}
#endif /* IS_ENABLED(CONFIG_HYPERV) */

static inline bool is_exception_n(u32 intr_info, u8 vector)
{
	return (intr_info & (INTR_INFO_INTR_TYPE_MASK | INTR_INFO_VECTOR_MASK |
			     INTR_INFO_VALID_MASK)) ==
		(INTR_TYPE_HARD_EXCEPTION | vector | INTR_INFO_VALID_MASK);
}

static inline bool is_debug(u32 intr_info)
{
	return is_exception_n(intr_info, DB_VECTOR);
}

static inline bool is_breakpoint(u32 intr_info)
{
	return is_exception_n(intr_info, BP_VECTOR);
}

static inline bool is_page_fault(u32 intr_info)
{
	return is_exception_n(intr_info, PF_VECTOR);
}

static inline bool is_no_device(u32 intr_info)
{
	return is_exception_n(intr_info, NM_VECTOR);
}

static inline bool is_invalid_opcode(u32 intr_info)
{
	return is_exception_n(intr_info, UD_VECTOR);
}

static inline bool is_gp_fault(u32 intr_info)
{
	return is_exception_n(intr_info, GP_VECTOR);
}

static inline bool is_external_interrupt(u32 intr_info)
{
	return (intr_info & (INTR_INFO_INTR_TYPE_MASK | INTR_INFO_VALID_MASK))
		== (INTR_TYPE_EXT_INTR | INTR_INFO_VALID_MASK);
}

static inline bool is_machine_check(u32 intr_info)
{
	return (intr_info & (INTR_INFO_INTR_TYPE_MASK | INTR_INFO_VECTOR_MASK |
			     INTR_INFO_VALID_MASK)) ==
		(INTR_TYPE_HARD_EXCEPTION | MC_VECTOR | INTR_INFO_VALID_MASK);
}

/* Undocumented: icebp/int1 */
static inline bool is_icebp(u32 intr_info)
{
	return (intr_info & (INTR_INFO_INTR_TYPE_MASK | INTR_INFO_VALID_MASK))
		== (INTR_TYPE_PRIV_SW_EXCEPTION | INTR_INFO_VALID_MASK);
}

static inline bool cpu_has_vmx_msr_bitmap(void)
{
	return vmcs_config.cpu_based_exec_ctrl & CPU_BASED_USE_MSR_BITMAPS;
}

static inline bool cpu_has_vmx_tpr_shadow(void)
{
	return vmcs_config.cpu_based_exec_ctrl & CPU_BASED_TPR_SHADOW;
}

static inline bool cpu_need_tpr_shadow(struct kvm_vcpu *vcpu)
{
	return cpu_has_vmx_tpr_shadow() && lapic_in_kernel(vcpu);
}

static inline bool cpu_has_secondary_exec_ctrls(void)
{
	return vmcs_config.cpu_based_exec_ctrl &
		CPU_BASED_ACTIVATE_SECONDARY_CONTROLS;
}

static inline bool cpu_has_vmx_virtualize_apic_accesses(void)
{
	return vmcs_config.cpu_based_2nd_exec_ctrl &
		SECONDARY_EXEC_VIRTUALIZE_APIC_ACCESSES;
}

static inline bool cpu_has_vmx_virtualize_x2apic_mode(void)
{
	return vmcs_config.cpu_based_2nd_exec_ctrl &
		SECONDARY_EXEC_VIRTUALIZE_X2APIC_MODE;
}

static inline bool cpu_has_vmx_apic_register_virt(void)
{
	return vmcs_config.cpu_based_2nd_exec_ctrl &
		SECONDARY_EXEC_APIC_REGISTER_VIRT;
}

static inline bool cpu_has_vmx_virtual_intr_delivery(void)
{
	return vmcs_config.cpu_based_2nd_exec_ctrl &
		SECONDARY_EXEC_VIRTUAL_INTR_DELIVERY;
}

static inline bool cpu_has_vmx_encls_vmexit(void)
{
	return vmcs_config.cpu_based_2nd_exec_ctrl &
		SECONDARY_EXEC_ENCLS_EXITING;
}

/*
 * Comment's format: document - errata name - stepping - processor name.
 * Refer from
 * https://www.virtualbox.org/svn/vbox/trunk/src/VBox/VMM/VMMR0/HMR0.cpp
 */
static u32 vmx_preemption_cpu_tfms[] = {
/* 323344.pdf - BA86   - D0 - Xeon 7500 Series */
0x000206E6,
/* 323056.pdf - AAX65  - C2 - Xeon L3406 */
/* 322814.pdf - AAT59  - C2 - i7-600, i5-500, i5-400 and i3-300 Mobile */
/* 322911.pdf - AAU65  - C2 - i5-600, i3-500 Desktop and Pentium G6950 */
0x00020652,
/* 322911.pdf - AAU65  - K0 - i5-600, i3-500 Desktop and Pentium G6950 */
0x00020655,
/* 322373.pdf - AAO95  - B1 - Xeon 3400 Series */
/* 322166.pdf - AAN92  - B1 - i7-800 and i5-700 Desktop */
/*
 * 320767.pdf - AAP86  - B1 -
 * i7-900 Mobile Extreme, i7-800 and i7-700 Mobile
 */
0x000106E5,
/* 321333.pdf - AAM126 - C0 - Xeon 3500 */
0x000106A0,
/* 321333.pdf - AAM126 - C1 - Xeon 3500 */
0x000106A1,
/* 320836.pdf - AAJ124 - C0 - i7-900 Desktop Extreme and i7-900 Desktop */
0x000106A4,
 /* 321333.pdf - AAM126 - D0 - Xeon 3500 */
 /* 321324.pdf - AAK139 - D0 - Xeon 5500 */
 /* 320836.pdf - AAJ124 - D0 - i7-900 Extreme and i7-900 Desktop */
0x000106A5,
};

static inline bool cpu_has_broken_vmx_preemption_timer(void)
{
	u32 eax = cpuid_eax(0x00000001), i;

	/* Clear the reserved bits */
	eax &= ~(0x3U << 14 | 0xfU << 28);
	for (i = 0; i < ARRAY_SIZE(vmx_preemption_cpu_tfms); i++)
		if (eax == vmx_preemption_cpu_tfms[i])
			return true;

	return false;
}

static inline bool cpu_has_vmx_preemption_timer(void)
{
	return vmcs_config.pin_based_exec_ctrl &
		PIN_BASED_VMX_PREEMPTION_TIMER;
}

static inline bool cpu_has_vmx_posted_intr(void)
{
	return IS_ENABLED(CONFIG_X86_LOCAL_APIC) &&
		vmcs_config.pin_based_exec_ctrl & PIN_BASED_POSTED_INTR;
}

static inline bool cpu_has_vmx_apicv(void)
{
	return cpu_has_vmx_apic_register_virt() &&
		cpu_has_vmx_virtual_intr_delivery() &&
		cpu_has_vmx_posted_intr();
}

static inline bool cpu_has_vmx_flexpriority(void)
{
	return cpu_has_vmx_tpr_shadow() &&
		cpu_has_vmx_virtualize_apic_accesses();
}

static inline bool cpu_has_vmx_ept_execute_only(void)
{
	return vmx_capability.ept & VMX_EPT_EXECUTE_ONLY_BIT;
}

static inline bool cpu_has_vmx_ept_2m_page(void)
{
	return vmx_capability.ept & VMX_EPT_2MB_PAGE_BIT;
}

static inline bool cpu_has_vmx_ept_1g_page(void)
{
	return vmx_capability.ept & VMX_EPT_1GB_PAGE_BIT;
}

static inline bool cpu_has_vmx_ept_4levels(void)
{
	return vmx_capability.ept & VMX_EPT_PAGE_WALK_4_BIT;
}

static inline bool cpu_has_vmx_ept_mt_wb(void)
{
	return vmx_capability.ept & VMX_EPTP_WB_BIT;
}

static inline bool cpu_has_vmx_ept_5levels(void)
{
	return vmx_capability.ept & VMX_EPT_PAGE_WALK_5_BIT;
}

static inline bool cpu_has_vmx_ept_ad_bits(void)
{
	return vmx_capability.ept & VMX_EPT_AD_BIT;
}

static inline bool cpu_has_vmx_invept_context(void)
{
	return vmx_capability.ept & VMX_EPT_EXTENT_CONTEXT_BIT;
}

static inline bool cpu_has_vmx_invept_global(void)
{
	return vmx_capability.ept & VMX_EPT_EXTENT_GLOBAL_BIT;
}

static inline bool cpu_has_vmx_invvpid_individual_addr(void)
{
	return vmx_capability.vpid & VMX_VPID_EXTENT_INDIVIDUAL_ADDR_BIT;
}

static inline bool cpu_has_vmx_invvpid_single(void)
{
	return vmx_capability.vpid & VMX_VPID_EXTENT_SINGLE_CONTEXT_BIT;
}

static inline bool cpu_has_vmx_invvpid_global(void)
{
	return vmx_capability.vpid & VMX_VPID_EXTENT_GLOBAL_CONTEXT_BIT;
}

static inline bool cpu_has_vmx_invvpid(void)
{
	return vmx_capability.vpid & VMX_VPID_INVVPID_BIT;
}

static inline bool cpu_has_vmx_ept(void)
{
	return vmcs_config.cpu_based_2nd_exec_ctrl &
		SECONDARY_EXEC_ENABLE_EPT;
}

static inline bool cpu_has_vmx_unrestricted_guest(void)
{
	return vmcs_config.cpu_based_2nd_exec_ctrl &
		SECONDARY_EXEC_UNRESTRICTED_GUEST;
}

static inline bool cpu_has_vmx_ple(void)
{
	return vmcs_config.cpu_based_2nd_exec_ctrl &
		SECONDARY_EXEC_PAUSE_LOOP_EXITING;
}

static inline bool cpu_has_vmx_basic_inout(void)
{
	return	(((u64)vmcs_config.basic_cap << 32) & VMX_BASIC_INOUT);
}

static inline bool cpu_need_virtualize_apic_accesses(struct kvm_vcpu *vcpu)
{
	return flexpriority_enabled && lapic_in_kernel(vcpu);
}

static inline bool cpu_has_vmx_vpid(void)
{
	return vmcs_config.cpu_based_2nd_exec_ctrl &
		SECONDARY_EXEC_ENABLE_VPID;
}

static inline bool cpu_has_vmx_rdtscp(void)
{
	return vmcs_config.cpu_based_2nd_exec_ctrl &
		SECONDARY_EXEC_RDTSCP;
}

static inline bool cpu_has_vmx_invpcid(void)
{
	return vmcs_config.cpu_based_2nd_exec_ctrl &
		SECONDARY_EXEC_ENABLE_INVPCID;
}

static inline bool cpu_has_virtual_nmis(void)
{
	return vmcs_config.pin_based_exec_ctrl & PIN_BASED_VIRTUAL_NMIS;
}

static inline bool cpu_has_vmx_wbinvd_exit(void)
{
	return vmcs_config.cpu_based_2nd_exec_ctrl &
		SECONDARY_EXEC_WBINVD_EXITING;
}

static inline bool cpu_has_vmx_shadow_vmcs(void)
{
	u64 vmx_msr;
	rdmsrl(MSR_IA32_VMX_MISC, vmx_msr);
	/* check if the cpu supports writing r/o exit information fields */
	if (!(vmx_msr & MSR_IA32_VMX_MISC_VMWRITE_SHADOW_RO_FIELDS))
		return false;

	return vmcs_config.cpu_based_2nd_exec_ctrl &
		SECONDARY_EXEC_SHADOW_VMCS;
}

static inline bool cpu_has_vmx_pml(void)
{
	return vmcs_config.cpu_based_2nd_exec_ctrl & SECONDARY_EXEC_ENABLE_PML;
}

static inline bool cpu_has_vmx_tsc_scaling(void)
{
	return vmcs_config.cpu_based_2nd_exec_ctrl &
		SECONDARY_EXEC_TSC_SCALING;
}

static inline bool cpu_has_vmx_vmfunc(void)
{
	return vmcs_config.cpu_based_2nd_exec_ctrl &
		SECONDARY_EXEC_ENABLE_VMFUNC;
}

static bool vmx_umip_emulated(void)
{
	return vmcs_config.cpu_based_2nd_exec_ctrl &
		SECONDARY_EXEC_DESC;
}

static inline bool report_flexpriority(void)
{
	return flexpriority_enabled;
}

static inline unsigned nested_cpu_vmx_misc_cr3_count(struct kvm_vcpu *vcpu)
{
	return vmx_misc_cr3_count(to_vmx(vcpu)->nested.msrs.misc_low);
}

/*
 * Do the virtual VMX capability MSRs specify that L1 can use VMWRITE
 * to modify any valid field of the VMCS, or are the VM-exit
 * information fields read-only?
 */
static inline bool nested_cpu_has_vmwrite_any_field(struct kvm_vcpu *vcpu)
{
	return to_vmx(vcpu)->nested.msrs.misc_low &
		MSR_IA32_VMX_MISC_VMWRITE_SHADOW_RO_FIELDS;
}

static inline bool nested_cpu_has_zero_length_injection(struct kvm_vcpu *vcpu)
{
	return to_vmx(vcpu)->nested.msrs.misc_low & VMX_MISC_ZERO_LEN_INS;
}

static inline bool nested_cpu_supports_monitor_trap_flag(struct kvm_vcpu *vcpu)
{
	return to_vmx(vcpu)->nested.msrs.procbased_ctls_high &
			CPU_BASED_MONITOR_TRAP_FLAG;
}

static inline bool nested_cpu_has_vmx_shadow_vmcs(struct kvm_vcpu *vcpu)
{
	return to_vmx(vcpu)->nested.msrs.secondary_ctls_high &
		SECONDARY_EXEC_SHADOW_VMCS;
}

static inline bool nested_cpu_has(struct vmcs12 *vmcs12, u32 bit)
{
	return vmcs12->cpu_based_vm_exec_control & bit;
}

static inline bool nested_cpu_has2(struct vmcs12 *vmcs12, u32 bit)
{
	return (vmcs12->cpu_based_vm_exec_control &
			CPU_BASED_ACTIVATE_SECONDARY_CONTROLS) &&
		(vmcs12->secondary_vm_exec_control & bit);
}

static inline bool nested_cpu_has_preemption_timer(struct vmcs12 *vmcs12)
{
	return vmcs12->pin_based_vm_exec_control &
		PIN_BASED_VMX_PREEMPTION_TIMER;
}

static inline bool nested_cpu_has_nmi_exiting(struct vmcs12 *vmcs12)
{
	return vmcs12->pin_based_vm_exec_control & PIN_BASED_NMI_EXITING;
}

static inline bool nested_cpu_has_virtual_nmis(struct vmcs12 *vmcs12)
{
	return vmcs12->pin_based_vm_exec_control & PIN_BASED_VIRTUAL_NMIS;
}

static inline int nested_cpu_has_ept(struct vmcs12 *vmcs12)
{
	return nested_cpu_has2(vmcs12, SECONDARY_EXEC_ENABLE_EPT);
}

static inline bool nested_cpu_has_xsaves(struct vmcs12 *vmcs12)
{
	return nested_cpu_has2(vmcs12, SECONDARY_EXEC_XSAVES);
}

static inline bool nested_cpu_has_pml(struct vmcs12 *vmcs12)
{
	return nested_cpu_has2(vmcs12, SECONDARY_EXEC_ENABLE_PML);
}

static inline bool nested_cpu_has_virt_x2apic_mode(struct vmcs12 *vmcs12)
{
	return nested_cpu_has2(vmcs12, SECONDARY_EXEC_VIRTUALIZE_X2APIC_MODE);
}

static inline bool nested_cpu_has_vpid(struct vmcs12 *vmcs12)
{
	return nested_cpu_has2(vmcs12, SECONDARY_EXEC_ENABLE_VPID);
}

static inline bool nested_cpu_has_apic_reg_virt(struct vmcs12 *vmcs12)
{
	return nested_cpu_has2(vmcs12, SECONDARY_EXEC_APIC_REGISTER_VIRT);
}

static inline bool nested_cpu_has_vid(struct vmcs12 *vmcs12)
{
	return nested_cpu_has2(vmcs12, SECONDARY_EXEC_VIRTUAL_INTR_DELIVERY);
}

static inline bool nested_cpu_has_posted_intr(struct vmcs12 *vmcs12)
{
	return vmcs12->pin_based_vm_exec_control & PIN_BASED_POSTED_INTR;
}

static inline bool nested_cpu_has_vmfunc(struct vmcs12 *vmcs12)
{
	return nested_cpu_has2(vmcs12, SECONDARY_EXEC_ENABLE_VMFUNC);
}

static inline bool nested_cpu_has_eptp_switching(struct vmcs12 *vmcs12)
{
	return nested_cpu_has_vmfunc(vmcs12) &&
		(vmcs12->vm_function_control &
		 VMX_VMFUNC_EPTP_SWITCHING);
}

static inline bool nested_cpu_has_shadow_vmcs(struct vmcs12 *vmcs12)
{
	return nested_cpu_has2(vmcs12, SECONDARY_EXEC_SHADOW_VMCS);
}

static inline bool nested_cpu_has_save_preemption_timer(struct vmcs12 *vmcs12)
{
	return vmcs12->vm_exit_controls &
	    VM_EXIT_SAVE_VMX_PREEMPTION_TIMER;
}

static inline bool is_nmi(u32 intr_info)
{
	return (intr_info & (INTR_INFO_INTR_TYPE_MASK | INTR_INFO_VALID_MASK))
		== (INTR_TYPE_NMI_INTR | INTR_INFO_VALID_MASK);
}

static void nested_vmx_vmexit(struct kvm_vcpu *vcpu, u32 exit_reason,
			      u32 exit_intr_info,
			      unsigned long exit_qualification);
static void nested_vmx_entry_failure(struct kvm_vcpu *vcpu,
			struct vmcs12 *vmcs12,
			u32 reason, unsigned long qualification);

static int __find_msr_index(struct vcpu_vmx *vmx, u32 msr)
{
	int i;

	for (i = 0; i < vmx->nmsrs; ++i)
		if (vmx_msr_index[vmx->guest_msrs[i].index] == msr)
			return i;
	return -1;
}

static inline void __invvpid(unsigned long ext, u16 vpid, gva_t gva)
{
    struct {
	u64 vpid : 16;
	u64 rsvd : 48;
	u64 gva;
    } operand = { vpid, 0, gva };
    bool error;

    asm volatile (__ex(ASM_VMX_INVVPID) CC_SET(na)
		  : CC_OUT(na) (error) : "a"(&operand), "c"(ext)
		  : "memory");
    BUG_ON(error);
}

static inline void __invept(unsigned long ext, u64 eptp, gpa_t gpa)
{
	struct {
		u64 eptp, gpa;
	} operand = {eptp, gpa};
	bool error;

	asm volatile (__ex(ASM_VMX_INVEPT) CC_SET(na)
		      : CC_OUT(na) (error) : "a" (&operand), "c" (ext)
		      : "memory");
	BUG_ON(error);
}

static void vmx_setup_fb_clear_ctrl(void)
{
	u64 msr;

	if (boot_cpu_has(X86_FEATURE_ARCH_CAPABILITIES) &&
	    !boot_cpu_has_bug(X86_BUG_MDS) &&
	    !boot_cpu_has_bug(X86_BUG_TAA)) {
		rdmsrl(MSR_IA32_ARCH_CAPABILITIES, msr);
		if (msr & ARCH_CAP_FB_CLEAR_CTRL)
			vmx_fb_clear_ctrl_available = true;
	}
}

static __always_inline void vmx_disable_fb_clear(struct vcpu_vmx *vmx)
{
	u64 msr;

	if (!vmx->disable_fb_clear)
		return;

	msr = __rdmsr(MSR_IA32_MCU_OPT_CTRL);
	msr |= FB_CLEAR_DIS;
	native_wrmsrl(MSR_IA32_MCU_OPT_CTRL, msr);
	/* Cache the MSR value to avoid reading it later */
	vmx->msr_ia32_mcu_opt_ctrl = msr;
}

static __always_inline void vmx_enable_fb_clear(struct vcpu_vmx *vmx)
{
	if (!vmx->disable_fb_clear)
		return;

	vmx->msr_ia32_mcu_opt_ctrl &= ~FB_CLEAR_DIS;
	native_wrmsrl(MSR_IA32_MCU_OPT_CTRL, vmx->msr_ia32_mcu_opt_ctrl);
}

static void vmx_update_fb_clear_dis(struct kvm_vcpu *vcpu, struct vcpu_vmx *vmx)
{
	vmx->disable_fb_clear = vmx_fb_clear_ctrl_available;

	/*
	 * If guest will not execute VERW, there is no need to set FB_CLEAR_DIS
	 * at VMEntry. Skip the MSR read/write when a guest has no use case to
	 * execute VERW.
	 */
	if ((vcpu->arch.arch_capabilities & ARCH_CAP_FB_CLEAR) ||
	   ((vcpu->arch.arch_capabilities & ARCH_CAP_MDS_NO) &&
	    (vcpu->arch.arch_capabilities & ARCH_CAP_TAA_NO) &&
	    (vcpu->arch.arch_capabilities & ARCH_CAP_PSDP_NO) &&
	    (vcpu->arch.arch_capabilities & ARCH_CAP_FBSDP_NO) &&
	    (vcpu->arch.arch_capabilities & ARCH_CAP_SBDR_SSDP_NO)))
		vmx->disable_fb_clear = false;
}

static struct shared_msr_entry *find_msr_entry(struct vcpu_vmx *vmx, u32 msr)
{
	int i;

	i = __find_msr_index(vmx, msr);
	if (i >= 0)
		return &vmx->guest_msrs[i];
	return NULL;
}

static void vmcs_clear(struct vmcs *vmcs)
{
	u64 phys_addr = __pa(vmcs);
	bool error;

	asm volatile (__ex(ASM_VMX_VMCLEAR_RAX) CC_SET(na)
		      : CC_OUT(na) (error) : "a"(&phys_addr), "m"(phys_addr)
		      : "memory");
	if (unlikely(error))
		printk(KERN_ERR "kvm: vmclear fail: %p/%llx\n",
		       vmcs, phys_addr);
}

static inline void loaded_vmcs_init(struct loaded_vmcs *loaded_vmcs)
{
	vmcs_clear(loaded_vmcs->vmcs);
	if (loaded_vmcs->shadow_vmcs && loaded_vmcs->launched)
		vmcs_clear(loaded_vmcs->shadow_vmcs);
	loaded_vmcs->cpu = -1;
	loaded_vmcs->launched = 0;
}

static void vmcs_load(struct vmcs *vmcs)
{
	u64 phys_addr = __pa(vmcs);
	bool error;

	if (static_branch_unlikely(&enable_evmcs))
		return evmcs_load(phys_addr);

	asm volatile (__ex(ASM_VMX_VMPTRLD_RAX) CC_SET(na)
		      : CC_OUT(na) (error) : "a"(&phys_addr), "m"(phys_addr)
		      : "memory");
	if (unlikely(error))
		printk(KERN_ERR "kvm: vmptrld %p/%llx failed\n",
		       vmcs, phys_addr);
}

#ifdef CONFIG_KEXEC_CORE
static void crash_vmclear_local_loaded_vmcss(void)
{
	int cpu = raw_smp_processor_id();
	struct loaded_vmcs *v;

	list_for_each_entry(v, &per_cpu(loaded_vmcss_on_cpu, cpu),
			    loaded_vmcss_on_cpu_link)
		vmcs_clear(v->vmcs);
}
#endif /* CONFIG_KEXEC_CORE */

static void __loaded_vmcs_clear(void *arg)
{
	struct loaded_vmcs *loaded_vmcs = arg;
	int cpu = raw_smp_processor_id();

	if (loaded_vmcs->cpu != cpu)
		return; /* vcpu migration can race with cpu offline */
	if (per_cpu(current_vmcs, cpu) == loaded_vmcs->vmcs)
		per_cpu(current_vmcs, cpu) = NULL;

	vmcs_clear(loaded_vmcs->vmcs);
	if (loaded_vmcs->shadow_vmcs && loaded_vmcs->launched)
		vmcs_clear(loaded_vmcs->shadow_vmcs);

	list_del(&loaded_vmcs->loaded_vmcss_on_cpu_link);

	/*
	 * Ensure all writes to loaded_vmcs, including deleting it from its
	 * current percpu list, complete before setting loaded_vmcs->vcpu to
	 * -1, otherwise a different cpu can see vcpu == -1 first and add
	 * loaded_vmcs to its percpu list before it's deleted from this cpu's
	 * list. Pairs with the smp_rmb() in vmx_vcpu_load_vmcs().
	 */
	smp_wmb();

	loaded_vmcs->cpu = -1;
	loaded_vmcs->launched = 0;
}

static void loaded_vmcs_clear(struct loaded_vmcs *loaded_vmcs)
{
	int cpu = loaded_vmcs->cpu;

	if (cpu != -1)
		smp_call_function_single(cpu,
			 __loaded_vmcs_clear, loaded_vmcs, 1);
}

static inline bool vpid_sync_vcpu_addr(int vpid, gva_t addr)
{
	if (vpid == 0)
		return true;

	if (cpu_has_vmx_invvpid_individual_addr()) {
		__invvpid(VMX_VPID_EXTENT_INDIVIDUAL_ADDR, vpid, addr);
		return true;
	}

	return false;
}

static inline void vpid_sync_vcpu_single(int vpid)
{
	if (vpid == 0)
		return;

	if (cpu_has_vmx_invvpid_single())
		__invvpid(VMX_VPID_EXTENT_SINGLE_CONTEXT, vpid, 0);
}

static inline void vpid_sync_vcpu_global(void)
{
	if (cpu_has_vmx_invvpid_global())
		__invvpid(VMX_VPID_EXTENT_ALL_CONTEXT, 0, 0);
}

static inline void vpid_sync_context(int vpid)
{
	if (cpu_has_vmx_invvpid_single())
		vpid_sync_vcpu_single(vpid);
	else
		vpid_sync_vcpu_global();
}

static inline void ept_sync_global(void)
{
	__invept(VMX_EPT_EXTENT_GLOBAL, 0, 0);
}

static inline void ept_sync_context(u64 eptp)
{
	if (cpu_has_vmx_invept_context())
		__invept(VMX_EPT_EXTENT_CONTEXT, eptp, 0);
	else
		ept_sync_global();
}

static __always_inline void vmcs_check16(unsigned long field)
{
        BUILD_BUG_ON_MSG(__builtin_constant_p(field) && ((field) & 0x6001) == 0x2000,
			 "16-bit accessor invalid for 64-bit field");
        BUILD_BUG_ON_MSG(__builtin_constant_p(field) && ((field) & 0x6001) == 0x2001,
			 "16-bit accessor invalid for 64-bit high field");
        BUILD_BUG_ON_MSG(__builtin_constant_p(field) && ((field) & 0x6000) == 0x4000,
			 "16-bit accessor invalid for 32-bit high field");
        BUILD_BUG_ON_MSG(__builtin_constant_p(field) && ((field) & 0x6000) == 0x6000,
			 "16-bit accessor invalid for natural width field");
}

static __always_inline void vmcs_check32(unsigned long field)
{
        BUILD_BUG_ON_MSG(__builtin_constant_p(field) && ((field) & 0x6000) == 0,
			 "32-bit accessor invalid for 16-bit field");
        BUILD_BUG_ON_MSG(__builtin_constant_p(field) && ((field) & 0x6000) == 0x6000,
			 "32-bit accessor invalid for natural width field");
}

static __always_inline void vmcs_check64(unsigned long field)
{
        BUILD_BUG_ON_MSG(__builtin_constant_p(field) && ((field) & 0x6000) == 0,
			 "64-bit accessor invalid for 16-bit field");
        BUILD_BUG_ON_MSG(__builtin_constant_p(field) && ((field) & 0x6001) == 0x2001,
			 "64-bit accessor invalid for 64-bit high field");
        BUILD_BUG_ON_MSG(__builtin_constant_p(field) && ((field) & 0x6000) == 0x4000,
			 "64-bit accessor invalid for 32-bit field");
        BUILD_BUG_ON_MSG(__builtin_constant_p(field) && ((field) & 0x6000) == 0x6000,
			 "64-bit accessor invalid for natural width field");
}

static __always_inline void vmcs_checkl(unsigned long field)
{
        BUILD_BUG_ON_MSG(__builtin_constant_p(field) && ((field) & 0x6000) == 0,
			 "Natural width accessor invalid for 16-bit field");
        BUILD_BUG_ON_MSG(__builtin_constant_p(field) && ((field) & 0x6001) == 0x2000,
			 "Natural width accessor invalid for 64-bit field");
        BUILD_BUG_ON_MSG(__builtin_constant_p(field) && ((field) & 0x6001) == 0x2001,
			 "Natural width accessor invalid for 64-bit high field");
        BUILD_BUG_ON_MSG(__builtin_constant_p(field) && ((field) & 0x6000) == 0x4000,
			 "Natural width accessor invalid for 32-bit field");
}

static __always_inline unsigned long __vmcs_readl(unsigned long field)
{
	unsigned long value;

	asm volatile (__ex_clear(ASM_VMX_VMREAD_RDX_RAX, "%0")
		      : "=a"(value) : "d"(field) : "cc");
	return value;
}

static __always_inline u16 vmcs_read16(unsigned long field)
{
	vmcs_check16(field);
	if (static_branch_unlikely(&enable_evmcs))
		return evmcs_read16(field);
	return __vmcs_readl(field);
}

static __always_inline u32 vmcs_read32(unsigned long field)
{
	vmcs_check32(field);
	if (static_branch_unlikely(&enable_evmcs))
		return evmcs_read32(field);
	return __vmcs_readl(field);
}

static __always_inline u64 vmcs_read64(unsigned long field)
{
	vmcs_check64(field);
	if (static_branch_unlikely(&enable_evmcs))
		return evmcs_read64(field);
#ifdef CONFIG_X86_64
	return __vmcs_readl(field);
#else
	return __vmcs_readl(field) | ((u64)__vmcs_readl(field+1) << 32);
#endif
}

static __always_inline unsigned long vmcs_readl(unsigned long field)
{
	vmcs_checkl(field);
	if (static_branch_unlikely(&enable_evmcs))
		return evmcs_read64(field);
	return __vmcs_readl(field);
}

static noinline void vmwrite_error(unsigned long field, unsigned long value)
{
	printk(KERN_ERR "vmwrite error: reg %lx value %lx (err %d)\n",
	       field, value, vmcs_read32(VM_INSTRUCTION_ERROR));
	dump_stack();
}

static __always_inline void __vmcs_writel(unsigned long field, unsigned long value)
{
	bool error;

	asm volatile (__ex(ASM_VMX_VMWRITE_RAX_RDX) CC_SET(na)
		      : CC_OUT(na) (error) : "a"(value), "d"(field));
	if (unlikely(error))
		vmwrite_error(field, value);
}

static __always_inline void vmcs_write16(unsigned long field, u16 value)
{
	vmcs_check16(field);
	if (static_branch_unlikely(&enable_evmcs))
		return evmcs_write16(field, value);

	__vmcs_writel(field, value);
}

static __always_inline void vmcs_write32(unsigned long field, u32 value)
{
	vmcs_check32(field);
	if (static_branch_unlikely(&enable_evmcs))
		return evmcs_write32(field, value);

	__vmcs_writel(field, value);
}

static __always_inline void vmcs_write64(unsigned long field, u64 value)
{
	vmcs_check64(field);
	if (static_branch_unlikely(&enable_evmcs))
		return evmcs_write64(field, value);

	__vmcs_writel(field, value);
#ifndef CONFIG_X86_64
	asm volatile ("");
	__vmcs_writel(field+1, value >> 32);
#endif
}

static __always_inline void vmcs_writel(unsigned long field, unsigned long value)
{
	vmcs_checkl(field);
	if (static_branch_unlikely(&enable_evmcs))
		return evmcs_write64(field, value);

	__vmcs_writel(field, value);
}

static __always_inline void vmcs_clear_bits(unsigned long field, u32 mask)
{
        BUILD_BUG_ON_MSG(__builtin_constant_p(field) && ((field) & 0x6000) == 0x2000,
			 "vmcs_clear_bits does not support 64-bit fields");
	if (static_branch_unlikely(&enable_evmcs))
		return evmcs_write32(field, evmcs_read32(field) & ~mask);

	__vmcs_writel(field, __vmcs_readl(field) & ~mask);
}

static __always_inline void vmcs_set_bits(unsigned long field, u32 mask)
{
        BUILD_BUG_ON_MSG(__builtin_constant_p(field) && ((field) & 0x6000) == 0x2000,
			 "vmcs_set_bits does not support 64-bit fields");
	if (static_branch_unlikely(&enable_evmcs))
		return evmcs_write32(field, evmcs_read32(field) | mask);

	__vmcs_writel(field, __vmcs_readl(field) | mask);
}

static inline void vm_entry_controls_reset_shadow(struct vcpu_vmx *vmx)
{
	vmx->vm_entry_controls_shadow = vmcs_read32(VM_ENTRY_CONTROLS);
}

static inline void vm_entry_controls_init(struct vcpu_vmx *vmx, u32 val)
{
	vmcs_write32(VM_ENTRY_CONTROLS, val);
	vmx->vm_entry_controls_shadow = val;
}

static inline void vm_entry_controls_set(struct vcpu_vmx *vmx, u32 val)
{
	if (vmx->vm_entry_controls_shadow != val)
		vm_entry_controls_init(vmx, val);
}

static inline u32 vm_entry_controls_get(struct vcpu_vmx *vmx)
{
	return vmx->vm_entry_controls_shadow;
}


static inline void vm_entry_controls_setbit(struct vcpu_vmx *vmx, u32 val)
{
	vm_entry_controls_set(vmx, vm_entry_controls_get(vmx) | val);
}

static inline void vm_entry_controls_clearbit(struct vcpu_vmx *vmx, u32 val)
{
	vm_entry_controls_set(vmx, vm_entry_controls_get(vmx) & ~val);
}

static inline void vm_exit_controls_reset_shadow(struct vcpu_vmx *vmx)
{
	vmx->vm_exit_controls_shadow = vmcs_read32(VM_EXIT_CONTROLS);
}

static inline void vm_exit_controls_init(struct vcpu_vmx *vmx, u32 val)
{
	vmcs_write32(VM_EXIT_CONTROLS, val);
	vmx->vm_exit_controls_shadow = val;
}

static inline void vm_exit_controls_set(struct vcpu_vmx *vmx, u32 val)
{
	if (vmx->vm_exit_controls_shadow != val)
		vm_exit_controls_init(vmx, val);
}

static inline u32 vm_exit_controls_get(struct vcpu_vmx *vmx)
{
	return vmx->vm_exit_controls_shadow;
}


static inline void vm_exit_controls_setbit(struct vcpu_vmx *vmx, u32 val)
{
	vm_exit_controls_set(vmx, vm_exit_controls_get(vmx) | val);
}

static inline void vm_exit_controls_clearbit(struct vcpu_vmx *vmx, u32 val)
{
	vm_exit_controls_set(vmx, vm_exit_controls_get(vmx) & ~val);
}

static void vmx_segment_cache_clear(struct vcpu_vmx *vmx)
{
	vmx->segment_cache.bitmask = 0;
}

static bool vmx_segment_cache_test_set(struct vcpu_vmx *vmx, unsigned seg,
				       unsigned field)
{
	bool ret;
	u32 mask = 1 << (seg * SEG_FIELD_NR + field);

	if (!(vmx->vcpu.arch.regs_avail & (1 << VCPU_EXREG_SEGMENTS))) {
		vmx->vcpu.arch.regs_avail |= (1 << VCPU_EXREG_SEGMENTS);
		vmx->segment_cache.bitmask = 0;
	}
	ret = vmx->segment_cache.bitmask & mask;
	vmx->segment_cache.bitmask |= mask;
	return ret;
}

static u16 vmx_read_guest_seg_selector(struct vcpu_vmx *vmx, unsigned seg)
{
	u16 *p = &vmx->segment_cache.seg[seg].selector;

	if (!vmx_segment_cache_test_set(vmx, seg, SEG_FIELD_SEL))
		*p = vmcs_read16(kvm_vmx_segment_fields[seg].selector);
	return *p;
}

static ulong vmx_read_guest_seg_base(struct vcpu_vmx *vmx, unsigned seg)
{
	ulong *p = &vmx->segment_cache.seg[seg].base;

	if (!vmx_segment_cache_test_set(vmx, seg, SEG_FIELD_BASE))
		*p = vmcs_readl(kvm_vmx_segment_fields[seg].base);
	return *p;
}

static u32 vmx_read_guest_seg_limit(struct vcpu_vmx *vmx, unsigned seg)
{
	u32 *p = &vmx->segment_cache.seg[seg].limit;

	if (!vmx_segment_cache_test_set(vmx, seg, SEG_FIELD_LIMIT))
		*p = vmcs_read32(kvm_vmx_segment_fields[seg].limit);
	return *p;
}

static u32 vmx_read_guest_seg_ar(struct vcpu_vmx *vmx, unsigned seg)
{
	u32 *p = &vmx->segment_cache.seg[seg].ar;

	if (!vmx_segment_cache_test_set(vmx, seg, SEG_FIELD_AR))
		*p = vmcs_read32(kvm_vmx_segment_fields[seg].ar_bytes);
	return *p;
}

static void update_exception_bitmap(struct kvm_vcpu *vcpu)
{
	u32 eb;

	eb = (1u << PF_VECTOR) | (1u << UD_VECTOR) | (1u << MC_VECTOR) |
	     (1u << DB_VECTOR) | (1u << AC_VECTOR);
	/*
	 * Guest access to VMware backdoor ports could legitimately
	 * trigger #GP because of TSS I/O permission bitmap.
	 * We intercept those #GP and allow access to them anyway
	 * as VMware does.
	 */
	if (enable_vmware_backdoor)
		eb |= (1u << GP_VECTOR);
	if ((vcpu->guest_debug &
	     (KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_SW_BP)) ==
	    (KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_SW_BP))
		eb |= 1u << BP_VECTOR;
	if (to_vmx(vcpu)->rmode.vm86_active)
		eb = ~0;
	if (enable_ept)
		eb &= ~(1u << PF_VECTOR); /* bypass_guest_pf = 0 */

	/* When we are running a nested L2 guest and L1 specified for it a
	 * certain exception bitmap, we must trap the same exceptions and pass
	 * them to L1. When running L2, we will only handle the exceptions
	 * specified above if L1 did not want them.
	 */
	if (is_guest_mode(vcpu))
		eb |= get_vmcs12(vcpu)->exception_bitmap;

	vmcs_write32(EXCEPTION_BITMAP, eb);
}

/*
 * Check if MSR is intercepted for currently loaded MSR bitmap.
 */
static bool msr_write_intercepted(struct kvm_vcpu *vcpu, u32 msr)
{
	unsigned long *msr_bitmap;
	int f = sizeof(unsigned long);

	if (!cpu_has_vmx_msr_bitmap())
		return true;

	msr_bitmap = to_vmx(vcpu)->loaded_vmcs->msr_bitmap;

	if (msr <= 0x1fff) {
		return !!test_bit(msr, msr_bitmap + 0x800 / f);
	} else if ((msr >= 0xc0000000) && (msr <= 0xc0001fff)) {
		msr &= 0x1fff;
		return !!test_bit(msr, msr_bitmap + 0xc00 / f);
	}

	return true;
}

/*
 * Check if MSR is intercepted for L01 MSR bitmap.
 */
static bool msr_write_intercepted_l01(struct kvm_vcpu *vcpu, u32 msr)
{
	unsigned long *msr_bitmap;
	int f = sizeof(unsigned long);

	if (!cpu_has_vmx_msr_bitmap())
		return true;

	msr_bitmap = to_vmx(vcpu)->vmcs01.msr_bitmap;

	if (msr <= 0x1fff) {
		return !!test_bit(msr, msr_bitmap + 0x800 / f);
	} else if ((msr >= 0xc0000000) && (msr <= 0xc0001fff)) {
		msr &= 0x1fff;
		return !!test_bit(msr, msr_bitmap + 0xc00 / f);
	}

	return true;
}

static void clear_atomic_switch_msr_special(struct vcpu_vmx *vmx,
		unsigned long entry, unsigned long exit)
{
	vm_entry_controls_clearbit(vmx, entry);
	vm_exit_controls_clearbit(vmx, exit);
}

static int find_msr(struct vmx_msrs *m, unsigned int msr)
{
	unsigned int i;

	for (i = 0; i < m->nr; ++i) {
		if (m->val[i].index == msr)
			return i;
	}
	return -ENOENT;
}

static void clear_atomic_switch_msr(struct vcpu_vmx *vmx, unsigned msr)
{
	int i;
	struct msr_autoload *m = &vmx->msr_autoload;

	switch (msr) {
	case MSR_EFER:
		if (cpu_has_load_ia32_efer) {
			clear_atomic_switch_msr_special(vmx,
					VM_ENTRY_LOAD_IA32_EFER,
					VM_EXIT_LOAD_IA32_EFER);
			return;
		}
		break;
	case MSR_CORE_PERF_GLOBAL_CTRL:
		if (cpu_has_load_perf_global_ctrl) {
			clear_atomic_switch_msr_special(vmx,
					VM_ENTRY_LOAD_IA32_PERF_GLOBAL_CTRL,
					VM_EXIT_LOAD_IA32_PERF_GLOBAL_CTRL);
			return;
		}
		break;
	}
	i = find_msr(&m->guest, msr);
	if (i < 0)
		goto skip_guest;
	--m->guest.nr;
	m->guest.val[i] = m->guest.val[m->guest.nr];
	vmcs_write32(VM_ENTRY_MSR_LOAD_COUNT, m->guest.nr);

skip_guest:
	i = find_msr(&m->host, msr);
	if (i < 0)
		return;

	--m->host.nr;
	m->host.val[i] = m->host.val[m->host.nr];
	vmcs_write32(VM_EXIT_MSR_LOAD_COUNT, m->host.nr);
}

static void add_atomic_switch_msr_special(struct vcpu_vmx *vmx,
		unsigned long entry, unsigned long exit,
		unsigned long guest_val_vmcs, unsigned long host_val_vmcs,
		u64 guest_val, u64 host_val)
{
	vmcs_write64(guest_val_vmcs, guest_val);
	vmcs_write64(host_val_vmcs, host_val);
	vm_entry_controls_setbit(vmx, entry);
	vm_exit_controls_setbit(vmx, exit);
}

static void add_atomic_switch_msr(struct vcpu_vmx *vmx, unsigned msr,
				  u64 guest_val, u64 host_val, bool entry_only)
{
	int i, j = 0;
	struct msr_autoload *m = &vmx->msr_autoload;

	switch (msr) {
	case MSR_EFER:
		if (cpu_has_load_ia32_efer) {
			add_atomic_switch_msr_special(vmx,
					VM_ENTRY_LOAD_IA32_EFER,
					VM_EXIT_LOAD_IA32_EFER,
					GUEST_IA32_EFER,
					HOST_IA32_EFER,
					guest_val, host_val);
			return;
		}
		break;
	case MSR_CORE_PERF_GLOBAL_CTRL:
		if (cpu_has_load_perf_global_ctrl) {
			add_atomic_switch_msr_special(vmx,
					VM_ENTRY_LOAD_IA32_PERF_GLOBAL_CTRL,
					VM_EXIT_LOAD_IA32_PERF_GLOBAL_CTRL,
					GUEST_IA32_PERF_GLOBAL_CTRL,
					HOST_IA32_PERF_GLOBAL_CTRL,
					guest_val, host_val);
			return;
		}
		break;
	case MSR_IA32_PEBS_ENABLE:
		/* PEBS needs a quiescent period after being disabled (to write
		 * a record).  Disabling PEBS through VMX MSR swapping doesn't
		 * provide that period, so a CPU could write host's record into
		 * guest's memory.
		 */
		wrmsrl(MSR_IA32_PEBS_ENABLE, 0);
	}

	i = find_msr(&m->guest, msr);
	if (!entry_only)
		j = find_msr(&m->host, msr);

	if ((i < 0 && m->guest.nr == NR_AUTOLOAD_MSRS) ||
		(j < 0 &&  m->host.nr == NR_AUTOLOAD_MSRS)) {
		printk_once(KERN_WARNING "Not enough msr switch entries. "
				"Can't add msr %x\n", msr);
		return;
	}
	if (i < 0) {
		i = m->guest.nr++;
		vmcs_write32(VM_ENTRY_MSR_LOAD_COUNT, m->guest.nr);
	}
	m->guest.val[i].index = msr;
	m->guest.val[i].value = guest_val;

	if (entry_only)
		return;

	if (j < 0) {
		j = m->host.nr++;
		vmcs_write32(VM_EXIT_MSR_LOAD_COUNT, m->host.nr);
	}
	m->host.val[j].index = msr;
	m->host.val[j].value = host_val;
}

static bool update_transition_efer(struct vcpu_vmx *vmx, int efer_offset)
{
	u64 guest_efer = vmx->vcpu.arch.efer;
	u64 ignore_bits = 0;

	/* Shadow paging assumes NX to be available.  */
	if (!enable_ept)
		guest_efer |= EFER_NX;

	/*
	 * LMA and LME handled by hardware; SCE meaningless outside long mode.
	 */
	ignore_bits |= EFER_SCE;
#ifdef CONFIG_X86_64
	ignore_bits |= EFER_LMA | EFER_LME;
	/* SCE is meaningful only in long mode on Intel */
	if (guest_efer & EFER_LMA)
		ignore_bits &= ~(u64)EFER_SCE;
#endif

	clear_atomic_switch_msr(vmx, MSR_EFER);

	/*
	 * On EPT, we can't emulate NX, so we must switch EFER atomically.
	 * On CPUs that support "load IA32_EFER", always switch EFER
	 * atomically, since it's faster than switching it manually.
	 */
	if (cpu_has_load_ia32_efer ||
	    (enable_ept && ((vmx->vcpu.arch.efer ^ host_efer) & EFER_NX))) {
		if (!(guest_efer & EFER_LMA))
			guest_efer &= ~EFER_LME;
		if (guest_efer != host_efer)
			add_atomic_switch_msr(vmx, MSR_EFER,
					      guest_efer, host_efer, false);
		return false;
	} else {
		guest_efer &= ~ignore_bits;
		guest_efer |= host_efer & ignore_bits;

		vmx->guest_msrs[efer_offset].data = guest_efer;
		vmx->guest_msrs[efer_offset].mask = ~ignore_bits;

		return true;
	}
}

#ifdef CONFIG_X86_32
/*
 * On 32-bit kernels, VM exits still load the FS and GS bases from the
 * VMCS rather than the segment table.  KVM uses this helper to figure
 * out the current bases to poke them into the VMCS before entry.
 */
static unsigned long segment_base(u16 selector)
{
	struct desc_struct *table;
	unsigned long v;

	if (!(selector & ~SEGMENT_RPL_MASK))
		return 0;

	table = get_current_gdt_ro();

	if ((selector & SEGMENT_TI_MASK) == SEGMENT_LDT) {
		u16 ldt_selector = kvm_read_ldt();

		if (!(ldt_selector & ~SEGMENT_RPL_MASK))
			return 0;

		table = (struct desc_struct *)segment_base(ldt_selector);
	}
	v = get_desc_base(&table[selector >> 3]);
	return v;
}
#endif

static void vmx_prepare_switch_to_guest(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	struct vmcs_host_state *host_state;
#ifdef CONFIG_X86_64
	int cpu = raw_smp_processor_id();
#endif
	unsigned long fs_base, gs_base;
	u16 fs_sel, gs_sel;
	int i;

	vmx->req_immediate_exit = false;

	/*
	 * Note that guest MSRs to be saved/restored can also be changed
	 * when guest state is loaded. This happens when guest transitions
	 * to/from long-mode by setting MSR_EFER.LMA.
	 */
	if (!vmx->loaded_cpu_state || vmx->guest_msrs_dirty) {
		vmx->guest_msrs_dirty = false;
		for (i = 0; i < vmx->save_nmsrs; ++i)
			kvm_set_shared_msr(vmx->guest_msrs[i].index,
					   vmx->guest_msrs[i].data,
					   vmx->guest_msrs[i].mask);

	}

	if (vmx->loaded_cpu_state)
		return;

	vmx->loaded_cpu_state = vmx->loaded_vmcs;
	host_state = &vmx->loaded_cpu_state->host_state;

	/*
	 * Set host fs and gs selectors.  Unfortunately, 22.2.3 does not
	 * allow segment selectors with cpl > 0 or ti == 1.
	 */
	host_state->ldt_sel = kvm_read_ldt();

#ifdef CONFIG_X86_64
	savesegment(ds, host_state->ds_sel);
	savesegment(es, host_state->es_sel);

	gs_base = cpu_kernelmode_gs_base(cpu);
	if (likely(is_64bit_mm(current->mm))) {
		save_fsgs_for_kvm();
		fs_sel = current->thread.fsindex;
		gs_sel = current->thread.gsindex;
		fs_base = current->thread.fsbase;
		vmx->msr_host_kernel_gs_base = current->thread.gsbase;
	} else {
		savesegment(fs, fs_sel);
		savesegment(gs, gs_sel);
		fs_base = read_msr(MSR_FS_BASE);
		vmx->msr_host_kernel_gs_base = read_msr(MSR_KERNEL_GS_BASE);
	}

	wrmsrl(MSR_KERNEL_GS_BASE, vmx->msr_guest_kernel_gs_base);
#else
	savesegment(fs, fs_sel);
	savesegment(gs, gs_sel);
	fs_base = segment_base(fs_sel);
	gs_base = segment_base(gs_sel);
#endif

	if (unlikely(fs_sel != host_state->fs_sel)) {
		if (!(fs_sel & 7))
			vmcs_write16(HOST_FS_SELECTOR, fs_sel);
		else
			vmcs_write16(HOST_FS_SELECTOR, 0);
		host_state->fs_sel = fs_sel;
	}
	if (unlikely(gs_sel != host_state->gs_sel)) {
		if (!(gs_sel & 7))
			vmcs_write16(HOST_GS_SELECTOR, gs_sel);
		else
			vmcs_write16(HOST_GS_SELECTOR, 0);
		host_state->gs_sel = gs_sel;
	}
	if (unlikely(fs_base != host_state->fs_base)) {
		vmcs_writel(HOST_FS_BASE, fs_base);
		host_state->fs_base = fs_base;
	}
	if (unlikely(gs_base != host_state->gs_base)) {
		vmcs_writel(HOST_GS_BASE, gs_base);
		host_state->gs_base = gs_base;
	}
}

static void vmx_prepare_switch_to_host(struct vcpu_vmx *vmx)
{
	struct vmcs_host_state *host_state;

	if (!vmx->loaded_cpu_state)
		return;

	WARN_ON_ONCE(vmx->loaded_cpu_state != vmx->loaded_vmcs);
	host_state = &vmx->loaded_cpu_state->host_state;

	++vmx->vcpu.stat.host_state_reload;
	vmx->loaded_cpu_state = NULL;

#ifdef CONFIG_X86_64
	rdmsrl(MSR_KERNEL_GS_BASE, vmx->msr_guest_kernel_gs_base);
#endif
	if (host_state->ldt_sel || (host_state->gs_sel & 7)) {
		kvm_load_ldt(host_state->ldt_sel);
#ifdef CONFIG_X86_64
		load_gs_index(host_state->gs_sel);
#else
		loadsegment(gs, host_state->gs_sel);
#endif
	}
	if (host_state->fs_sel & 7)
		loadsegment(fs, host_state->fs_sel);
#ifdef CONFIG_X86_64
	if (unlikely(host_state->ds_sel | host_state->es_sel)) {
		loadsegment(ds, host_state->ds_sel);
		loadsegment(es, host_state->es_sel);
	}
#endif
	invalidate_tss_limit();
#ifdef CONFIG_X86_64
	wrmsrl(MSR_KERNEL_GS_BASE, vmx->msr_host_kernel_gs_base);
#endif
	load_fixmap_gdt(raw_smp_processor_id());
}

#ifdef CONFIG_X86_64
static u64 vmx_read_guest_kernel_gs_base(struct vcpu_vmx *vmx)
{
	preempt_disable();
	if (vmx->loaded_cpu_state)
		rdmsrl(MSR_KERNEL_GS_BASE, vmx->msr_guest_kernel_gs_base);
	preempt_enable();
	return vmx->msr_guest_kernel_gs_base;
}

static void vmx_write_guest_kernel_gs_base(struct vcpu_vmx *vmx, u64 data)
{
	preempt_disable();
	if (vmx->loaded_cpu_state)
		wrmsrl(MSR_KERNEL_GS_BASE, data);
	preempt_enable();
	vmx->msr_guest_kernel_gs_base = data;
}
#endif

static void vmx_vcpu_pi_load(struct kvm_vcpu *vcpu, int cpu)
{
	struct pi_desc *pi_desc = vcpu_to_pi_desc(vcpu);
	struct pi_desc old, new;
	unsigned int dest;

	/*
	 * In case of hot-plug or hot-unplug, we may have to undo
	 * vmx_vcpu_pi_put even if there is no assigned device.  And we
	 * always keep PI.NDST up to date for simplicity: it makes the
	 * code easier, and CPU migration is not a fast path.
	 */
	if (!pi_test_sn(pi_desc) && vcpu->cpu == cpu)
		return;

	/*
	 * First handle the simple case where no cmpxchg is necessary; just
	 * allow posting non-urgent interrupts.
	 *
	 * If the 'nv' field is POSTED_INTR_WAKEUP_VECTOR, do not change
	 * PI.NDST: pi_post_block will do it for us and the wakeup_handler
	 * expects the VCPU to be on the blocked_vcpu_list that matches
	 * PI.NDST.
	 */
	if (pi_desc->nv == POSTED_INTR_WAKEUP_VECTOR ||
	    vcpu->cpu == cpu) {
		pi_clear_sn(pi_desc);
		return;
	}

	/* The full case.  */
	do {
		old.control = new.control = pi_desc->control;

		dest = cpu_physical_id(cpu);

		if (x2apic_enabled())
			new.ndst = dest;
		else
			new.ndst = (dest << 8) & 0xFF00;

		new.sn = 0;
	} while (cmpxchg64(&pi_desc->control, old.control,
			   new.control) != old.control);
}

static void decache_tsc_multiplier(struct vcpu_vmx *vmx)
{
	vmx->current_tsc_ratio = vmx->vcpu.arch.tsc_scaling_ratio;
	vmcs_write64(TSC_MULTIPLIER, vmx->current_tsc_ratio);
}

/*
 * Switches to specified vcpu, until a matching vcpu_put(), but assumes
 * vcpu mutex is already taken.
 */
static void vmx_vcpu_load(struct kvm_vcpu *vcpu, int cpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	bool already_loaded = vmx->loaded_vmcs->cpu == cpu;

	if (!already_loaded) {
		loaded_vmcs_clear(vmx->loaded_vmcs);
		local_irq_disable();

		/*
		 * Ensure loaded_vmcs->cpu is read before adding loaded_vmcs to
		 * this cpu's percpu list, otherwise it may not yet be deleted
		 * from its previous cpu's percpu list.  Pairs with the
		 * smb_wmb() in __loaded_vmcs_clear().
		 */
		smp_rmb();

		list_add(&vmx->loaded_vmcs->loaded_vmcss_on_cpu_link,
			 &per_cpu(loaded_vmcss_on_cpu, cpu));
		local_irq_enable();
	}

	if (per_cpu(current_vmcs, cpu) != vmx->loaded_vmcs->vmcs) {
		per_cpu(current_vmcs, cpu) = vmx->loaded_vmcs->vmcs;
		vmcs_load(vmx->loaded_vmcs->vmcs);
		indirect_branch_prediction_barrier();
	}

	if (!already_loaded) {
		void *gdt = get_current_gdt_ro();
		unsigned long sysenter_esp;

		kvm_make_request(KVM_REQ_TLB_FLUSH, vcpu);

		/*
		 * Linux uses per-cpu TSS and GDT, so set these when switching
		 * processors.  See 22.2.4.
		 */
		vmcs_writel(HOST_TR_BASE,
			    (unsigned long)&get_cpu_entry_area(cpu)->tss.x86_tss);
		vmcs_writel(HOST_GDTR_BASE, (unsigned long)gdt);   /* 22.2.4 */

		/*
		 * VM exits change the host TR limit to 0x67 after a VM
		 * exit.  This is okay, since 0x67 covers everything except
		 * the IO bitmap and have have code to handle the IO bitmap
		 * being lost after a VM exit.
		 */
		BUILD_BUG_ON(IO_BITMAP_OFFSET - 1 != 0x67);

		rdmsrl(MSR_IA32_SYSENTER_ESP, sysenter_esp);
		vmcs_writel(HOST_IA32_SYSENTER_ESP, sysenter_esp); /* 22.2.3 */

		vmx->loaded_vmcs->cpu = cpu;
	}

	/* Setup TSC multiplier */
	if (kvm_has_tsc_control &&
	    vmx->current_tsc_ratio != vcpu->arch.tsc_scaling_ratio)
		decache_tsc_multiplier(vmx);

	vmx_vcpu_pi_load(vcpu, cpu);
	vmx->host_pkru = read_pkru();
	vmx->host_debugctlmsr = get_debugctlmsr();
}

static void vmx_vcpu_pi_put(struct kvm_vcpu *vcpu)
{
	struct pi_desc *pi_desc = vcpu_to_pi_desc(vcpu);

	if (!kvm_arch_has_assigned_device(vcpu->kvm) ||
		!irq_remapping_cap(IRQ_POSTING_CAP)  ||
		!kvm_vcpu_apicv_active(vcpu))
		return;

	/* Set SN when the vCPU is preempted */
	if (vcpu->preempted)
		pi_set_sn(pi_desc);
}

static void vmx_vcpu_put(struct kvm_vcpu *vcpu)
{
	vmx_vcpu_pi_put(vcpu);

	vmx_prepare_switch_to_host(to_vmx(vcpu));
}

static bool emulation_required(struct kvm_vcpu *vcpu)
{
	return emulate_invalid_guest_state && !guest_state_valid(vcpu);
}

static void vmx_decache_cr0_guest_bits(struct kvm_vcpu *vcpu);

/*
 * Return the cr0 value that a nested guest would read. This is a combination
 * of the real cr0 used to run the guest (guest_cr0), and the bits shadowed by
 * its hypervisor (cr0_read_shadow).
 */
static inline unsigned long nested_read_cr0(struct vmcs12 *fields)
{
	return (fields->guest_cr0 & ~fields->cr0_guest_host_mask) |
		(fields->cr0_read_shadow & fields->cr0_guest_host_mask);
}
static inline unsigned long nested_read_cr4(struct vmcs12 *fields)
{
	return (fields->guest_cr4 & ~fields->cr4_guest_host_mask) |
		(fields->cr4_read_shadow & fields->cr4_guest_host_mask);
}

static unsigned long vmx_get_rflags(struct kvm_vcpu *vcpu)
{
	unsigned long rflags, save_rflags;

	if (!test_bit(VCPU_EXREG_RFLAGS, (ulong *)&vcpu->arch.regs_avail)) {
		__set_bit(VCPU_EXREG_RFLAGS, (ulong *)&vcpu->arch.regs_avail);
		rflags = vmcs_readl(GUEST_RFLAGS);
		if (to_vmx(vcpu)->rmode.vm86_active) {
			rflags &= RMODE_GUEST_OWNED_EFLAGS_BITS;
			save_rflags = to_vmx(vcpu)->rmode.save_rflags;
			rflags |= save_rflags & ~RMODE_GUEST_OWNED_EFLAGS_BITS;
		}
		to_vmx(vcpu)->rflags = rflags;
	}
	return to_vmx(vcpu)->rflags;
}

static void vmx_set_rflags(struct kvm_vcpu *vcpu, unsigned long rflags)
{
	unsigned long old_rflags = vmx_get_rflags(vcpu);

	__set_bit(VCPU_EXREG_RFLAGS, (ulong *)&vcpu->arch.regs_avail);
	to_vmx(vcpu)->rflags = rflags;
	if (to_vmx(vcpu)->rmode.vm86_active) {
		to_vmx(vcpu)->rmode.save_rflags = rflags;
		rflags |= X86_EFLAGS_IOPL | X86_EFLAGS_VM;
	}
	vmcs_writel(GUEST_RFLAGS, rflags);

	if ((old_rflags ^ to_vmx(vcpu)->rflags) & X86_EFLAGS_VM)
		to_vmx(vcpu)->emulation_required = emulation_required(vcpu);
}

static u32 vmx_get_interrupt_shadow(struct kvm_vcpu *vcpu)
{
	u32 interruptibility = vmcs_read32(GUEST_INTERRUPTIBILITY_INFO);
	int ret = 0;

	if (interruptibility & GUEST_INTR_STATE_STI)
		ret |= KVM_X86_SHADOW_INT_STI;
	if (interruptibility & GUEST_INTR_STATE_MOV_SS)
		ret |= KVM_X86_SHADOW_INT_MOV_SS;

	return ret;
}

static void vmx_set_interrupt_shadow(struct kvm_vcpu *vcpu, int mask)
{
	u32 interruptibility_old = vmcs_read32(GUEST_INTERRUPTIBILITY_INFO);
	u32 interruptibility = interruptibility_old;

	interruptibility &= ~(GUEST_INTR_STATE_STI | GUEST_INTR_STATE_MOV_SS);

	if (mask & KVM_X86_SHADOW_INT_MOV_SS)
		interruptibility |= GUEST_INTR_STATE_MOV_SS;
	else if (mask & KVM_X86_SHADOW_INT_STI)
		interruptibility |= GUEST_INTR_STATE_STI;

	if ((interruptibility != interruptibility_old))
		vmcs_write32(GUEST_INTERRUPTIBILITY_INFO, interruptibility);
}

static void skip_emulated_instruction(struct kvm_vcpu *vcpu)
{
	unsigned long rip;

	rip = kvm_rip_read(vcpu);
	rip += vmcs_read32(VM_EXIT_INSTRUCTION_LEN);
	kvm_rip_write(vcpu, rip);

	/* skipping an emulated instruction also counts */
	vmx_set_interrupt_shadow(vcpu, 0);
}

static void nested_vmx_inject_exception_vmexit(struct kvm_vcpu *vcpu,
					       unsigned long exit_qual)
{
	struct vmcs12 *vmcs12 = get_vmcs12(vcpu);
	unsigned int nr = vcpu->arch.exception.nr;
	u32 intr_info = nr | INTR_INFO_VALID_MASK;

	if (vcpu->arch.exception.has_error_code) {
		vmcs12->vm_exit_intr_error_code = vcpu->arch.exception.error_code;
		intr_info |= INTR_INFO_DELIVER_CODE_MASK;
	}

	if (kvm_exception_is_soft(nr))
		intr_info |= INTR_TYPE_SOFT_EXCEPTION;
	else
		intr_info |= INTR_TYPE_HARD_EXCEPTION;

	if (!(vmcs12->idt_vectoring_info_field & VECTORING_INFO_VALID_MASK) &&
	    vmx_get_nmi_mask(vcpu))
		intr_info |= INTR_INFO_UNBLOCK_NMI;

	nested_vmx_vmexit(vcpu, EXIT_REASON_EXCEPTION_NMI, intr_info, exit_qual);
}

/*
 * KVM wants to inject page-faults which it got to the guest. This function
 * checks whether in a nested guest, we need to inject them to L1 or L2.
 */
static int nested_vmx_check_exception(struct kvm_vcpu *vcpu, unsigned long *exit_qual)
{
	struct vmcs12 *vmcs12 = get_vmcs12(vcpu);
	unsigned int nr = vcpu->arch.exception.nr;

	if (nr == PF_VECTOR) {
		if (vcpu->arch.exception.nested_apf) {
			*exit_qual = vcpu->arch.apf.nested_apf_token;
			return 1;
		}
		/*
		 * FIXME: we must not write CR2 when L1 intercepts an L2 #PF exception.
		 * The fix is to add the ancillary datum (CR2 or DR6) to structs
		 * kvm_queued_exception and kvm_vcpu_events, so that CR2 and DR6
		 * can be written only when inject_pending_event runs.  This should be
		 * conditional on a new capability---if the capability is disabled,
		 * kvm_multiple_exception would write the ancillary information to
		 * CR2 or DR6, for backwards ABI-compatibility.
		 */
		if (nested_vmx_is_page_fault_vmexit(vmcs12,
						    vcpu->arch.exception.error_code)) {
			*exit_qual = vcpu->arch.cr2;
			return 1;
		}
	} else {
		if (vmcs12->exception_bitmap & (1u << nr)) {
			if (nr == DB_VECTOR) {
				*exit_qual = vcpu->arch.dr6;
				*exit_qual &= ~(DR6_FIXED_1 | DR6_BT);
				*exit_qual ^= DR6_RTM;
			} else {
				*exit_qual = 0;
			}
			return 1;
		}
	}

	return 0;
}

static void vmx_clear_hlt(struct kvm_vcpu *vcpu)
{
	/*
	 * Ensure that we clear the HLT state in the VMCS.  We don't need to
	 * explicitly skip the instruction because if the HLT state is set,
	 * then the instruction is already executing and RIP has already been
	 * advanced.
	 */
	if (kvm_hlt_in_guest(vcpu->kvm) &&
			vmcs_read32(GUEST_ACTIVITY_STATE) == GUEST_ACTIVITY_HLT)
		vmcs_write32(GUEST_ACTIVITY_STATE, GUEST_ACTIVITY_ACTIVE);
}

static void vmx_queue_exception(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	unsigned nr = vcpu->arch.exception.nr;
	bool has_error_code = vcpu->arch.exception.has_error_code;
	u32 error_code = vcpu->arch.exception.error_code;
	u32 intr_info = nr | INTR_INFO_VALID_MASK;

	if (has_error_code) {
		vmcs_write32(VM_ENTRY_EXCEPTION_ERROR_CODE, error_code);
		intr_info |= INTR_INFO_DELIVER_CODE_MASK;
	}

	if (vmx->rmode.vm86_active) {
		int inc_eip = 0;
		if (kvm_exception_is_soft(nr))
			inc_eip = vcpu->arch.event_exit_inst_len;
		if (kvm_inject_realmode_interrupt(vcpu, nr, inc_eip) != EMULATE_DONE)
			kvm_make_request(KVM_REQ_TRIPLE_FAULT, vcpu);
		return;
	}

	WARN_ON_ONCE(vmx->emulation_required);

	if (kvm_exception_is_soft(nr)) {
		vmcs_write32(VM_ENTRY_INSTRUCTION_LEN,
			     vmx->vcpu.arch.event_exit_inst_len);
		intr_info |= INTR_TYPE_SOFT_EXCEPTION;
	} else
		intr_info |= INTR_TYPE_HARD_EXCEPTION;

	vmcs_write32(VM_ENTRY_INTR_INFO_FIELD, intr_info);

	vmx_clear_hlt(vcpu);
}

static bool vmx_rdtscp_supported(void)
{
	return cpu_has_vmx_rdtscp();
}

static bool vmx_invpcid_supported(void)
{
	return cpu_has_vmx_invpcid();
}

/*
 * Swap MSR entry in host/guest MSR entry array.
 */
static void move_msr_up(struct vcpu_vmx *vmx, int from, int to)
{
	struct shared_msr_entry tmp;

	tmp = vmx->guest_msrs[to];
	vmx->guest_msrs[to] = vmx->guest_msrs[from];
	vmx->guest_msrs[from] = tmp;
}

/*
 * Set up the vmcs to automatically save and restore system
 * msrs.  Don't touch the 64-bit msrs if the guest is in legacy
 * mode, as fiddling with msrs is very expensive.
 */
static void setup_msrs(struct vcpu_vmx *vmx)
{
	int save_nmsrs, index;

	save_nmsrs = 0;
#ifdef CONFIG_X86_64
	if (is_long_mode(&vmx->vcpu)) {
		index = __find_msr_index(vmx, MSR_SYSCALL_MASK);
		if (index >= 0)
			move_msr_up(vmx, index, save_nmsrs++);
		index = __find_msr_index(vmx, MSR_LSTAR);
		if (index >= 0)
			move_msr_up(vmx, index, save_nmsrs++);
		index = __find_msr_index(vmx, MSR_CSTAR);
		if (index >= 0)
			move_msr_up(vmx, index, save_nmsrs++);
		/*
		 * MSR_STAR is only needed on long mode guests, and only
		 * if efer.sce is enabled.
		 */
		index = __find_msr_index(vmx, MSR_STAR);
		if ((index >= 0) && (vmx->vcpu.arch.efer & EFER_SCE))
			move_msr_up(vmx, index, save_nmsrs++);
	}
#endif
	index = __find_msr_index(vmx, MSR_EFER);
	if (index >= 0 && update_transition_efer(vmx, index))
		move_msr_up(vmx, index, save_nmsrs++);
	index = __find_msr_index(vmx, MSR_TSC_AUX);
	if (index >= 0 && guest_cpuid_has(&vmx->vcpu, X86_FEATURE_RDTSCP))
		move_msr_up(vmx, index, save_nmsrs++);

	vmx->save_nmsrs = save_nmsrs;
	vmx->guest_msrs_dirty = true;

	if (cpu_has_vmx_msr_bitmap())
		vmx_update_msr_bitmap(&vmx->vcpu);
}

static u64 vmx_read_l1_tsc_offset(struct kvm_vcpu *vcpu)
{
	struct vmcs12 *vmcs12 = get_vmcs12(vcpu);

	if (is_guest_mode(vcpu) &&
	    (vmcs12->cpu_based_vm_exec_control & CPU_BASED_USE_TSC_OFFSETING))
		return vcpu->arch.tsc_offset - vmcs12->tsc_offset;

	return vcpu->arch.tsc_offset;
}

static u64 vmx_write_l1_tsc_offset(struct kvm_vcpu *vcpu, u64 offset)
{
	u64 active_offset = offset;
	if (is_guest_mode(vcpu)) {
		/*
		 * We're here if L1 chose not to trap WRMSR to TSC. According
		 * to the spec, this should set L1's TSC; The offset that L1
		 * set for L2 remains unchanged, and still needs to be added
		 * to the newly set TSC to get L2's TSC.
		 */
		struct vmcs12 *vmcs12 = get_vmcs12(vcpu);
		if (nested_cpu_has(vmcs12, CPU_BASED_USE_TSC_OFFSETING))
			active_offset += vmcs12->tsc_offset;
	} else {
		trace_kvm_write_tsc_offset(vcpu->vcpu_id,
					   vmcs_read64(TSC_OFFSET), offset);
	}

	vmcs_write64(TSC_OFFSET, active_offset);
	return active_offset;
}

/*
 * nested_vmx_allowed() checks whether a guest should be allowed to use VMX
 * instructions and MSRs (i.e., nested VMX). Nested VMX is disabled for
 * all guests if the "nested" module option is off, and can also be disabled
 * for a single guest by disabling its VMX cpuid bit.
 */
static inline bool nested_vmx_allowed(struct kvm_vcpu *vcpu)
{
	return nested && guest_cpuid_has(vcpu, X86_FEATURE_VMX);
}

/*
 * nested_vmx_setup_ctls_msrs() sets up variables containing the values to be
 * returned for the various VMX controls MSRs when nested VMX is enabled.
 * The same values should also be used to verify that vmcs12 control fields are
 * valid during nested entry from L1 to L2.
 * Each of these control msrs has a low and high 32-bit half: A low bit is on
 * if the corresponding bit in the (32-bit) control field *must* be on, and a
 * bit in the high half is on if the corresponding bit in the control field
 * may be on. See also vmx_control_verify().
 */
static void nested_vmx_setup_ctls_msrs(struct nested_vmx_msrs *msrs, bool apicv)
{
	if (!nested) {
		memset(msrs, 0, sizeof(*msrs));
		return;
	}

	/*
	 * Note that as a general rule, the high half of the MSRs (bits in
	 * the control fields which may be 1) should be initialized by the
	 * intersection of the underlying hardware's MSR (i.e., features which
	 * can be supported) and the list of features we want to expose -
	 * because they are known to be properly supported in our code.
	 * Also, usually, the low half of the MSRs (bits which must be 1) can
	 * be set to 0, meaning that L1 may turn off any of these bits. The
	 * reason is that if one of these bits is necessary, it will appear
	 * in vmcs01 and prepare_vmcs02, when it bitwise-or's the control
	 * fields of vmcs01 and vmcs02, will turn these bits off - and
	 * nested_vmx_exit_reflected() will not pass related exits to L1.
	 * These rules have exceptions below.
	 */

	/* pin-based controls */
	rdmsr(MSR_IA32_VMX_PINBASED_CTLS,
		msrs->pinbased_ctls_low,
		msrs->pinbased_ctls_high);
	msrs->pinbased_ctls_low |=
		PIN_BASED_ALWAYSON_WITHOUT_TRUE_MSR;
	msrs->pinbased_ctls_high &=
		PIN_BASED_EXT_INTR_MASK |
		PIN_BASED_NMI_EXITING |
		PIN_BASED_VIRTUAL_NMIS |
		(apicv ? PIN_BASED_POSTED_INTR : 0);
	msrs->pinbased_ctls_high |=
		PIN_BASED_ALWAYSON_WITHOUT_TRUE_MSR |
		PIN_BASED_VMX_PREEMPTION_TIMER;

	/* exit controls */
	rdmsr(MSR_IA32_VMX_EXIT_CTLS,
		msrs->exit_ctls_low,
		msrs->exit_ctls_high);
	msrs->exit_ctls_low =
		VM_EXIT_ALWAYSON_WITHOUT_TRUE_MSR;

	msrs->exit_ctls_high &=
#ifdef CONFIG_X86_64
		VM_EXIT_HOST_ADDR_SPACE_SIZE |
#endif
		VM_EXIT_LOAD_IA32_PAT | VM_EXIT_SAVE_IA32_PAT;
	msrs->exit_ctls_high |=
		VM_EXIT_ALWAYSON_WITHOUT_TRUE_MSR |
		VM_EXIT_LOAD_IA32_EFER | VM_EXIT_SAVE_IA32_EFER |
		VM_EXIT_SAVE_VMX_PREEMPTION_TIMER | VM_EXIT_ACK_INTR_ON_EXIT;

	/* We support free control of debug control saving. */
	msrs->exit_ctls_low &= ~VM_EXIT_SAVE_DEBUG_CONTROLS;

	/* entry controls */
	rdmsr(MSR_IA32_VMX_ENTRY_CTLS,
		msrs->entry_ctls_low,
		msrs->entry_ctls_high);
	msrs->entry_ctls_low =
		VM_ENTRY_ALWAYSON_WITHOUT_TRUE_MSR;
	msrs->entry_ctls_high &=
#ifdef CONFIG_X86_64
		VM_ENTRY_IA32E_MODE |
#endif
		VM_ENTRY_LOAD_IA32_PAT;
	msrs->entry_ctls_high |=
		(VM_ENTRY_ALWAYSON_WITHOUT_TRUE_MSR | VM_ENTRY_LOAD_IA32_EFER);

	/* We support free control of debug control loading. */
	msrs->entry_ctls_low &= ~VM_ENTRY_LOAD_DEBUG_CONTROLS;

	/* cpu-based controls */
	rdmsr(MSR_IA32_VMX_PROCBASED_CTLS,
		msrs->procbased_ctls_low,
		msrs->procbased_ctls_high);
	msrs->procbased_ctls_low =
		CPU_BASED_ALWAYSON_WITHOUT_TRUE_MSR;
	msrs->procbased_ctls_high &=
		CPU_BASED_VIRTUAL_INTR_PENDING |
		CPU_BASED_VIRTUAL_NMI_PENDING | CPU_BASED_USE_TSC_OFFSETING |
		CPU_BASED_HLT_EXITING | CPU_BASED_INVLPG_EXITING |
		CPU_BASED_MWAIT_EXITING | CPU_BASED_CR3_LOAD_EXITING |
		CPU_BASED_CR3_STORE_EXITING |
#ifdef CONFIG_X86_64
		CPU_BASED_CR8_LOAD_EXITING | CPU_BASED_CR8_STORE_EXITING |
#endif
		CPU_BASED_MOV_DR_EXITING | CPU_BASED_UNCOND_IO_EXITING |
		CPU_BASED_USE_IO_BITMAPS | CPU_BASED_MONITOR_TRAP_FLAG |
		CPU_BASED_MONITOR_EXITING | CPU_BASED_RDPMC_EXITING |
		CPU_BASED_RDTSC_EXITING | CPU_BASED_PAUSE_EXITING |
		CPU_BASED_TPR_SHADOW | CPU_BASED_ACTIVATE_SECONDARY_CONTROLS;
	/*
	 * We can allow some features even when not supported by the
	 * hardware. For example, L1 can specify an MSR bitmap - and we
	 * can use it to avoid exits to L1 - even when L0 runs L2
	 * without MSR bitmaps.
	 */
	msrs->procbased_ctls_high |=
		CPU_BASED_ALWAYSON_WITHOUT_TRUE_MSR |
		CPU_BASED_USE_MSR_BITMAPS;

	/* We support free control of CR3 access interception. */
	msrs->procbased_ctls_low &=
		~(CPU_BASED_CR3_LOAD_EXITING | CPU_BASED_CR3_STORE_EXITING);

	/*
	 * secondary cpu-based controls.  Do not include those that
	 * depend on CPUID bits, they are added later by vmx_cpuid_update.
	 */
	if (msrs->procbased_ctls_high & CPU_BASED_ACTIVATE_SECONDARY_CONTROLS)
		rdmsr(MSR_IA32_VMX_PROCBASED_CTLS2,
		      msrs->secondary_ctls_low,
		      msrs->secondary_ctls_high);

	msrs->secondary_ctls_low = 0;
	msrs->secondary_ctls_high &=
		SECONDARY_EXEC_DESC |
		SECONDARY_EXEC_VIRTUALIZE_X2APIC_MODE |
		SECONDARY_EXEC_APIC_REGISTER_VIRT |
		SECONDARY_EXEC_VIRTUAL_INTR_DELIVERY |
		SECONDARY_EXEC_WBINVD_EXITING;

	/*
	 * We can emulate "VMCS shadowing," even if the hardware
	 * doesn't support it.
	 */
	msrs->secondary_ctls_high |=
		SECONDARY_EXEC_SHADOW_VMCS;

	if (enable_ept) {
		/* nested EPT: emulate EPT also to L1 */
		msrs->secondary_ctls_high |=
			SECONDARY_EXEC_ENABLE_EPT;
		msrs->ept_caps = VMX_EPT_PAGE_WALK_4_BIT |
			 VMX_EPTP_WB_BIT | VMX_EPT_INVEPT_BIT;
		if (cpu_has_vmx_ept_execute_only())
			msrs->ept_caps |=
				VMX_EPT_EXECUTE_ONLY_BIT;
		msrs->ept_caps &= vmx_capability.ept;
		msrs->ept_caps |= VMX_EPT_EXTENT_GLOBAL_BIT |
			VMX_EPT_EXTENT_CONTEXT_BIT | VMX_EPT_2MB_PAGE_BIT |
			VMX_EPT_1GB_PAGE_BIT;
		if (enable_ept_ad_bits) {
			msrs->secondary_ctls_high |=
				SECONDARY_EXEC_ENABLE_PML;
			msrs->ept_caps |= VMX_EPT_AD_BIT;
		}
	}

	if (cpu_has_vmx_vmfunc()) {
		msrs->secondary_ctls_high |=
			SECONDARY_EXEC_ENABLE_VMFUNC;
		/*
		 * Advertise EPTP switching unconditionally
		 * since we emulate it
		 */
		if (enable_ept)
			msrs->vmfunc_controls =
				VMX_VMFUNC_EPTP_SWITCHING;
	}

	/*
	 * Old versions of KVM use the single-context version without
	 * checking for support, so declare that it is supported even
	 * though it is treated as global context.  The alternative is
	 * not failing the single-context invvpid, and it is worse.
	 */
	if (enable_vpid) {
		msrs->secondary_ctls_high |=
			SECONDARY_EXEC_ENABLE_VPID;
		msrs->vpid_caps = VMX_VPID_INVVPID_BIT |
			VMX_VPID_EXTENT_SUPPORTED_MASK;
	}

	if (enable_unrestricted_guest)
		msrs->secondary_ctls_high |=
			SECONDARY_EXEC_UNRESTRICTED_GUEST;

	if (flexpriority_enabled)
		msrs->secondary_ctls_high |=
			SECONDARY_EXEC_VIRTUALIZE_APIC_ACCESSES;

	/* miscellaneous data */
	rdmsr(MSR_IA32_VMX_MISC,
		msrs->misc_low,
		msrs->misc_high);
	msrs->misc_low &= VMX_MISC_SAVE_EFER_LMA;
	msrs->misc_low |=
		MSR_IA32_VMX_MISC_VMWRITE_SHADOW_RO_FIELDS |
		VMX_MISC_EMULATED_PREEMPTION_TIMER_RATE |
		VMX_MISC_ACTIVITY_HLT;
	msrs->misc_high = 0;

	/*
	 * This MSR reports some information about VMX support. We
	 * should return information about the VMX we emulate for the
	 * guest, and the VMCS structure we give it - not about the
	 * VMX support of the underlying hardware.
	 */
	msrs->basic =
		VMCS12_REVISION |
		VMX_BASIC_TRUE_CTLS |
		((u64)VMCS12_SIZE << VMX_BASIC_VMCS_SIZE_SHIFT) |
		(VMX_BASIC_MEM_TYPE_WB << VMX_BASIC_MEM_TYPE_SHIFT);

	if (cpu_has_vmx_basic_inout())
		msrs->basic |= VMX_BASIC_INOUT;

	/*
	 * These MSRs specify bits which the guest must keep fixed on
	 * while L1 is in VMXON mode (in L1's root mode, or running an L2).
	 * We picked the standard core2 setting.
	 */
#define VMXON_CR0_ALWAYSON     (X86_CR0_PE | X86_CR0_PG | X86_CR0_NE)
#define VMXON_CR4_ALWAYSON     X86_CR4_VMXE
	msrs->cr0_fixed0 = VMXON_CR0_ALWAYSON;
	msrs->cr4_fixed0 = VMXON_CR4_ALWAYSON;

	/* These MSRs specify bits which the guest must keep fixed off. */
	rdmsrl(MSR_IA32_VMX_CR0_FIXED1, msrs->cr0_fixed1);
	rdmsrl(MSR_IA32_VMX_CR4_FIXED1, msrs->cr4_fixed1);

	/* highest index: VMX_PREEMPTION_TIMER_VALUE */
	msrs->vmcs_enum = VMCS12_MAX_FIELD_INDEX << 1;
}

/*
 * if fixed0[i] == 1: val[i] must be 1
 * if fixed1[i] == 0: val[i] must be 0
 */
static inline bool fixed_bits_valid(u64 val, u64 fixed0, u64 fixed1)
{
	return ((val & fixed1) | fixed0) == val;
}

static inline bool vmx_control_verify(u32 control, u32 low, u32 high)
{
	return fixed_bits_valid(control, low, high);
}

static inline u64 vmx_control_msr(u32 low, u32 high)
{
	return low | ((u64)high << 32);
}

static bool is_bitwise_subset(u64 superset, u64 subset, u64 mask)
{
	superset &= mask;
	subset &= mask;

	return (superset | subset) == superset;
}

static int vmx_restore_vmx_basic(struct vcpu_vmx *vmx, u64 data)
{
	const u64 feature_and_reserved =
		/* feature (except bit 48; see below) */
		BIT_ULL(49) | BIT_ULL(54) | BIT_ULL(55) |
		/* reserved */
		BIT_ULL(31) | GENMASK_ULL(47, 45) | GENMASK_ULL(63, 56);
	u64 vmx_basic = vmx->nested.msrs.basic;

	if (!is_bitwise_subset(vmx_basic, data, feature_and_reserved))
		return -EINVAL;

	/*
	 * KVM does not emulate a version of VMX that constrains physical
	 * addresses of VMX structures (e.g. VMCS) to 32-bits.
	 */
	if (data & BIT_ULL(48))
		return -EINVAL;

	if (vmx_basic_vmcs_revision_id(vmx_basic) !=
	    vmx_basic_vmcs_revision_id(data))
		return -EINVAL;

	if (vmx_basic_vmcs_size(vmx_basic) > vmx_basic_vmcs_size(data))
		return -EINVAL;

	vmx->nested.msrs.basic = data;
	return 0;
}

static int
vmx_restore_control_msr(struct vcpu_vmx *vmx, u32 msr_index, u64 data)
{
	u64 supported;
	u32 *lowp, *highp;

	switch (msr_index) {
	case MSR_IA32_VMX_TRUE_PINBASED_CTLS:
		lowp = &vmx->nested.msrs.pinbased_ctls_low;
		highp = &vmx->nested.msrs.pinbased_ctls_high;
		break;
	case MSR_IA32_VMX_TRUE_PROCBASED_CTLS:
		lowp = &vmx->nested.msrs.procbased_ctls_low;
		highp = &vmx->nested.msrs.procbased_ctls_high;
		break;
	case MSR_IA32_VMX_TRUE_EXIT_CTLS:
		lowp = &vmx->nested.msrs.exit_ctls_low;
		highp = &vmx->nested.msrs.exit_ctls_high;
		break;
	case MSR_IA32_VMX_TRUE_ENTRY_CTLS:
		lowp = &vmx->nested.msrs.entry_ctls_low;
		highp = &vmx->nested.msrs.entry_ctls_high;
		break;
	case MSR_IA32_VMX_PROCBASED_CTLS2:
		lowp = &vmx->nested.msrs.secondary_ctls_low;
		highp = &vmx->nested.msrs.secondary_ctls_high;
		break;
	default:
		BUG();
	}

	supported = vmx_control_msr(*lowp, *highp);

	/* Check must-be-1 bits are still 1. */
	if (!is_bitwise_subset(data, supported, GENMASK_ULL(31, 0)))
		return -EINVAL;

	/* Check must-be-0 bits are still 0. */
	if (!is_bitwise_subset(supported, data, GENMASK_ULL(63, 32)))
		return -EINVAL;

	*lowp = data;
	*highp = data >> 32;
	return 0;
}

static int vmx_restore_vmx_misc(struct vcpu_vmx *vmx, u64 data)
{
	const u64 feature_and_reserved_bits =
		/* feature */
		BIT_ULL(5) | GENMASK_ULL(8, 6) | BIT_ULL(14) | BIT_ULL(15) |
		BIT_ULL(28) | BIT_ULL(29) | BIT_ULL(30) |
		/* reserved */
		GENMASK_ULL(13, 9) | BIT_ULL(31);
	u64 vmx_misc;

	vmx_misc = vmx_control_msr(vmx->nested.msrs.misc_low,
				   vmx->nested.msrs.misc_high);

	if (!is_bitwise_subset(vmx_misc, data, feature_and_reserved_bits))
		return -EINVAL;

	if ((vmx->nested.msrs.pinbased_ctls_high &
	     PIN_BASED_VMX_PREEMPTION_TIMER) &&
	    vmx_misc_preemption_timer_rate(data) !=
	    vmx_misc_preemption_timer_rate(vmx_misc))
		return -EINVAL;

	if (vmx_misc_cr3_count(data) > vmx_misc_cr3_count(vmx_misc))
		return -EINVAL;

	if (vmx_misc_max_msr(data) > vmx_misc_max_msr(vmx_misc))
		return -EINVAL;

	if (vmx_misc_mseg_revid(data) != vmx_misc_mseg_revid(vmx_misc))
		return -EINVAL;

	vmx->nested.msrs.misc_low = data;
	vmx->nested.msrs.misc_high = data >> 32;

	/*
	 * If L1 has read-only VM-exit information fields, use the
	 * less permissive vmx_vmwrite_bitmap to specify write
	 * permissions for the shadow VMCS.
	 */
	if (enable_shadow_vmcs && !nested_cpu_has_vmwrite_any_field(&vmx->vcpu))
		vmcs_write64(VMWRITE_BITMAP, __pa(vmx_vmwrite_bitmap));

	return 0;
}

static int vmx_restore_vmx_ept_vpid_cap(struct vcpu_vmx *vmx, u64 data)
{
	u64 vmx_ept_vpid_cap;

	vmx_ept_vpid_cap = vmx_control_msr(vmx->nested.msrs.ept_caps,
					   vmx->nested.msrs.vpid_caps);

	/* Every bit is either reserved or a feature bit. */
	if (!is_bitwise_subset(vmx_ept_vpid_cap, data, -1ULL))
		return -EINVAL;

	vmx->nested.msrs.ept_caps = data;
	vmx->nested.msrs.vpid_caps = data >> 32;
	return 0;
}

static int vmx_restore_fixed0_msr(struct vcpu_vmx *vmx, u32 msr_index, u64 data)
{
	u64 *msr;

	switch (msr_index) {
	case MSR_IA32_VMX_CR0_FIXED0:
		msr = &vmx->nested.msrs.cr0_fixed0;
		break;
	case MSR_IA32_VMX_CR4_FIXED0:
		msr = &vmx->nested.msrs.cr4_fixed0;
		break;
	default:
		BUG();
	}

	/*
	 * 1 bits (which indicates bits which "must-be-1" during VMX operation)
	 * must be 1 in the restored value.
	 */
	if (!is_bitwise_subset(data, *msr, -1ULL))
		return -EINVAL;

	*msr = data;
	return 0;
}

/*
 * Called when userspace is restoring VMX MSRs.
 *
 * Returns 0 on success, non-0 otherwise.
 */
static int vmx_set_vmx_msr(struct kvm_vcpu *vcpu, u32 msr_index, u64 data)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);

	/*
	 * Don't allow changes to the VMX capability MSRs while the vCPU
	 * is in VMX operation.
	 */
	if (vmx->nested.vmxon)
		return -EBUSY;

	switch (msr_index) {
	case MSR_IA32_VMX_BASIC:
		return vmx_restore_vmx_basic(vmx, data);
	case MSR_IA32_VMX_PINBASED_CTLS:
	case MSR_IA32_VMX_PROCBASED_CTLS:
	case MSR_IA32_VMX_EXIT_CTLS:
	case MSR_IA32_VMX_ENTRY_CTLS:
		/*
		 * The "non-true" VMX capability MSRs are generated from the
		 * "true" MSRs, so we do not support restoring them directly.
		 *
		 * If userspace wants to emulate VMX_BASIC[55]=0, userspace
		 * should restore the "true" MSRs with the must-be-1 bits
		 * set according to the SDM Vol 3. A.2 "RESERVED CONTROLS AND
		 * DEFAULT SETTINGS".
		 */
		return -EINVAL;
	case MSR_IA32_VMX_TRUE_PINBASED_CTLS:
	case MSR_IA32_VMX_TRUE_PROCBASED_CTLS:
	case MSR_IA32_VMX_TRUE_EXIT_CTLS:
	case MSR_IA32_VMX_TRUE_ENTRY_CTLS:
	case MSR_IA32_VMX_PROCBASED_CTLS2:
		return vmx_restore_control_msr(vmx, msr_index, data);
	case MSR_IA32_VMX_MISC:
		return vmx_restore_vmx_misc(vmx, data);
	case MSR_IA32_VMX_CR0_FIXED0:
	case MSR_IA32_VMX_CR4_FIXED0:
		return vmx_restore_fixed0_msr(vmx, msr_index, data);
	case MSR_IA32_VMX_CR0_FIXED1:
	case MSR_IA32_VMX_CR4_FIXED1:
		/*
		 * These MSRs are generated based on the vCPU's CPUID, so we
		 * do not support restoring them directly.
		 */
		return -EINVAL;
	case MSR_IA32_VMX_EPT_VPID_CAP:
		return vmx_restore_vmx_ept_vpid_cap(vmx, data);
	case MSR_IA32_VMX_VMCS_ENUM:
		vmx->nested.msrs.vmcs_enum = data;
		return 0;
	default:
		/*
		 * The rest of the VMX capability MSRs do not support restore.
		 */
		return -EINVAL;
	}
}

/* Returns 0 on success, non-0 otherwise. */
static int vmx_get_vmx_msr(struct nested_vmx_msrs *msrs, u32 msr_index, u64 *pdata)
{
	switch (msr_index) {
	case MSR_IA32_VMX_BASIC:
		*pdata = msrs->basic;
		break;
	case MSR_IA32_VMX_TRUE_PINBASED_CTLS:
	case MSR_IA32_VMX_PINBASED_CTLS:
		*pdata = vmx_control_msr(
			msrs->pinbased_ctls_low,
			msrs->pinbased_ctls_high);
		if (msr_index == MSR_IA32_VMX_PINBASED_CTLS)
			*pdata |= PIN_BASED_ALWAYSON_WITHOUT_TRUE_MSR;
		break;
	case MSR_IA32_VMX_TRUE_PROCBASED_CTLS:
	case MSR_IA32_VMX_PROCBASED_CTLS:
		*pdata = vmx_control_msr(
			msrs->procbased_ctls_low,
			msrs->procbased_ctls_high);
		if (msr_index == MSR_IA32_VMX_PROCBASED_CTLS)
			*pdata |= CPU_BASED_ALWAYSON_WITHOUT_TRUE_MSR;
		break;
	case MSR_IA32_VMX_TRUE_EXIT_CTLS:
	case MSR_IA32_VMX_EXIT_CTLS:
		*pdata = vmx_control_msr(
			msrs->exit_ctls_low,
			msrs->exit_ctls_high);
		if (msr_index == MSR_IA32_VMX_EXIT_CTLS)
			*pdata |= VM_EXIT_ALWAYSON_WITHOUT_TRUE_MSR;
		break;
	case MSR_IA32_VMX_TRUE_ENTRY_CTLS:
	case MSR_IA32_VMX_ENTRY_CTLS:
		*pdata = vmx_control_msr(
			msrs->entry_ctls_low,
			msrs->entry_ctls_high);
		if (msr_index == MSR_IA32_VMX_ENTRY_CTLS)
			*pdata |= VM_ENTRY_ALWAYSON_WITHOUT_TRUE_MSR;
		break;
	case MSR_IA32_VMX_MISC:
		*pdata = vmx_control_msr(
			msrs->misc_low,
			msrs->misc_high);
		break;
	case MSR_IA32_VMX_CR0_FIXED0:
		*pdata = msrs->cr0_fixed0;
		break;
	case MSR_IA32_VMX_CR0_FIXED1:
		*pdata = msrs->cr0_fixed1;
		break;
	case MSR_IA32_VMX_CR4_FIXED0:
		*pdata = msrs->cr4_fixed0;
		break;
	case MSR_IA32_VMX_CR4_FIXED1:
		*pdata = msrs->cr4_fixed1;
		break;
	case MSR_IA32_VMX_VMCS_ENUM:
		*pdata = msrs->vmcs_enum;
		break;
	case MSR_IA32_VMX_PROCBASED_CTLS2:
		*pdata = vmx_control_msr(
			msrs->secondary_ctls_low,
			msrs->secondary_ctls_high);
		break;
	case MSR_IA32_VMX_EPT_VPID_CAP:
		*pdata = msrs->ept_caps |
			((u64)msrs->vpid_caps << 32);
		break;
	case MSR_IA32_VMX_VMFUNC:
		*pdata = msrs->vmfunc_controls;
		break;
	default:
		return 1;
	}

	return 0;
}

static inline bool vmx_feature_control_msr_valid(struct kvm_vcpu *vcpu,
						 uint64_t val)
{
	uint64_t valid_bits = to_vmx(vcpu)->msr_ia32_feature_control_valid_bits;

	return !(val & ~valid_bits);
}

static int vmx_get_msr_feature(struct kvm_msr_entry *msr)
{
	switch (msr->index) {
	case MSR_IA32_VMX_BASIC ... MSR_IA32_VMX_VMFUNC:
		if (!nested)
			return 1;
		return vmx_get_vmx_msr(&vmcs_config.nested, msr->index, &msr->data);
	default:
		return 1;
	}

	return 0;
}

/*
 * Reads an msr value (of 'msr_index') into 'pdata'.
 * Returns 0 on success, non-0 otherwise.
 * Assumes vcpu_load() was already called.
 */
static int vmx_get_msr(struct kvm_vcpu *vcpu, struct msr_data *msr_info)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	struct shared_msr_entry *msr;

	switch (msr_info->index) {
#ifdef CONFIG_X86_64
	case MSR_FS_BASE:
		msr_info->data = vmcs_readl(GUEST_FS_BASE);
		break;
	case MSR_GS_BASE:
		msr_info->data = vmcs_readl(GUEST_GS_BASE);
		break;
	case MSR_KERNEL_GS_BASE:
		msr_info->data = vmx_read_guest_kernel_gs_base(vmx);
		break;
#endif
	case MSR_EFER:
		return kvm_get_msr_common(vcpu, msr_info);
	case MSR_IA32_SPEC_CTRL:
		if (!msr_info->host_initiated &&
		    !guest_has_spec_ctrl_msr(vcpu))
			return 1;

		msr_info->data = to_vmx(vcpu)->spec_ctrl;
		break;
	case MSR_IA32_SYSENTER_CS:
		msr_info->data = vmcs_read32(GUEST_SYSENTER_CS);
		break;
	case MSR_IA32_SYSENTER_EIP:
		msr_info->data = vmcs_readl(GUEST_SYSENTER_EIP);
		break;
	case MSR_IA32_SYSENTER_ESP:
		msr_info->data = vmcs_readl(GUEST_SYSENTER_ESP);
		break;
	case MSR_IA32_BNDCFGS:
		if (!kvm_mpx_supported() ||
		    (!msr_info->host_initiated &&
		     !guest_cpuid_has(vcpu, X86_FEATURE_MPX)))
			return 1;
		msr_info->data = vmcs_read64(GUEST_BNDCFGS);
		break;
	case MSR_IA32_MCG_EXT_CTL:
		if (!msr_info->host_initiated &&
		    !(vmx->msr_ia32_feature_control &
		      FEATURE_CONTROL_LMCE))
			return 1;
		msr_info->data = vcpu->arch.mcg_ext_ctl;
		break;
	case MSR_IA32_FEATURE_CONTROL:
		msr_info->data = vmx->msr_ia32_feature_control;
		break;
	case MSR_IA32_VMX_BASIC ... MSR_IA32_VMX_VMFUNC:
		if (!nested_vmx_allowed(vcpu))
			return 1;
		return vmx_get_vmx_msr(&vmx->nested.msrs, msr_info->index,
				       &msr_info->data);
	case MSR_IA32_XSS:
		if (!vmx_xsaves_supported() ||
		    (!msr_info->host_initiated &&
		     !(guest_cpuid_has(vcpu, X86_FEATURE_XSAVE) &&
		       guest_cpuid_has(vcpu, X86_FEATURE_XSAVES))))
			return 1;
		msr_info->data = vcpu->arch.ia32_xss;
		break;
	case MSR_TSC_AUX:
		if (!msr_info->host_initiated &&
		    !guest_cpuid_has(vcpu, X86_FEATURE_RDTSCP))
			return 1;
		/* Otherwise falls through */
	default:
		msr = find_msr_entry(vmx, msr_info->index);
		if (msr) {
			msr_info->data = msr->data;
			break;
		}
		return kvm_get_msr_common(vcpu, msr_info);
	}

	return 0;
}

static void vmx_leave_nested(struct kvm_vcpu *vcpu);

/*
 * Writes msr value into into the appropriate "register".
 * Returns 0 on success, non-0 otherwise.
 * Assumes vcpu_load() was already called.
 */
static int vmx_set_msr(struct kvm_vcpu *vcpu, struct msr_data *msr_info)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	struct shared_msr_entry *msr;
	int ret = 0;
	u32 msr_index = msr_info->index;
	u64 data = msr_info->data;

	switch (msr_index) {
	case MSR_EFER:
		ret = kvm_set_msr_common(vcpu, msr_info);
		break;
#ifdef CONFIG_X86_64
	case MSR_FS_BASE:
		vmx_segment_cache_clear(vmx);
		vmcs_writel(GUEST_FS_BASE, data);
		break;
	case MSR_GS_BASE:
		vmx_segment_cache_clear(vmx);
		vmcs_writel(GUEST_GS_BASE, data);
		break;
	case MSR_KERNEL_GS_BASE:
		vmx_write_guest_kernel_gs_base(vmx, data);
		break;
#endif
	case MSR_IA32_SYSENTER_CS:
		vmcs_write32(GUEST_SYSENTER_CS, data);
		break;
	case MSR_IA32_SYSENTER_EIP:
		vmcs_writel(GUEST_SYSENTER_EIP, data);
		break;
	case MSR_IA32_SYSENTER_ESP:
		vmcs_writel(GUEST_SYSENTER_ESP, data);
		break;
	case MSR_IA32_BNDCFGS:
		if (!kvm_mpx_supported() ||
		    (!msr_info->host_initiated &&
		     !guest_cpuid_has(vcpu, X86_FEATURE_MPX)))
			return 1;
		if (is_noncanonical_address(data & PAGE_MASK, vcpu) ||
		    (data & MSR_IA32_BNDCFGS_RSVD))
			return 1;
		vmcs_write64(GUEST_BNDCFGS, data);
		break;
	case MSR_IA32_SPEC_CTRL:
		if (!msr_info->host_initiated &&
		    !guest_has_spec_ctrl_msr(vcpu))
			return 1;

		/* The STIBP bit doesn't fault even if it's not advertised */
		if (data & ~(SPEC_CTRL_IBRS | SPEC_CTRL_STIBP | SPEC_CTRL_SSBD))
			return 1;

		vmx->spec_ctrl = data;

		if (!data)
			break;

		/*
		 * For non-nested:
		 * When it's written (to non-zero) for the first time, pass
		 * it through.
		 *
		 * For nested:
		 * The handling of the MSR bitmap for L2 guests is done in
		 * nested_vmx_merge_msr_bitmap. We should not touch the
		 * vmcs02.msr_bitmap here since it gets completely overwritten
		 * in the merging. We update the vmcs01 here for L1 as well
		 * since it will end up touching the MSR anyway now.
		 */
		vmx_disable_intercept_for_msr(vmx->vmcs01.msr_bitmap,
					      MSR_IA32_SPEC_CTRL,
					      MSR_TYPE_RW);
		break;
	case MSR_IA32_PRED_CMD:
		if (!msr_info->host_initiated &&
		    !guest_has_pred_cmd_msr(vcpu))
			return 1;

		if (data & ~PRED_CMD_IBPB)
			return 1;

		if (!data)
			break;

		wrmsrl(MSR_IA32_PRED_CMD, PRED_CMD_IBPB);

		/*
		 * For non-nested:
		 * When it's written (to non-zero) for the first time, pass
		 * it through.
		 *
		 * For nested:
		 * The handling of the MSR bitmap for L2 guests is done in
		 * nested_vmx_merge_msr_bitmap. We should not touch the
		 * vmcs02.msr_bitmap here since it gets completely overwritten
		 * in the merging.
		 */
		vmx_disable_intercept_for_msr(vmx->vmcs01.msr_bitmap, MSR_IA32_PRED_CMD,
					      MSR_TYPE_W);
		break;
	case MSR_IA32_CR_PAT:
		if (!kvm_pat_valid(data))
			return 1;

		if (vmcs_config.vmentry_ctrl & VM_ENTRY_LOAD_IA32_PAT) {
			vmcs_write64(GUEST_IA32_PAT, data);
			vcpu->arch.pat = data;
			break;
		}
		ret = kvm_set_msr_common(vcpu, msr_info);
		break;
	case MSR_IA32_TSC_ADJUST:
		ret = kvm_set_msr_common(vcpu, msr_info);
		break;
	case MSR_IA32_MCG_EXT_CTL:
		if ((!msr_info->host_initiated &&
		     !(to_vmx(vcpu)->msr_ia32_feature_control &
		       FEATURE_CONTROL_LMCE)) ||
		    (data & ~MCG_EXT_CTL_LMCE_EN))
			return 1;
		vcpu->arch.mcg_ext_ctl = data;
		break;
	case MSR_IA32_FEATURE_CONTROL:
		if (!vmx_feature_control_msr_valid(vcpu, data) ||
		    (to_vmx(vcpu)->msr_ia32_feature_control &
		     FEATURE_CONTROL_LOCKED && !msr_info->host_initiated))
			return 1;
		vmx->msr_ia32_feature_control = data;
		if (msr_info->host_initiated && data == 0)
			vmx_leave_nested(vcpu);
		break;
	case MSR_IA32_VMX_BASIC ... MSR_IA32_VMX_VMFUNC:
		if (!msr_info->host_initiated)
			return 1; /* they are read-only */
		if (!nested_vmx_allowed(vcpu))
			return 1;
		return vmx_set_vmx_msr(vcpu, msr_index, data);
	case MSR_IA32_XSS:
		if (!vmx_xsaves_supported() ||
		    (!msr_info->host_initiated &&
		     !(guest_cpuid_has(vcpu, X86_FEATURE_XSAVE) &&
		       guest_cpuid_has(vcpu, X86_FEATURE_XSAVES))))
			return 1;
		/*
		 * The only supported bit as of Skylake is bit 8, but
		 * it is not supported on KVM.
		 */
		if (data != 0)
			return 1;
		vcpu->arch.ia32_xss = data;
		if (vcpu->arch.ia32_xss != host_xss)
			add_atomic_switch_msr(vmx, MSR_IA32_XSS,
				vcpu->arch.ia32_xss, host_xss, false);
		else
			clear_atomic_switch_msr(vmx, MSR_IA32_XSS);
		break;
	case MSR_TSC_AUX:
		if (!msr_info->host_initiated &&
		    !guest_cpuid_has(vcpu, X86_FEATURE_RDTSCP))
			return 1;
		/* Check reserved bit, higher 32 bits should be zero */
		if ((data >> 32) != 0)
			return 1;
		/* Otherwise falls through */
	default:
		msr = find_msr_entry(vmx, msr_index);
		if (msr) {
			u64 old_msr_data = msr->data;
			msr->data = data;
			if (msr - vmx->guest_msrs < vmx->save_nmsrs) {
				preempt_disable();
				ret = kvm_set_shared_msr(msr->index, msr->data,
							 msr->mask);
				preempt_enable();
				if (ret)
					msr->data = old_msr_data;
			}
			break;
		}
			ret = kvm_set_msr_common(vcpu, msr_info);
	}

	/* FB_CLEAR may have changed, also update the FB_CLEAR_DIS behavior */
	if (msr_index == MSR_IA32_ARCH_CAPABILITIES)
		vmx_update_fb_clear_dis(vcpu, vmx);

	return ret;
}

static void vmx_cache_reg(struct kvm_vcpu *vcpu, enum kvm_reg reg)
{
	__set_bit(reg, (unsigned long *)&vcpu->arch.regs_avail);
	switch (reg) {
	case VCPU_REGS_RSP:
		vcpu->arch.regs[VCPU_REGS_RSP] = vmcs_readl(GUEST_RSP);
		break;
	case VCPU_REGS_RIP:
		vcpu->arch.regs[VCPU_REGS_RIP] = vmcs_readl(GUEST_RIP);
		break;
	case VCPU_EXREG_PDPTR:
		if (enable_ept)
			ept_save_pdptrs(vcpu);
		break;
	default:
		break;
	}
}

static __init int cpu_has_kvm_support(void)
{
	return cpu_has_vmx();
}

static __init int vmx_disabled_by_bios(void)
{
	u64 msr;

	rdmsrl(MSR_IA32_FEATURE_CONTROL, msr);
	if (msr & FEATURE_CONTROL_LOCKED) {
		/* launched w/ TXT and VMX disabled */
		if (!(msr & FEATURE_CONTROL_VMXON_ENABLED_INSIDE_SMX)
			&& tboot_enabled())
			return 1;
		/* launched w/o TXT and VMX only enabled w/ TXT */
		if (!(msr & FEATURE_CONTROL_VMXON_ENABLED_OUTSIDE_SMX)
			&& (msr & FEATURE_CONTROL_VMXON_ENABLED_INSIDE_SMX)
			&& !tboot_enabled()) {
			printk(KERN_WARNING "kvm: disable TXT in the BIOS or "
				"activate TXT before enabling KVM\n");
			return 1;
		}
		/* launched w/o TXT and VMX disabled */
		if (!(msr & FEATURE_CONTROL_VMXON_ENABLED_OUTSIDE_SMX)
			&& !tboot_enabled())
			return 1;
	}

	return 0;
}

static void kvm_cpu_vmxon(u64 addr)
{
	cr4_set_bits(X86_CR4_VMXE);
	intel_pt_handle_vmx(1);

	asm volatile (ASM_VMX_VMXON_RAX
			: : "a"(&addr), "m"(addr)
			: "memory", "cc");
}

static int hardware_enable(void)
{
	int cpu = raw_smp_processor_id();
	u64 phys_addr = __pa(per_cpu(vmxarea, cpu));
	u64 old, test_bits;

	if (cr4_read_shadow() & X86_CR4_VMXE)
		return -EBUSY;

	/*
	 * This can happen if we hot-added a CPU but failed to allocate
	 * VP assist page for it.
	 */
	if (static_branch_unlikely(&enable_evmcs) &&
	    !hv_get_vp_assist_page(cpu))
		return -EFAULT;

	rdmsrl(MSR_IA32_FEATURE_CONTROL, old);

	test_bits = FEATURE_CONTROL_LOCKED;
	test_bits |= FEATURE_CONTROL_VMXON_ENABLED_OUTSIDE_SMX;
	if (tboot_enabled())
		test_bits |= FEATURE_CONTROL_VMXON_ENABLED_INSIDE_SMX;

	if ((old & test_bits) != test_bits) {
		/* enable and lock */
		wrmsrl(MSR_IA32_FEATURE_CONTROL, old | test_bits);
	}
	kvm_cpu_vmxon(phys_addr);
	if (enable_ept)
		ept_sync_global();

	return 0;
}

static void vmclear_local_loaded_vmcss(void)
{
	int cpu = raw_smp_processor_id();
	struct loaded_vmcs *v, *n;

	list_for_each_entry_safe(v, n, &per_cpu(loaded_vmcss_on_cpu, cpu),
				 loaded_vmcss_on_cpu_link)
		__loaded_vmcs_clear(v);
}


/* Just like cpu_vmxoff(), but with the __kvm_handle_fault_on_reboot()
 * tricks.
 */
static void kvm_cpu_vmxoff(void)
{
	asm volatile (__ex(ASM_VMX_VMXOFF) : : : "cc");

	intel_pt_handle_vmx(0);
	cr4_clear_bits(X86_CR4_VMXE);
}

static void hardware_disable(void)
{
	vmclear_local_loaded_vmcss();
	kvm_cpu_vmxoff();
}

static __init int adjust_vmx_controls(u32 ctl_min, u32 ctl_opt,
				      u32 msr, u32 *result)
{
	u32 vmx_msr_low, vmx_msr_high;
	u32 ctl = ctl_min | ctl_opt;

	rdmsr(msr, vmx_msr_low, vmx_msr_high);

	ctl &= vmx_msr_high; /* bit == 0 in high word ==> must be zero */
	ctl |= vmx_msr_low;  /* bit == 1 in low word  ==> must be one  */

	/* Ensure minimum (required) set of control bits are supported. */
	if (ctl_min & ~ctl)
		return -EIO;

	*result = ctl;
	return 0;
}

static __init bool allow_1_setting(u32 msr, u32 ctl)
{
	u32 vmx_msr_low, vmx_msr_high;

	rdmsr(msr, vmx_msr_low, vmx_msr_high);
	return vmx_msr_high & ctl;
}

static __init int setup_vmcs_config(struct vmcs_config *vmcs_conf)
{
	u32 vmx_msr_low, vmx_msr_high;
	u32 min, opt, min2, opt2;
	u32 _pin_based_exec_control = 0;
	u32 _cpu_based_exec_control = 0;
	u32 _cpu_based_2nd_exec_control = 0;
	u32 _vmexit_control = 0;
	u32 _vmentry_control = 0;

	memset(vmcs_conf, 0, sizeof(*vmcs_conf));
	min = CPU_BASED_HLT_EXITING |
#ifdef CONFIG_X86_64
	      CPU_BASED_CR8_LOAD_EXITING |
	      CPU_BASED_CR8_STORE_EXITING |
#endif
	      CPU_BASED_CR3_LOAD_EXITING |
	      CPU_BASED_CR3_STORE_EXITING |
	      CPU_BASED_UNCOND_IO_EXITING |
	      CPU_BASED_MOV_DR_EXITING |
	      CPU_BASED_USE_TSC_OFFSETING |
	      CPU_BASED_MWAIT_EXITING |
	      CPU_BASED_MONITOR_EXITING |
	      CPU_BASED_INVLPG_EXITING |
	      CPU_BASED_RDPMC_EXITING;

	opt = CPU_BASED_TPR_SHADOW |
	      CPU_BASED_USE_MSR_BITMAPS |
	      CPU_BASED_ACTIVATE_SECONDARY_CONTROLS;
	if (adjust_vmx_controls(min, opt, MSR_IA32_VMX_PROCBASED_CTLS,
				&_cpu_based_exec_control) < 0)
		return -EIO;
#ifdef CONFIG_X86_64
	if ((_cpu_based_exec_control & CPU_BASED_TPR_SHADOW))
		_cpu_based_exec_control &= ~CPU_BASED_CR8_LOAD_EXITING &
					   ~CPU_BASED_CR8_STORE_EXITING;
#endif
	if (_cpu_based_exec_control & CPU_BASED_ACTIVATE_SECONDARY_CONTROLS) {
		min2 = 0;
		opt2 = SECONDARY_EXEC_VIRTUALIZE_APIC_ACCESSES |
			SECONDARY_EXEC_VIRTUALIZE_X2APIC_MODE |
			SECONDARY_EXEC_WBINVD_EXITING |
			SECONDARY_EXEC_ENABLE_VPID |
			SECONDARY_EXEC_ENABLE_EPT |
			SECONDARY_EXEC_UNRESTRICTED_GUEST |
			SECONDARY_EXEC_PAUSE_LOOP_EXITING |
			SECONDARY_EXEC_DESC |
			SECONDARY_EXEC_RDTSCP |
			SECONDARY_EXEC_ENABLE_INVPCID |
			SECONDARY_EXEC_APIC_REGISTER_VIRT |
			SECONDARY_EXEC_VIRTUAL_INTR_DELIVERY |
			SECONDARY_EXEC_SHADOW_VMCS |
			SECONDARY_EXEC_XSAVES |
			SECONDARY_EXEC_RDSEED_EXITING |
			SECONDARY_EXEC_RDRAND_EXITING |
			SECONDARY_EXEC_ENABLE_PML |
			SECONDARY_EXEC_TSC_SCALING |
			SECONDARY_EXEC_ENABLE_VMFUNC |
			SECONDARY_EXEC_ENCLS_EXITING;
		if (adjust_vmx_controls(min2, opt2,
					MSR_IA32_VMX_PROCBASED_CTLS2,
					&_cpu_based_2nd_exec_control) < 0)
			return -EIO;
	}
#ifndef CONFIG_X86_64
	if (!(_cpu_based_2nd_exec_control &
				SECONDARY_EXEC_VIRTUALIZE_APIC_ACCESSES))
		_cpu_based_exec_control &= ~CPU_BASED_TPR_SHADOW;
#endif

	if (!(_cpu_based_exec_control & CPU_BASED_TPR_SHADOW))
		_cpu_based_2nd_exec_control &= ~(
				SECONDARY_EXEC_APIC_REGISTER_VIRT |
				SECONDARY_EXEC_VIRTUALIZE_X2APIC_MODE |
				SECONDARY_EXEC_VIRTUAL_INTR_DELIVERY);

	rdmsr_safe(MSR_IA32_VMX_EPT_VPID_CAP,
		&vmx_capability.ept, &vmx_capability.vpid);

	if (_cpu_based_2nd_exec_control & SECONDARY_EXEC_ENABLE_EPT) {
		/* CR3 accesses and invlpg don't need to cause VM Exits when EPT
		   enabled */
		_cpu_based_exec_control &= ~(CPU_BASED_CR3_LOAD_EXITING |
					     CPU_BASED_CR3_STORE_EXITING |
					     CPU_BASED_INVLPG_EXITING);
	} else if (vmx_capability.ept) {
		vmx_capability.ept = 0;
		pr_warn_once("EPT CAP should not exist if not support "
				"1-setting enable EPT VM-execution control\n");
	}
	if (!(_cpu_based_2nd_exec_control & SECONDARY_EXEC_ENABLE_VPID) &&
		vmx_capability.vpid) {
		vmx_capability.vpid = 0;
		pr_warn_once("VPID CAP should not exist if not support "
				"1-setting enable VPID VM-execution control\n");
	}

	min = VM_EXIT_SAVE_DEBUG_CONTROLS | VM_EXIT_ACK_INTR_ON_EXIT;
#ifdef CONFIG_X86_64
	min |= VM_EXIT_HOST_ADDR_SPACE_SIZE;
#endif
	opt = VM_EXIT_SAVE_IA32_PAT | VM_EXIT_LOAD_IA32_PAT |
		VM_EXIT_CLEAR_BNDCFGS;
	if (adjust_vmx_controls(min, opt, MSR_IA32_VMX_EXIT_CTLS,
				&_vmexit_control) < 0)
		return -EIO;

	min = PIN_BASED_EXT_INTR_MASK | PIN_BASED_NMI_EXITING;
	opt = PIN_BASED_VIRTUAL_NMIS | PIN_BASED_POSTED_INTR |
		 PIN_BASED_VMX_PREEMPTION_TIMER;
	if (adjust_vmx_controls(min, opt, MSR_IA32_VMX_PINBASED_CTLS,
				&_pin_based_exec_control) < 0)
		return -EIO;

	if (cpu_has_broken_vmx_preemption_timer())
		_pin_based_exec_control &= ~PIN_BASED_VMX_PREEMPTION_TIMER;
	if (!(_cpu_based_2nd_exec_control &
		SECONDARY_EXEC_VIRTUAL_INTR_DELIVERY))
		_pin_based_exec_control &= ~PIN_BASED_POSTED_INTR;

	min = VM_ENTRY_LOAD_DEBUG_CONTROLS;
	opt = VM_ENTRY_LOAD_IA32_PAT | VM_ENTRY_LOAD_BNDCFGS;
	if (adjust_vmx_controls(min, opt, MSR_IA32_VMX_ENTRY_CTLS,
				&_vmentry_control) < 0)
		return -EIO;

	rdmsr(MSR_IA32_VMX_BASIC, vmx_msr_low, vmx_msr_high);

	/* IA-32 SDM Vol 3B: VMCS size is never greater than 4kB. */
	if ((vmx_msr_high & 0x1fff) > PAGE_SIZE)
		return -EIO;

#ifdef CONFIG_X86_64
	/* IA-32 SDM Vol 3B: 64-bit CPUs always have VMX_BASIC_MSR[48]==0. */
	if (vmx_msr_high & (1u<<16))
		return -EIO;
#endif

	/* Require Write-Back (WB) memory type for VMCS accesses. */
	if (((vmx_msr_high >> 18) & 15) != 6)
		return -EIO;

	vmcs_conf->size = vmx_msr_high & 0x1fff;
	vmcs_conf->order = get_order(vmcs_conf->size);
	vmcs_conf->basic_cap = vmx_msr_high & ~0x1fff;

	vmcs_conf->revision_id = vmx_msr_low;

	vmcs_conf->pin_based_exec_ctrl = _pin_based_exec_control;
	vmcs_conf->cpu_based_exec_ctrl = _cpu_based_exec_control;
	vmcs_conf->cpu_based_2nd_exec_ctrl = _cpu_based_2nd_exec_control;
	vmcs_conf->vmexit_ctrl         = _vmexit_control;
	vmcs_conf->vmentry_ctrl        = _vmentry_control;

	if (static_branch_unlikely(&enable_evmcs))
		evmcs_sanitize_exec_ctrls(vmcs_conf);

	cpu_has_load_ia32_efer =
		allow_1_setting(MSR_IA32_VMX_ENTRY_CTLS,
				VM_ENTRY_LOAD_IA32_EFER)
		&& allow_1_setting(MSR_IA32_VMX_EXIT_CTLS,
				   VM_EXIT_LOAD_IA32_EFER);

	cpu_has_load_perf_global_ctrl =
		allow_1_setting(MSR_IA32_VMX_ENTRY_CTLS,
				VM_ENTRY_LOAD_IA32_PERF_GLOBAL_CTRL)
		&& allow_1_setting(MSR_IA32_VMX_EXIT_CTLS,
				   VM_EXIT_LOAD_IA32_PERF_GLOBAL_CTRL);

	/*
	 * Some cpus support VM_ENTRY_(LOAD|SAVE)_IA32_PERF_GLOBAL_CTRL
	 * but due to errata below it can't be used. Workaround is to use
	 * msr load mechanism to switch IA32_PERF_GLOBAL_CTRL.
	 *
	 * VM Exit May Incorrectly Clear IA32_PERF_GLOBAL_CTRL [34:32]
	 *
	 * AAK155             (model 26)
	 * AAP115             (model 30)
	 * AAT100             (model 37)
	 * BC86,AAY89,BD102   (model 44)
	 * BA97               (model 46)
	 *
	 */
	if (cpu_has_load_perf_global_ctrl && boot_cpu_data.x86 == 0x6) {
		switch (boot_cpu_data.x86_model) {
		case 26:
		case 30:
		case 37:
		case 44:
		case 46:
			cpu_has_load_perf_global_ctrl = false;
			printk_once(KERN_WARNING"kvm: VM_EXIT_LOAD_IA32_PERF_GLOBAL_CTRL "
					"does not work properly. Using workaround\n");
			break;
		default:
			break;
		}
	}

	return 0;
}

static struct vmcs *alloc_vmcs_cpu(bool shadow, int cpu)
{
	int node = cpu_to_node(cpu);
	struct page *pages;
	struct vmcs *vmcs;

	pages = __alloc_pages_node(node, GFP_KERNEL, vmcs_config.order);
	if (!pages)
		return NULL;
	vmcs = page_address(pages);
	memset(vmcs, 0, vmcs_config.size);

	/* KVM supports Enlightened VMCS v1 only */
	if (static_branch_unlikely(&enable_evmcs))
		vmcs->hdr.revision_id = KVM_EVMCS_VERSION;
	else
		vmcs->hdr.revision_id = vmcs_config.revision_id;

	if (shadow)
		vmcs->hdr.shadow_vmcs = 1;
	return vmcs;
}

static void free_vmcs(struct vmcs *vmcs)
{
	free_pages((unsigned long)vmcs, vmcs_config.order);
}

/*
 * Free a VMCS, but before that VMCLEAR it on the CPU where it was last loaded
 */
static void free_loaded_vmcs(struct loaded_vmcs *loaded_vmcs)
{
	if (!loaded_vmcs->vmcs)
		return;
	loaded_vmcs_clear(loaded_vmcs);
	free_vmcs(loaded_vmcs->vmcs);
	loaded_vmcs->vmcs = NULL;
	if (loaded_vmcs->msr_bitmap)
		free_page((unsigned long)loaded_vmcs->msr_bitmap);
	WARN_ON(loaded_vmcs->shadow_vmcs != NULL);
}

static struct vmcs *alloc_vmcs(bool shadow)
{
	return alloc_vmcs_cpu(shadow, raw_smp_processor_id());
}

static int alloc_loaded_vmcs(struct loaded_vmcs *loaded_vmcs)
{
	loaded_vmcs->vmcs = alloc_vmcs(false);
	if (!loaded_vmcs->vmcs)
		return -ENOMEM;

	loaded_vmcs->shadow_vmcs = NULL;
	loaded_vmcs_init(loaded_vmcs);

	if (cpu_has_vmx_msr_bitmap()) {
		loaded_vmcs->msr_bitmap = (unsigned long *)__get_free_page(GFP_KERNEL);
		if (!loaded_vmcs->msr_bitmap)
			goto out_vmcs;
		memset(loaded_vmcs->msr_bitmap, 0xff, PAGE_SIZE);

		if (IS_ENABLED(CONFIG_HYPERV) &&
		    static_branch_unlikely(&enable_evmcs) &&
		    (ms_hyperv.nested_features & HV_X64_NESTED_MSR_BITMAP)) {
			struct hv_enlightened_vmcs *evmcs =
				(struct hv_enlightened_vmcs *)loaded_vmcs->vmcs;

			evmcs->hv_enlightenments_control.msr_bitmap = 1;
		}
	}

	memset(&loaded_vmcs->host_state, 0, sizeof(struct vmcs_host_state));

	return 0;

out_vmcs:
	free_loaded_vmcs(loaded_vmcs);
	return -ENOMEM;
}

static void free_kvm_area(void)
{
	int cpu;

	for_each_possible_cpu(cpu) {
		free_vmcs(per_cpu(vmxarea, cpu));
		per_cpu(vmxarea, cpu) = NULL;
	}
}

enum vmcs_field_width {
	VMCS_FIELD_WIDTH_U16 = 0,
	VMCS_FIELD_WIDTH_U64 = 1,
	VMCS_FIELD_WIDTH_U32 = 2,
	VMCS_FIELD_WIDTH_NATURAL_WIDTH = 3
};

static inline int vmcs_field_width(unsigned long field)
{
	if (0x1 & field)	/* the *_HIGH fields are all 32 bit */
		return VMCS_FIELD_WIDTH_U32;
	return (field >> 13) & 0x3 ;
}

static inline int vmcs_field_readonly(unsigned long field)
{
	return (((field >> 10) & 0x3) == 1);
}

static void init_vmcs_shadow_fields(void)
{
	int i, j;

	for (i = j = 0; i < max_shadow_read_only_fields; i++) {
		u16 field = shadow_read_only_fields[i];
		if (vmcs_field_width(field) == VMCS_FIELD_WIDTH_U64 &&
		    (i + 1 == max_shadow_read_only_fields ||
		     shadow_read_only_fields[i + 1] != field + 1))
			pr_err("Missing field from shadow_read_only_field %x\n",
			       field + 1);

		clear_bit(field, vmx_vmread_bitmap);
#ifdef CONFIG_X86_64
		if (field & 1)
			continue;
#endif
		if (j < i)
			shadow_read_only_fields[j] = field;
		j++;
	}
	max_shadow_read_only_fields = j;

	for (i = j = 0; i < max_shadow_read_write_fields; i++) {
		u16 field = shadow_read_write_fields[i];
		if (vmcs_field_width(field) == VMCS_FIELD_WIDTH_U64 &&
		    (i + 1 == max_shadow_read_write_fields ||
		     shadow_read_write_fields[i + 1] != field + 1))
			pr_err("Missing field from shadow_read_write_field %x\n",
			       field + 1);

		/*
		 * PML and the preemption timer can be emulated, but the
		 * processor cannot vmwrite to fields that don't exist
		 * on bare metal.
		 */
		switch (field) {
		case GUEST_PML_INDEX:
			if (!cpu_has_vmx_pml())
				continue;
			break;
		case VMX_PREEMPTION_TIMER_VALUE:
			if (!cpu_has_vmx_preemption_timer())
				continue;
			break;
		case GUEST_INTR_STATUS:
			if (!cpu_has_vmx_apicv())
				continue;
			break;
		default:
			break;
		}

		clear_bit(field, vmx_vmwrite_bitmap);
		clear_bit(field, vmx_vmread_bitmap);
#ifdef CONFIG_X86_64
		if (field & 1)
			continue;
#endif
		if (j < i)
			shadow_read_write_fields[j] = field;
		j++;
	}
	max_shadow_read_write_fields = j;
}

static __init int alloc_kvm_area(void)
{
	int cpu;

	for_each_possible_cpu(cpu) {
		struct vmcs *vmcs;

		vmcs = alloc_vmcs_cpu(false, cpu);
		if (!vmcs) {
			free_kvm_area();
			return -ENOMEM;
		}

		/*
		 * When eVMCS is enabled, alloc_vmcs_cpu() sets
		 * vmcs->revision_id to KVM_EVMCS_VERSION instead of
		 * revision_id reported by MSR_IA32_VMX_BASIC.
		 *
		 * However, even though not explictly documented by
		 * TLFS, VMXArea passed as VMXON argument should
		 * still be marked with revision_id reported by
		 * physical CPU.
		 */
		if (static_branch_unlikely(&enable_evmcs))
			vmcs->hdr.revision_id = vmcs_config.revision_id;

		per_cpu(vmxarea, cpu) = vmcs;
	}
	return 0;
}

static void fix_pmode_seg(struct kvm_vcpu *vcpu, int seg,
		struct kvm_segment *save)
{
	if (!emulate_invalid_guest_state) {
		/*
		 * CS and SS RPL should be equal during guest entry according
		 * to VMX spec, but in reality it is not always so. Since vcpu
		 * is in the middle of the transition from real mode to
		 * protected mode it is safe to assume that RPL 0 is a good
		 * default value.
		 */
		if (seg == VCPU_SREG_CS || seg == VCPU_SREG_SS)
			save->selector &= ~SEGMENT_RPL_MASK;
		save->dpl = save->selector & SEGMENT_RPL_MASK;
		save->s = 1;
	}
	vmx_set_segment(vcpu, save, seg);
}

static void enter_pmode(struct kvm_vcpu *vcpu)
{
	unsigned long flags;
	struct vcpu_vmx *vmx = to_vmx(vcpu);

	/*
	 * Update real mode segment cache. It may be not up-to-date if sement
	 * register was written while vcpu was in a guest mode.
	 */
	vmx_get_segment(vcpu, &vmx->rmode.segs[VCPU_SREG_ES], VCPU_SREG_ES);
	vmx_get_segment(vcpu, &vmx->rmode.segs[VCPU_SREG_DS], VCPU_SREG_DS);
	vmx_get_segment(vcpu, &vmx->rmode.segs[VCPU_SREG_FS], VCPU_SREG_FS);
	vmx_get_segment(vcpu, &vmx->rmode.segs[VCPU_SREG_GS], VCPU_SREG_GS);
	vmx_get_segment(vcpu, &vmx->rmode.segs[VCPU_SREG_SS], VCPU_SREG_SS);
	vmx_get_segment(vcpu, &vmx->rmode.segs[VCPU_SREG_CS], VCPU_SREG_CS);

	vmx->rmode.vm86_active = 0;

	vmx_segment_cache_clear(vmx);

	vmx_set_segment(vcpu, &vmx->rmode.segs[VCPU_SREG_TR], VCPU_SREG_TR);

	flags = vmcs_readl(GUEST_RFLAGS);
	flags &= RMODE_GUEST_OWNED_EFLAGS_BITS;
	flags |= vmx->rmode.save_rflags & ~RMODE_GUEST_OWNED_EFLAGS_BITS;
	vmcs_writel(GUEST_RFLAGS, flags);

	vmcs_writel(GUEST_CR4, (vmcs_readl(GUEST_CR4) & ~X86_CR4_VME) |
			(vmcs_readl(CR4_READ_SHADOW) & X86_CR4_VME));

	update_exception_bitmap(vcpu);

	fix_pmode_seg(vcpu, VCPU_SREG_CS, &vmx->rmode.segs[VCPU_SREG_CS]);
	fix_pmode_seg(vcpu, VCPU_SREG_SS, &vmx->rmode.segs[VCPU_SREG_SS]);
	fix_pmode_seg(vcpu, VCPU_SREG_ES, &vmx->rmode.segs[VCPU_SREG_ES]);
	fix_pmode_seg(vcpu, VCPU_SREG_DS, &vmx->rmode.segs[VCPU_SREG_DS]);
	fix_pmode_seg(vcpu, VCPU_SREG_FS, &vmx->rmode.segs[VCPU_SREG_FS]);
	fix_pmode_seg(vcpu, VCPU_SREG_GS, &vmx->rmode.segs[VCPU_SREG_GS]);
}

static void fix_rmode_seg(int seg, struct kvm_segment *save)
{
	const struct kvm_vmx_segment_field *sf = &kvm_vmx_segment_fields[seg];
	struct kvm_segment var = *save;

	var.dpl = 0x3;
	if (seg == VCPU_SREG_CS)
		var.type = 0x3;

	if (!emulate_invalid_guest_state) {
		var.selector = var.base >> 4;
		var.base = var.base & 0xffff0;
		var.limit = 0xffff;
		var.g = 0;
		var.db = 0;
		var.present = 1;
		var.s = 1;
		var.l = 0;
		var.unusable = 0;
		var.type = 0x3;
		var.avl = 0;
		if (save->base & 0xf)
			printk_once(KERN_WARNING "kvm: segment base is not "
					"paragraph aligned when entering "
					"protected mode (seg=%d)", seg);
	}

	vmcs_write16(sf->selector, var.selector);
	vmcs_writel(sf->base, var.base);
	vmcs_write32(sf->limit, var.limit);
	vmcs_write32(sf->ar_bytes, vmx_segment_access_rights(&var));
}

static void enter_rmode(struct kvm_vcpu *vcpu)
{
	unsigned long flags;
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	struct kvm_vmx *kvm_vmx = to_kvm_vmx(vcpu->kvm);

	vmx_get_segment(vcpu, &vmx->rmode.segs[VCPU_SREG_TR], VCPU_SREG_TR);
	vmx_get_segment(vcpu, &vmx->rmode.segs[VCPU_SREG_ES], VCPU_SREG_ES);
	vmx_get_segment(vcpu, &vmx->rmode.segs[VCPU_SREG_DS], VCPU_SREG_DS);
	vmx_get_segment(vcpu, &vmx->rmode.segs[VCPU_SREG_FS], VCPU_SREG_FS);
	vmx_get_segment(vcpu, &vmx->rmode.segs[VCPU_SREG_GS], VCPU_SREG_GS);
	vmx_get_segment(vcpu, &vmx->rmode.segs[VCPU_SREG_SS], VCPU_SREG_SS);
	vmx_get_segment(vcpu, &vmx->rmode.segs[VCPU_SREG_CS], VCPU_SREG_CS);

	vmx->rmode.vm86_active = 1;

	/*
	 * Very old userspace does not call KVM_SET_TSS_ADDR before entering
	 * vcpu. Warn the user that an update is overdue.
	 */
	if (!kvm_vmx->tss_addr)
		printk_once(KERN_WARNING "kvm: KVM_SET_TSS_ADDR need to be "
			     "called before entering vcpu\n");

	vmx_segment_cache_clear(vmx);

	vmcs_writel(GUEST_TR_BASE, kvm_vmx->tss_addr);
	vmcs_write32(GUEST_TR_LIMIT, RMODE_TSS_SIZE - 1);
	vmcs_write32(GUEST_TR_AR_BYTES, 0x008b);

	flags = vmcs_readl(GUEST_RFLAGS);
	vmx->rmode.save_rflags = flags;

	flags |= X86_EFLAGS_IOPL | X86_EFLAGS_VM;

	vmcs_writel(GUEST_RFLAGS, flags);
	vmcs_writel(GUEST_CR4, vmcs_readl(GUEST_CR4) | X86_CR4_VME);
	update_exception_bitmap(vcpu);

	fix_rmode_seg(VCPU_SREG_SS, &vmx->rmode.segs[VCPU_SREG_SS]);
	fix_rmode_seg(VCPU_SREG_CS, &vmx->rmode.segs[VCPU_SREG_CS]);
	fix_rmode_seg(VCPU_SREG_ES, &vmx->rmode.segs[VCPU_SREG_ES]);
	fix_rmode_seg(VCPU_SREG_DS, &vmx->rmode.segs[VCPU_SREG_DS]);
	fix_rmode_seg(VCPU_SREG_GS, &vmx->rmode.segs[VCPU_SREG_GS]);
	fix_rmode_seg(VCPU_SREG_FS, &vmx->rmode.segs[VCPU_SREG_FS]);

	kvm_mmu_reset_context(vcpu);
}

static void vmx_set_efer(struct kvm_vcpu *vcpu, u64 efer)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	struct shared_msr_entry *msr = find_msr_entry(vmx, MSR_EFER);

	if (!msr)
		return;

	vcpu->arch.efer = efer;
	if (efer & EFER_LMA) {
		vm_entry_controls_setbit(to_vmx(vcpu), VM_ENTRY_IA32E_MODE);
		msr->data = efer;
	} else {
		vm_entry_controls_clearbit(to_vmx(vcpu), VM_ENTRY_IA32E_MODE);

		msr->data = efer & ~EFER_LME;
	}
	setup_msrs(vmx);
}

#ifdef CONFIG_X86_64

static void enter_lmode(struct kvm_vcpu *vcpu)
{
	u32 guest_tr_ar;

	vmx_segment_cache_clear(to_vmx(vcpu));

	guest_tr_ar = vmcs_read32(GUEST_TR_AR_BYTES);
	if ((guest_tr_ar & VMX_AR_TYPE_MASK) != VMX_AR_TYPE_BUSY_64_TSS) {
		pr_debug_ratelimited("%s: tss fixup for long mode. \n",
				     __func__);
		vmcs_write32(GUEST_TR_AR_BYTES,
			     (guest_tr_ar & ~VMX_AR_TYPE_MASK)
			     | VMX_AR_TYPE_BUSY_64_TSS);
	}
	vmx_set_efer(vcpu, vcpu->arch.efer | EFER_LMA);
}

static void exit_lmode(struct kvm_vcpu *vcpu)
{
	vm_entry_controls_clearbit(to_vmx(vcpu), VM_ENTRY_IA32E_MODE);
	vmx_set_efer(vcpu, vcpu->arch.efer & ~EFER_LMA);
}

#endif

static inline void __vmx_flush_tlb(struct kvm_vcpu *vcpu, int vpid,
				bool invalidate_gpa)
{
	if (enable_ept && (invalidate_gpa || !enable_vpid)) {
		if (!VALID_PAGE(vcpu->arch.mmu.root_hpa))
			return;
		ept_sync_context(construct_eptp(vcpu, vcpu->arch.mmu.root_hpa));
	} else {
		vpid_sync_context(vpid);
	}
}

static void vmx_flush_tlb(struct kvm_vcpu *vcpu, bool invalidate_gpa)
{
	__vmx_flush_tlb(vcpu, to_vmx(vcpu)->vpid, invalidate_gpa);
}

static void vmx_flush_tlb_gva(struct kvm_vcpu *vcpu, gva_t addr)
{
	int vpid = to_vmx(vcpu)->vpid;

	if (!vpid_sync_vcpu_addr(vpid, addr))
		vpid_sync_context(vpid);

	/*
	 * If VPIDs are not supported or enabled, then the above is a no-op.
	 * But we don't really need a TLB flush in that case anyway, because
	 * each VM entry/exit includes an implicit flush when VPID is 0.
	 */
}

static void vmx_decache_cr0_guest_bits(struct kvm_vcpu *vcpu)
{
	ulong cr0_guest_owned_bits = vcpu->arch.cr0_guest_owned_bits;

	vcpu->arch.cr0 &= ~cr0_guest_owned_bits;
	vcpu->arch.cr0 |= vmcs_readl(GUEST_CR0) & cr0_guest_owned_bits;
}

static void vmx_decache_cr3(struct kvm_vcpu *vcpu)
{
	if (enable_unrestricted_guest || (enable_ept && is_paging(vcpu)))
		vcpu->arch.cr3 = vmcs_readl(GUEST_CR3);
	__set_bit(VCPU_EXREG_CR3, (ulong *)&vcpu->arch.regs_avail);
}

static void vmx_decache_cr4_guest_bits(struct kvm_vcpu *vcpu)
{
	ulong cr4_guest_owned_bits = vcpu->arch.cr4_guest_owned_bits;

	vcpu->arch.cr4 &= ~cr4_guest_owned_bits;
	vcpu->arch.cr4 |= vmcs_readl(GUEST_CR4) & cr4_guest_owned_bits;
}

static void ept_load_pdptrs(struct kvm_vcpu *vcpu)
{
	struct kvm_mmu *mmu = vcpu->arch.walk_mmu;

	if (!test_bit(VCPU_EXREG_PDPTR,
		      (unsigned long *)&vcpu->arch.regs_dirty))
		return;

	if (is_pae_paging(vcpu)) {
		vmcs_write64(GUEST_PDPTR0, mmu->pdptrs[0]);
		vmcs_write64(GUEST_PDPTR1, mmu->pdptrs[1]);
		vmcs_write64(GUEST_PDPTR2, mmu->pdptrs[2]);
		vmcs_write64(GUEST_PDPTR3, mmu->pdptrs[3]);
	}
}

static void ept_save_pdptrs(struct kvm_vcpu *vcpu)
{
	struct kvm_mmu *mmu = vcpu->arch.walk_mmu;

	if (is_pae_paging(vcpu)) {
		mmu->pdptrs[0] = vmcs_read64(GUEST_PDPTR0);
		mmu->pdptrs[1] = vmcs_read64(GUEST_PDPTR1);
		mmu->pdptrs[2] = vmcs_read64(GUEST_PDPTR2);
		mmu->pdptrs[3] = vmcs_read64(GUEST_PDPTR3);
	}

	__set_bit(VCPU_EXREG_PDPTR,
		  (unsigned long *)&vcpu->arch.regs_avail);
	__set_bit(VCPU_EXREG_PDPTR,
		  (unsigned long *)&vcpu->arch.regs_dirty);
}

static bool nested_guest_cr0_valid(struct kvm_vcpu *vcpu, unsigned long val)
{
	u64 fixed0 = to_vmx(vcpu)->nested.msrs.cr0_fixed0;
	u64 fixed1 = to_vmx(vcpu)->nested.msrs.cr0_fixed1;
	struct vmcs12 *vmcs12 = get_vmcs12(vcpu);

	if (to_vmx(vcpu)->nested.msrs.secondary_ctls_high &
		SECONDARY_EXEC_UNRESTRICTED_GUEST &&
	    nested_cpu_has2(vmcs12, SECONDARY_EXEC_UNRESTRICTED_GUEST))
		fixed0 &= ~(X86_CR0_PE | X86_CR0_PG);

	return fixed_bits_valid(val, fixed0, fixed1);
}

static bool nested_host_cr0_valid(struct kvm_vcpu *vcpu, unsigned long val)
{
	u64 fixed0 = to_vmx(vcpu)->nested.msrs.cr0_fixed0;
	u64 fixed1 = to_vmx(vcpu)->nested.msrs.cr0_fixed1;

	return fixed_bits_valid(val, fixed0, fixed1);
}

static bool nested_cr4_valid(struct kvm_vcpu *vcpu, unsigned long val)
{
	u64 fixed0 = to_vmx(vcpu)->nested.msrs.cr4_fixed0;
	u64 fixed1 = to_vmx(vcpu)->nested.msrs.cr4_fixed1;

	return fixed_bits_valid(val, fixed0, fixed1);
}

/* No difference in the restrictions on guest and host CR4 in VMX operation. */
#define nested_guest_cr4_valid	nested_cr4_valid
#define nested_host_cr4_valid	nested_cr4_valid

static int vmx_set_cr4(struct kvm_vcpu *vcpu, unsigned long cr4);

static void ept_update_paging_mode_cr0(unsigned long *hw_cr0,
					unsigned long cr0,
					struct kvm_vcpu *vcpu)
{
	if (!test_bit(VCPU_EXREG_CR3, (ulong *)&vcpu->arch.regs_avail))
		vmx_decache_cr3(vcpu);
	if (!(cr0 & X86_CR0_PG)) {
		/* From paging/starting to nonpaging */
		vmcs_write32(CPU_BASED_VM_EXEC_CONTROL,
			     vmcs_read32(CPU_BASED_VM_EXEC_CONTROL) |
			     (CPU_BASED_CR3_LOAD_EXITING |
			      CPU_BASED_CR3_STORE_EXITING));
		vcpu->arch.cr0 = cr0;
		vmx_set_cr4(vcpu, kvm_read_cr4(vcpu));
	} else if (!is_paging(vcpu)) {
		/* From nonpaging to paging */
		vmcs_write32(CPU_BASED_VM_EXEC_CONTROL,
			     vmcs_read32(CPU_BASED_VM_EXEC_CONTROL) &
			     ~(CPU_BASED_CR3_LOAD_EXITING |
			       CPU_BASED_CR3_STORE_EXITING));
		vcpu->arch.cr0 = cr0;
		vmx_set_cr4(vcpu, kvm_read_cr4(vcpu));
	}

	if (!(cr0 & X86_CR0_WP))
		*hw_cr0 &= ~X86_CR0_WP;
}

static void vmx_set_cr0(struct kvm_vcpu *vcpu, unsigned long cr0)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	unsigned long hw_cr0;

	hw_cr0 = (cr0 & ~KVM_GUEST_CR0_MASK);
	if (enable_unrestricted_guest)
		hw_cr0 |= KVM_VM_CR0_ALWAYS_ON_UNRESTRICTED_GUEST;
	else {
		hw_cr0 |= KVM_VM_CR0_ALWAYS_ON;

		if (vmx->rmode.vm86_active && (cr0 & X86_CR0_PE))
			enter_pmode(vcpu);

		if (!vmx->rmode.vm86_active && !(cr0 & X86_CR0_PE))
			enter_rmode(vcpu);
	}

#ifdef CONFIG_X86_64
	if (vcpu->arch.efer & EFER_LME) {
		if (!is_paging(vcpu) && (cr0 & X86_CR0_PG))
			enter_lmode(vcpu);
		if (is_paging(vcpu) && !(cr0 & X86_CR0_PG))
			exit_lmode(vcpu);
	}
#endif

	if (enable_ept && !enable_unrestricted_guest)
		ept_update_paging_mode_cr0(&hw_cr0, cr0, vcpu);

	vmcs_writel(CR0_READ_SHADOW, cr0);
	vmcs_writel(GUEST_CR0, hw_cr0);
	vcpu->arch.cr0 = cr0;

	/* depends on vcpu->arch.cr0 to be set to a new value */
	vmx->emulation_required = emulation_required(vcpu);
}

static int get_ept_level(struct kvm_vcpu *vcpu)
{
	/* Nested EPT currently only supports 4-level walks. */
	if (is_guest_mode(vcpu) && nested_cpu_has_ept(get_vmcs12(vcpu)))
		return 4;
	if (cpu_has_vmx_ept_5levels() && (cpuid_maxphyaddr(vcpu) > 48))
		return 5;
	return 4;
}

static u64 construct_eptp(struct kvm_vcpu *vcpu, unsigned long root_hpa)
{
	u64 eptp = VMX_EPTP_MT_WB;

	eptp |= (get_ept_level(vcpu) == 5) ? VMX_EPTP_PWL_5 : VMX_EPTP_PWL_4;

	if (enable_ept_ad_bits &&
	    (!is_guest_mode(vcpu) || nested_ept_ad_enabled(vcpu)))
		eptp |= VMX_EPTP_AD_ENABLE_BIT;
	eptp |= (root_hpa & PAGE_MASK);

	return eptp;
}

static void vmx_set_cr3(struct kvm_vcpu *vcpu, unsigned long cr3)
{
	struct kvm *kvm = vcpu->kvm;
	unsigned long guest_cr3;
	u64 eptp;

	guest_cr3 = cr3;
	if (enable_ept) {
		eptp = construct_eptp(vcpu, cr3);
		vmcs_write64(EPT_POINTER, eptp);

		if (kvm_x86_ops->tlb_remote_flush) {
			spin_lock(&to_kvm_vmx(kvm)->ept_pointer_lock);
			to_vmx(vcpu)->ept_pointer = eptp;
			to_kvm_vmx(kvm)->ept_pointers_match
				= EPT_POINTERS_CHECK;
			spin_unlock(&to_kvm_vmx(kvm)->ept_pointer_lock);
		}

		if (enable_unrestricted_guest || is_paging(vcpu) ||
		    is_guest_mode(vcpu))
			guest_cr3 = kvm_read_cr3(vcpu);
		else
			guest_cr3 = to_kvm_vmx(kvm)->ept_identity_map_addr;
		ept_load_pdptrs(vcpu);
	}

	vmcs_writel(GUEST_CR3, guest_cr3);
}

static int vmx_set_cr4(struct kvm_vcpu *vcpu, unsigned long cr4)
{
	/*
	 * Pass through host's Machine Check Enable value to hw_cr4, which
	 * is in force while we are in guest mode.  Do not let guests control
	 * this bit, even if host CR4.MCE == 0.
	 */
	unsigned long hw_cr4;

	hw_cr4 = (cr4_read_shadow() & X86_CR4_MCE) | (cr4 & ~X86_CR4_MCE);
	if (enable_unrestricted_guest)
		hw_cr4 |= KVM_VM_CR4_ALWAYS_ON_UNRESTRICTED_GUEST;
	else if (to_vmx(vcpu)->rmode.vm86_active)
		hw_cr4 |= KVM_RMODE_VM_CR4_ALWAYS_ON;
	else
		hw_cr4 |= KVM_PMODE_VM_CR4_ALWAYS_ON;

	if (!boot_cpu_has(X86_FEATURE_UMIP) && vmx_umip_emulated()) {
		if (cr4 & X86_CR4_UMIP) {
			vmcs_set_bits(SECONDARY_VM_EXEC_CONTROL,
				SECONDARY_EXEC_DESC);
			hw_cr4 &= ~X86_CR4_UMIP;
		} else if (!is_guest_mode(vcpu) ||
			!nested_cpu_has2(get_vmcs12(vcpu), SECONDARY_EXEC_DESC))
			vmcs_clear_bits(SECONDARY_VM_EXEC_CONTROL,
					SECONDARY_EXEC_DESC);
	}

	if (cr4 & X86_CR4_VMXE) {
		/*
		 * To use VMXON (and later other VMX instructions), a guest
		 * must first be able to turn on cr4.VMXE (see handle_vmon()).
		 * So basically the check on whether to allow nested VMX
		 * is here.  We operate under the default treatment of SMM,
		 * so VMX cannot be enabled under SMM.
		 */
		if (!nested_vmx_allowed(vcpu) || is_smm(vcpu))
			return 1;
	}

	if (to_vmx(vcpu)->nested.vmxon && !nested_cr4_valid(vcpu, cr4))
		return 1;

	vcpu->arch.cr4 = cr4;

	if (!enable_unrestricted_guest) {
		if (enable_ept) {
			if (!is_paging(vcpu)) {
				hw_cr4 &= ~X86_CR4_PAE;
				hw_cr4 |= X86_CR4_PSE;
			} else if (!(cr4 & X86_CR4_PAE)) {
				hw_cr4 &= ~X86_CR4_PAE;
			}
		}

		/*
		 * SMEP/SMAP/PKU is disabled if CPU is in non-paging mode in
		 * hardware.  To emulate this behavior, SMEP/SMAP/PKU needs
		 * to be manually disabled when guest switches to non-paging
		 * mode.
		 *
		 * If !enable_unrestricted_guest, the CPU is always running
		 * with CR0.PG=1 and CR4 needs to be modified.
		 * If enable_unrestricted_guest, the CPU automatically
		 * disables SMEP/SMAP/PKU when the guest sets CR0.PG=0.
		 */
		if (!is_paging(vcpu))
			hw_cr4 &= ~(X86_CR4_SMEP | X86_CR4_SMAP | X86_CR4_PKE);
	}

	vmcs_writel(CR4_READ_SHADOW, cr4);
	vmcs_writel(GUEST_CR4, hw_cr4);
	return 0;
}

static void vmx_get_segment(struct kvm_vcpu *vcpu,
			    struct kvm_segment *var, int seg)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	u32 ar;

	if (vmx->rmode.vm86_active && seg != VCPU_SREG_LDTR) {
		*var = vmx->rmode.segs[seg];
		if (seg == VCPU_SREG_TR
		    || var->selector == vmx_read_guest_seg_selector(vmx, seg))
			return;
		var->base = vmx_read_guest_seg_base(vmx, seg);
		var->selector = vmx_read_guest_seg_selector(vmx, seg);
		return;
	}
	var->base = vmx_read_guest_seg_base(vmx, seg);
	var->limit = vmx_read_guest_seg_limit(vmx, seg);
	var->selector = vmx_read_guest_seg_selector(vmx, seg);
	ar = vmx_read_guest_seg_ar(vmx, seg);
	var->unusable = (ar >> 16) & 1;
	var->type = ar & 15;
	var->s = (ar >> 4) & 1;
	var->dpl = (ar >> 5) & 3;
	/*
	 * Some userspaces do not preserve unusable property. Since usable
	 * segment has to be present according to VMX spec we can use present
	 * property to amend userspace bug by making unusable segment always
	 * nonpresent. vmx_segment_access_rights() already marks nonpresent
	 * segment as unusable.
	 */
	var->present = !var->unusable;
	var->avl = (ar >> 12) & 1;
	var->l = (ar >> 13) & 1;
	var->db = (ar >> 14) & 1;
	var->g = (ar >> 15) & 1;
}

static u64 vmx_get_segment_base(struct kvm_vcpu *vcpu, int seg)
{
	struct kvm_segment s;

	if (to_vmx(vcpu)->rmode.vm86_active) {
		vmx_get_segment(vcpu, &s, seg);
		return s.base;
	}
	return vmx_read_guest_seg_base(to_vmx(vcpu), seg);
}

static int vmx_get_cpl(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);

	if (unlikely(vmx->rmode.vm86_active))
		return 0;
	else {
		int ar = vmx_read_guest_seg_ar(vmx, VCPU_SREG_SS);
		return VMX_AR_DPL(ar);
	}
}

static u32 vmx_segment_access_rights(struct kvm_segment *var)
{
	u32 ar;

	ar = var->type & 15;
	ar |= (var->s & 1) << 4;
	ar |= (var->dpl & 3) << 5;
	ar |= (var->present & 1) << 7;
	ar |= (var->avl & 1) << 12;
	ar |= (var->l & 1) << 13;
	ar |= (var->db & 1) << 14;
	ar |= (var->g & 1) << 15;
	ar |= (var->unusable || !var->present) << 16;

	return ar;
}

static void vmx_set_segment(struct kvm_vcpu *vcpu,
			    struct kvm_segment *var, int seg)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	const struct kvm_vmx_segment_field *sf = &kvm_vmx_segment_fields[seg];

	vmx_segment_cache_clear(vmx);

	if (vmx->rmode.vm86_active && seg != VCPU_SREG_LDTR) {
		vmx->rmode.segs[seg] = *var;
		if (seg == VCPU_SREG_TR)
			vmcs_write16(sf->selector, var->selector);
		else if (var->s)
			fix_rmode_seg(seg, &vmx->rmode.segs[seg]);
		goto out;
	}

	vmcs_writel(sf->base, var->base);
	vmcs_write32(sf->limit, var->limit);
	vmcs_write16(sf->selector, var->selector);

	/*
	 *   Fix the "Accessed" bit in AR field of segment registers for older
	 * qemu binaries.
	 *   IA32 arch specifies that at the time of processor reset the
	 * "Accessed" bit in the AR field of segment registers is 1. And qemu
	 * is setting it to 0 in the userland code. This causes invalid guest
	 * state vmexit when "unrestricted guest" mode is turned on.
	 *    Fix for this setup issue in cpu_reset is being pushed in the qemu
	 * tree. Newer qemu binaries with that qemu fix would not need this
	 * kvm hack.
	 */
	if (enable_unrestricted_guest && (seg != VCPU_SREG_LDTR))
		var->type |= 0x1; /* Accessed */

	vmcs_write32(sf->ar_bytes, vmx_segment_access_rights(var));

out:
	vmx->emulation_required = emulation_required(vcpu);
}

static void vmx_get_cs_db_l_bits(struct kvm_vcpu *vcpu, int *db, int *l)
{
	u32 ar = vmx_read_guest_seg_ar(to_vmx(vcpu), VCPU_SREG_CS);

	*db = (ar >> 14) & 1;
	*l = (ar >> 13) & 1;
}

static void vmx_get_idt(struct kvm_vcpu *vcpu, struct desc_ptr *dt)
{
	dt->size = vmcs_read32(GUEST_IDTR_LIMIT);
	dt->address = vmcs_readl(GUEST_IDTR_BASE);
}

static void vmx_set_idt(struct kvm_vcpu *vcpu, struct desc_ptr *dt)
{
	vmcs_write32(GUEST_IDTR_LIMIT, dt->size);
	vmcs_writel(GUEST_IDTR_BASE, dt->address);
}

static void vmx_get_gdt(struct kvm_vcpu *vcpu, struct desc_ptr *dt)
{
	dt->size = vmcs_read32(GUEST_GDTR_LIMIT);
	dt->address = vmcs_readl(GUEST_GDTR_BASE);
}

static void vmx_set_gdt(struct kvm_vcpu *vcpu, struct desc_ptr *dt)
{
	vmcs_write32(GUEST_GDTR_LIMIT, dt->size);
	vmcs_writel(GUEST_GDTR_BASE, dt->address);
}

static bool rmode_segment_valid(struct kvm_vcpu *vcpu, int seg)
{
	struct kvm_segment var;
	u32 ar;

	vmx_get_segment(vcpu, &var, seg);
	var.dpl = 0x3;
	if (seg == VCPU_SREG_CS)
		var.type = 0x3;
	ar = vmx_segment_access_rights(&var);

	if (var.base != (var.selector << 4))
		return false;
	if (var.limit != 0xffff)
		return false;
	if (ar != 0xf3)
		return false;

	return true;
}

static bool code_segment_valid(struct kvm_vcpu *vcpu)
{
	struct kvm_segment cs;
	unsigned int cs_rpl;

	vmx_get_segment(vcpu, &cs, VCPU_SREG_CS);
	cs_rpl = cs.selector & SEGMENT_RPL_MASK;

	if (cs.unusable)
		return false;
	if (~cs.type & (VMX_AR_TYPE_CODE_MASK|VMX_AR_TYPE_ACCESSES_MASK))
		return false;
	if (!cs.s)
		return false;
	if (cs.type & VMX_AR_TYPE_WRITEABLE_MASK) {
		if (cs.dpl > cs_rpl)
			return false;
	} else {
		if (cs.dpl != cs_rpl)
			return false;
	}
	if (!cs.present)
		return false;

	/* TODO: Add Reserved field check, this'll require a new member in the kvm_segment_field structure */
	return true;
}

static bool stack_segment_valid(struct kvm_vcpu *vcpu)
{
	struct kvm_segment ss;
	unsigned int ss_rpl;

	vmx_get_segment(vcpu, &ss, VCPU_SREG_SS);
	ss_rpl = ss.selector & SEGMENT_RPL_MASK;

	if (ss.unusable)
		return true;
	if (ss.type != 3 && ss.type != 7)
		return false;
	if (!ss.s)
		return false;
	if (ss.dpl != ss_rpl) /* DPL != RPL */
		return false;
	if (!ss.present)
		return false;

	return true;
}

static bool data_segment_valid(struct kvm_vcpu *vcpu, int seg)
{
	struct kvm_segment var;
	unsigned int rpl;

	vmx_get_segment(vcpu, &var, seg);
	rpl = var.selector & SEGMENT_RPL_MASK;

	if (var.unusable)
		return true;
	if (!var.s)
		return false;
	if (!var.present)
		return false;
	if (~var.type & (VMX_AR_TYPE_CODE_MASK|VMX_AR_TYPE_WRITEABLE_MASK)) {
		if (var.dpl < rpl) /* DPL < RPL */
			return false;
	}

	/* TODO: Add other members to kvm_segment_field to allow checking for other access
	 * rights flags
	 */
	return true;
}

static bool tr_valid(struct kvm_vcpu *vcpu)
{
	struct kvm_segment tr;

	vmx_get_segment(vcpu, &tr, VCPU_SREG_TR);

	if (tr.unusable)
		return false;
	if (tr.selector & SEGMENT_TI_MASK)	/* TI = 1 */
		return false;
	if (tr.type != 3 && tr.type != 11) /* TODO: Check if guest is in IA32e mode */
		return false;
	if (!tr.present)
		return false;

	return true;
}

static bool ldtr_valid(struct kvm_vcpu *vcpu)
{
	struct kvm_segment ldtr;

	vmx_get_segment(vcpu, &ldtr, VCPU_SREG_LDTR);

	if (ldtr.unusable)
		return true;
	if (ldtr.selector & SEGMENT_TI_MASK)	/* TI = 1 */
		return false;
	if (ldtr.type != 2)
		return false;
	if (!ldtr.present)
		return false;

	return true;
}

static bool cs_ss_rpl_check(struct kvm_vcpu *vcpu)
{
	struct kvm_segment cs, ss;

	vmx_get_segment(vcpu, &cs, VCPU_SREG_CS);
	vmx_get_segment(vcpu, &ss, VCPU_SREG_SS);

	return ((cs.selector & SEGMENT_RPL_MASK) ==
		 (ss.selector & SEGMENT_RPL_MASK));
}

static bool nested_vmx_check_io_bitmaps(struct kvm_vcpu *vcpu,
					unsigned int port, int size);
static bool nested_vmx_exit_handled_io(struct kvm_vcpu *vcpu,
				       struct vmcs12 *vmcs12)
{
	unsigned long exit_qualification;
	unsigned short port;
	int size;

	if (!nested_cpu_has(vmcs12, CPU_BASED_USE_IO_BITMAPS))
		return nested_cpu_has(vmcs12, CPU_BASED_UNCOND_IO_EXITING);

	exit_qualification = vmcs_readl(EXIT_QUALIFICATION);

	port = exit_qualification >> 16;
	size = (exit_qualification & 7) + 1;

	return nested_vmx_check_io_bitmaps(vcpu, port, size);
}

/*
 * Check if guest state is valid. Returns true if valid, false if
 * not.
 * We assume that registers are always usable
 */
static bool guest_state_valid(struct kvm_vcpu *vcpu)
{
	if (enable_unrestricted_guest)
		return true;

	/* real mode guest state checks */
	if (!is_protmode(vcpu) || (vmx_get_rflags(vcpu) & X86_EFLAGS_VM)) {
		if (!rmode_segment_valid(vcpu, VCPU_SREG_CS))
			return false;
		if (!rmode_segment_valid(vcpu, VCPU_SREG_SS))
			return false;
		if (!rmode_segment_valid(vcpu, VCPU_SREG_DS))
			return false;
		if (!rmode_segment_valid(vcpu, VCPU_SREG_ES))
			return false;
		if (!rmode_segment_valid(vcpu, VCPU_SREG_FS))
			return false;
		if (!rmode_segment_valid(vcpu, VCPU_SREG_GS))
			return false;
	} else {
	/* protected mode guest state checks */
		if (!cs_ss_rpl_check(vcpu))
			return false;
		if (!code_segment_valid(vcpu))
			return false;
		if (!stack_segment_valid(vcpu))
			return false;
		if (!data_segment_valid(vcpu, VCPU_SREG_DS))
			return false;
		if (!data_segment_valid(vcpu, VCPU_SREG_ES))
			return false;
		if (!data_segment_valid(vcpu, VCPU_SREG_FS))
			return false;
		if (!data_segment_valid(vcpu, VCPU_SREG_GS))
			return false;
		if (!tr_valid(vcpu))
			return false;
		if (!ldtr_valid(vcpu))
			return false;
	}
	/* TODO:
	 * - Add checks on RIP
	 * - Add checks on RFLAGS
	 */

	return true;
}

static bool page_address_valid(struct kvm_vcpu *vcpu, gpa_t gpa)
{
	return PAGE_ALIGNED(gpa) && !(gpa >> cpuid_maxphyaddr(vcpu));
}

static int init_rmode_tss(struct kvm *kvm)
{
	gfn_t fn;
	u16 data = 0;
	int idx, r;

	idx = srcu_read_lock(&kvm->srcu);
	fn = to_kvm_vmx(kvm)->tss_addr >> PAGE_SHIFT;
	r = kvm_clear_guest_page(kvm, fn, 0, PAGE_SIZE);
	if (r < 0)
		goto out;
	data = TSS_BASE_SIZE + TSS_REDIRECTION_SIZE;
	r = kvm_write_guest_page(kvm, fn++, &data,
			TSS_IOPB_BASE_OFFSET, sizeof(u16));
	if (r < 0)
		goto out;
	r = kvm_clear_guest_page(kvm, fn++, 0, PAGE_SIZE);
	if (r < 0)
		goto out;
	r = kvm_clear_guest_page(kvm, fn, 0, PAGE_SIZE);
	if (r < 0)
		goto out;
	data = ~0;
	r = kvm_write_guest_page(kvm, fn, &data,
				 RMODE_TSS_SIZE - 2 * PAGE_SIZE - 1,
				 sizeof(u8));
out:
	srcu_read_unlock(&kvm->srcu, idx);
	return r;
}

static int init_rmode_identity_map(struct kvm *kvm)
{
	struct kvm_vmx *kvm_vmx = to_kvm_vmx(kvm);
	int i, idx, r = 0;
	kvm_pfn_t identity_map_pfn;
	u32 tmp;

	/* Protect kvm_vmx->ept_identity_pagetable_done. */
	mutex_lock(&kvm->slots_lock);

	if (likely(kvm_vmx->ept_identity_pagetable_done))
		goto out2;

	if (!kvm_vmx->ept_identity_map_addr)
		kvm_vmx->ept_identity_map_addr = VMX_EPT_IDENTITY_PAGETABLE_ADDR;
	identity_map_pfn = kvm_vmx->ept_identity_map_addr >> PAGE_SHIFT;

	r = __x86_set_memory_region(kvm, IDENTITY_PAGETABLE_PRIVATE_MEMSLOT,
				    kvm_vmx->ept_identity_map_addr, PAGE_SIZE);
	if (r < 0)
		goto out2;

	idx = srcu_read_lock(&kvm->srcu);
	r = kvm_clear_guest_page(kvm, identity_map_pfn, 0, PAGE_SIZE);
	if (r < 0)
		goto out;
	/* Set up identity-mapping pagetable for EPT in real mode */
	for (i = 0; i < PT32_ENT_PER_PAGE; i++) {
		tmp = (i << 22) + (_PAGE_PRESENT | _PAGE_RW | _PAGE_USER |
			_PAGE_ACCESSED | _PAGE_DIRTY | _PAGE_PSE);
		r = kvm_write_guest_page(kvm, identity_map_pfn,
				&tmp, i * sizeof(tmp), sizeof(tmp));
		if (r < 0)
			goto out;
	}
	kvm_vmx->ept_identity_pagetable_done = true;

out:
	srcu_read_unlock(&kvm->srcu, idx);

out2:
	mutex_unlock(&kvm->slots_lock);
	return r;
}

static void seg_setup(int seg)
{
	const struct kvm_vmx_segment_field *sf = &kvm_vmx_segment_fields[seg];
	unsigned int ar;

	vmcs_write16(sf->selector, 0);
	vmcs_writel(sf->base, 0);
	vmcs_write32(sf->limit, 0xffff);
	ar = 0x93;
	if (seg == VCPU_SREG_CS)
		ar |= 0x08; /* code segment */

	vmcs_write32(sf->ar_bytes, ar);
}

static int alloc_apic_access_page(struct kvm *kvm)
{
	struct page *page;
	int r = 0;

	mutex_lock(&kvm->slots_lock);
	if (kvm->arch.apic_access_page_done)
		goto out;
	r = __x86_set_memory_region(kvm, APIC_ACCESS_PAGE_PRIVATE_MEMSLOT,
				    APIC_DEFAULT_PHYS_BASE, PAGE_SIZE);
	if (r)
		goto out;

	page = gfn_to_page(kvm, APIC_DEFAULT_PHYS_BASE >> PAGE_SHIFT);
	if (is_error_page(page)) {
		r = -EFAULT;
		goto out;
	}

	/*
	 * Do not pin the page in memory, so that memory hot-unplug
	 * is able to migrate it.
	 */
	put_page(page);
	kvm->arch.apic_access_page_done = true;
out:
	mutex_unlock(&kvm->slots_lock);
	return r;
}

static int allocate_vpid(void)
{
	int vpid;

	if (!enable_vpid)
		return 0;
	spin_lock(&vmx_vpid_lock);
	vpid = find_first_zero_bit(vmx_vpid_bitmap, VMX_NR_VPIDS);
	if (vpid < VMX_NR_VPIDS)
		__set_bit(vpid, vmx_vpid_bitmap);
	else
		vpid = 0;
	spin_unlock(&vmx_vpid_lock);
	return vpid;
}

static void free_vpid(int vpid)
{
	if (!enable_vpid || vpid == 0)
		return;
	spin_lock(&vmx_vpid_lock);
	__clear_bit(vpid, vmx_vpid_bitmap);
	spin_unlock(&vmx_vpid_lock);
}

static __always_inline void vmx_disable_intercept_for_msr(unsigned long *msr_bitmap,
							  u32 msr, int type)
{
	int f = sizeof(unsigned long);

	if (!cpu_has_vmx_msr_bitmap())
		return;

	if (static_branch_unlikely(&enable_evmcs))
		evmcs_touch_msr_bitmap();

	/*
	 * See Intel PRM Vol. 3, 20.6.9 (MSR-Bitmap Address). Early manuals
	 * have the write-low and read-high bitmap offsets the wrong way round.
	 * We can control MSRs 0x00000000-0x00001fff and 0xc0000000-0xc0001fff.
	 */
	if (msr <= 0x1fff) {
		if (type & MSR_TYPE_R)
			/* read-low */
			__clear_bit(msr, msr_bitmap + 0x000 / f);

		if (type & MSR_TYPE_W)
			/* write-low */
			__clear_bit(msr, msr_bitmap + 0x800 / f);

	} else if ((msr >= 0xc0000000) && (msr <= 0xc0001fff)) {
		msr &= 0x1fff;
		if (type & MSR_TYPE_R)
			/* read-high */
			__clear_bit(msr, msr_bitmap + 0x400 / f);

		if (type & MSR_TYPE_W)
			/* write-high */
			__clear_bit(msr, msr_bitmap + 0xc00 / f);

	}
}

static __always_inline void vmx_enable_intercept_for_msr(unsigned long *msr_bitmap,
							 u32 msr, int type)
{
	int f = sizeof(unsigned long);

	if (!cpu_has_vmx_msr_bitmap())
		return;

	if (static_branch_unlikely(&enable_evmcs))
		evmcs_touch_msr_bitmap();

	/*
	 * See Intel PRM Vol. 3, 20.6.9 (MSR-Bitmap Address). Early manuals
	 * have the write-low and read-high bitmap offsets the wrong way round.
	 * We can control MSRs 0x00000000-0x00001fff and 0xc0000000-0xc0001fff.
	 */
	if (msr <= 0x1fff) {
		if (type & MSR_TYPE_R)
			/* read-low */
			__set_bit(msr, msr_bitmap + 0x000 / f);

		if (type & MSR_TYPE_W)
			/* write-low */
			__set_bit(msr, msr_bitmap + 0x800 / f);

	} else if ((msr >= 0xc0000000) && (msr <= 0xc0001fff)) {
		msr &= 0x1fff;
		if (type & MSR_TYPE_R)
			/* read-high */
			__set_bit(msr, msr_bitmap + 0x400 / f);

		if (type & MSR_TYPE_W)
			/* write-high */
			__set_bit(msr, msr_bitmap + 0xc00 / f);

	}
}

static __always_inline void vmx_set_intercept_for_msr(unsigned long *msr_bitmap,
			     			      u32 msr, int type, bool value)
{
	if (value)
		vmx_enable_intercept_for_msr(msr_bitmap, msr, type);
	else
		vmx_disable_intercept_for_msr(msr_bitmap, msr, type);
}

/*
 * If a msr is allowed by L0, we should check whether it is allowed by L1.
 * The corresponding bit will be cleared unless both of L0 and L1 allow it.
 */
static void nested_vmx_disable_intercept_for_msr(unsigned long *msr_bitmap_l1,
					       unsigned long *msr_bitmap_nested,
					       u32 msr, int type)
{
	int f = sizeof(unsigned long);

	/*
	 * See Intel PRM Vol. 3, 20.6.9 (MSR-Bitmap Address). Early manuals
	 * have the write-low and read-high bitmap offsets the wrong way round.
	 * We can control MSRs 0x00000000-0x00001fff and 0xc0000000-0xc0001fff.
	 */
	if (msr <= 0x1fff) {
		if (type & MSR_TYPE_R &&
		   !test_bit(msr, msr_bitmap_l1 + 0x000 / f))
			/* read-low */
			__clear_bit(msr, msr_bitmap_nested + 0x000 / f);

		if (type & MSR_TYPE_W &&
		   !test_bit(msr, msr_bitmap_l1 + 0x800 / f))
			/* write-low */
			__clear_bit(msr, msr_bitmap_nested + 0x800 / f);

	} else if ((msr >= 0xc0000000) && (msr <= 0xc0001fff)) {
		msr &= 0x1fff;
		if (type & MSR_TYPE_R &&
		   !test_bit(msr, msr_bitmap_l1 + 0x400 / f))
			/* read-high */
			__clear_bit(msr, msr_bitmap_nested + 0x400 / f);

		if (type & MSR_TYPE_W &&
		   !test_bit(msr, msr_bitmap_l1 + 0xc00 / f))
			/* write-high */
			__clear_bit(msr, msr_bitmap_nested + 0xc00 / f);

	}
}

static u8 vmx_msr_bitmap_mode(struct kvm_vcpu *vcpu)
{
	u8 mode = 0;

	if (cpu_has_secondary_exec_ctrls() &&
	    (vmcs_read32(SECONDARY_VM_EXEC_CONTROL) &
	     SECONDARY_EXEC_VIRTUALIZE_X2APIC_MODE)) {
		mode |= MSR_BITMAP_MODE_X2APIC;
		if (enable_apicv && kvm_vcpu_apicv_active(vcpu))
			mode |= MSR_BITMAP_MODE_X2APIC_APICV;
	}

	return mode;
}

#define X2APIC_MSR(r) (APIC_BASE_MSR + ((r) >> 4))

static void vmx_update_msr_bitmap_x2apic(unsigned long *msr_bitmap,
					 u8 mode)
{
	int msr;

	for (msr = 0x800; msr <= 0x8ff; msr += BITS_PER_LONG) {
		unsigned word = msr / BITS_PER_LONG;
		msr_bitmap[word] = (mode & MSR_BITMAP_MODE_X2APIC_APICV) ? 0 : ~0;
		msr_bitmap[word + (0x800 / sizeof(long))] = ~0;
	}

	if (mode & MSR_BITMAP_MODE_X2APIC) {
		/*
		 * TPR reads and writes can be virtualized even if virtual interrupt
		 * delivery is not in use.
		 */
		vmx_disable_intercept_for_msr(msr_bitmap, X2APIC_MSR(APIC_TASKPRI), MSR_TYPE_RW);
		if (mode & MSR_BITMAP_MODE_X2APIC_APICV) {
			vmx_enable_intercept_for_msr(msr_bitmap, X2APIC_MSR(APIC_TMCCT), MSR_TYPE_R);
			vmx_disable_intercept_for_msr(msr_bitmap, X2APIC_MSR(APIC_EOI), MSR_TYPE_W);
			vmx_disable_intercept_for_msr(msr_bitmap, X2APIC_MSR(APIC_SELF_IPI), MSR_TYPE_W);
		}
	}
}

static void vmx_update_msr_bitmap(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	unsigned long *msr_bitmap = vmx->vmcs01.msr_bitmap;
	u8 mode = vmx_msr_bitmap_mode(vcpu);
	u8 changed = mode ^ vmx->msr_bitmap_mode;

	if (!changed)
		return;

	if (changed & (MSR_BITMAP_MODE_X2APIC | MSR_BITMAP_MODE_X2APIC_APICV))
		vmx_update_msr_bitmap_x2apic(msr_bitmap, mode);

	vmx->msr_bitmap_mode = mode;
}

static bool vmx_get_enable_apicv(struct kvm_vcpu *vcpu)
{
	return enable_apicv;
}

static void nested_mark_vmcs12_pages_dirty(struct kvm_vcpu *vcpu)
{
	struct vmcs12 *vmcs12 = get_vmcs12(vcpu);
	gfn_t gfn;

	/*
	 * Don't need to mark the APIC access page dirty; it is never
	 * written to by the CPU during APIC virtualization.
	 */

	if (nested_cpu_has(vmcs12, CPU_BASED_TPR_SHADOW)) {
		gfn = vmcs12->virtual_apic_page_addr >> PAGE_SHIFT;
		kvm_vcpu_mark_page_dirty(vcpu, gfn);
	}

	if (nested_cpu_has_posted_intr(vmcs12)) {
		gfn = vmcs12->posted_intr_desc_addr >> PAGE_SHIFT;
		kvm_vcpu_mark_page_dirty(vcpu, gfn);
	}
}


static void vmx_complete_nested_posted_interrupt(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	int max_irr;
	void *vapic_page;
	u16 status;

	if (!vmx->nested.pi_desc || !vmx->nested.pi_pending)
		return;

	vmx->nested.pi_pending = false;
	if (!pi_test_and_clear_on(vmx->nested.pi_desc))
		return;

	max_irr = find_last_bit((unsigned long *)vmx->nested.pi_desc->pir, 256);
	if (max_irr != 256) {
		vapic_page = kmap(vmx->nested.virtual_apic_page);
		__kvm_apic_update_irr(vmx->nested.pi_desc->pir,
			vapic_page, &max_irr);
		kunmap(vmx->nested.virtual_apic_page);

		status = vmcs_read16(GUEST_INTR_STATUS);
		if ((u8)max_irr > ((u8)status & 0xff)) {
			status &= ~0xff;
			status |= (u8)max_irr;
			vmcs_write16(GUEST_INTR_STATUS, status);
		}
	}

	nested_mark_vmcs12_pages_dirty(vcpu);
}

static u8 vmx_get_rvi(void)
{
	return vmcs_read16(GUEST_INTR_STATUS) & 0xff;
}

static bool vmx_guest_apic_has_interrupt(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	void *vapic_page;
	u32 vppr;
	int rvi;

	if (WARN_ON_ONCE(!is_guest_mode(vcpu)) ||
		!nested_cpu_has_vid(get_vmcs12(vcpu)) ||
		WARN_ON_ONCE(!vmx->nested.virtual_apic_page))
		return false;

	rvi = vmx_get_rvi();

	vapic_page = kmap(vmx->nested.virtual_apic_page);
	vppr = *((u32 *)(vapic_page + APIC_PROCPRI));
	kunmap(vmx->nested.virtual_apic_page);

	return ((rvi & 0xf0) > (vppr & 0xf0));
}

static inline bool kvm_vcpu_trigger_posted_interrupt(struct kvm_vcpu *vcpu,
						     bool nested)
{
#ifdef CONFIG_SMP
	int pi_vec = nested ? POSTED_INTR_NESTED_VECTOR : POSTED_INTR_VECTOR;

	if (vcpu->mode == IN_GUEST_MODE) {
		/*
		 * The vector of interrupt to be delivered to vcpu had
		 * been set in PIR before this function.
		 *
		 * Following cases will be reached in this block, and
		 * we always send a notification event in all cases as
		 * explained below.
		 *
		 * Case 1: vcpu keeps in non-root mode. Sending a
		 * notification event posts the interrupt to vcpu.
		 *
		 * Case 2: vcpu exits to root mode and is still
		 * runnable. PIR will be synced to vIRR before the
		 * next vcpu entry. Sending a notification event in
		 * this case has no effect, as vcpu is not in root
		 * mode.
		 *
		 * Case 3: vcpu exits to root mode and is blocked.
		 * vcpu_block() has already synced PIR to vIRR and
		 * never blocks vcpu if vIRR is not cleared. Therefore,
		 * a blocked vcpu here does not wait for any requested
		 * interrupts in PIR, and sending a notification event
		 * which has no effect is safe here.
		 */

		apic->send_IPI_mask(get_cpu_mask(vcpu->cpu), pi_vec);
		return true;
	}
#endif
	return false;
}

static int vmx_deliver_nested_posted_interrupt(struct kvm_vcpu *vcpu,
						int vector)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);

	if (is_guest_mode(vcpu) &&
	    vector == vmx->nested.posted_intr_nv) {
		/*
		 * If a posted intr is not recognized by hardware,
		 * we will accomplish it in the next vmentry.
		 */
		vmx->nested.pi_pending = true;
		kvm_make_request(KVM_REQ_EVENT, vcpu);
		/* the PIR and ON have been set by L1. */
		if (!kvm_vcpu_trigger_posted_interrupt(vcpu, true))
			kvm_vcpu_kick(vcpu);
		return 0;
	}
	return -1;
}
/*
 * Send interrupt to vcpu via posted interrupt way.
 * 1. If target vcpu is running(non-root mode), send posted interrupt
 * notification to vcpu and hardware will sync PIR to vIRR atomically.
 * 2. If target vcpu isn't running(root mode), kick it to pick up the
 * interrupt from PIR in next vmentry.
 */
static int vmx_deliver_posted_interrupt(struct kvm_vcpu *vcpu, int vector)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	int r;

	r = vmx_deliver_nested_posted_interrupt(vcpu, vector);
	if (!r)
		return 0;

	if (!vcpu->arch.apicv_active)
		return -1;

	if (pi_test_and_set_pir(vector, &vmx->pi_desc))
		return 0;

	/* If a previous notification has sent the IPI, nothing to do.  */
	if (pi_test_and_set_on(&vmx->pi_desc))
		return 0;

	if (!kvm_vcpu_trigger_posted_interrupt(vcpu, false))
		kvm_vcpu_kick(vcpu);

	return 0;
}

/*
 * Set up the vmcs's constant host-state fields, i.e., host-state fields that
 * will not change in the lifetime of the guest.
 * Note that host-state that does change is set elsewhere. E.g., host-state
 * that is set differently for each CPU is set in vmx_vcpu_load(), not here.
 */
static void vmx_set_constant_host_state(struct vcpu_vmx *vmx)
{
	u32 low32, high32;
	unsigned long tmpl;
	struct desc_ptr dt;
	unsigned long cr0, cr3, cr4;

	cr0 = read_cr0();
	WARN_ON(cr0 & X86_CR0_TS);
	vmcs_writel(HOST_CR0, cr0);  /* 22.2.3 */

	/*
	 * Save the most likely value for this task's CR3 in the VMCS.
	 * We can't use __get_current_cr3_fast() because we're not atomic.
	 */
	cr3 = __read_cr3();
	vmcs_writel(HOST_CR3, cr3);		/* 22.2.3  FIXME: shadow tables */
	vmx->loaded_vmcs->host_state.cr3 = cr3;

	/* Save the most likely value for this task's CR4 in the VMCS. */
	cr4 = cr4_read_shadow();
	vmcs_writel(HOST_CR4, cr4);			/* 22.2.3, 22.2.5 */
	vmx->loaded_vmcs->host_state.cr4 = cr4;

	vmcs_write16(HOST_CS_SELECTOR, __KERNEL_CS);  /* 22.2.4 */
#ifdef CONFIG_X86_64
	/*
	 * Load null selectors, so we can avoid reloading them in
	 * vmx_prepare_switch_to_host(), in case userspace uses
	 * the null selectors too (the expected case).
	 */
	vmcs_write16(HOST_DS_SELECTOR, 0);
	vmcs_write16(HOST_ES_SELECTOR, 0);
#else
	vmcs_write16(HOST_DS_SELECTOR, __KERNEL_DS);  /* 22.2.4 */
	vmcs_write16(HOST_ES_SELECTOR, __KERNEL_DS);  /* 22.2.4 */
#endif
	vmcs_write16(HOST_SS_SELECTOR, __KERNEL_DS);  /* 22.2.4 */
	vmcs_write16(HOST_TR_SELECTOR, GDT_ENTRY_TSS*8);  /* 22.2.4 */

	store_idt(&dt);
	vmcs_writel(HOST_IDTR_BASE, dt.address);   /* 22.2.4 */
	vmx->host_idt_base = dt.address;

	vmcs_writel(HOST_RIP, vmx_return); /* 22.2.5 */

	rdmsr(MSR_IA32_SYSENTER_CS, low32, high32);
	vmcs_write32(HOST_IA32_SYSENTER_CS, low32);
	rdmsrl(MSR_IA32_SYSENTER_EIP, tmpl);
	vmcs_writel(HOST_IA32_SYSENTER_EIP, tmpl);   /* 22.2.3 */

	if (vmcs_config.vmexit_ctrl & VM_EXIT_LOAD_IA32_PAT) {
		rdmsr(MSR_IA32_CR_PAT, low32, high32);
		vmcs_write64(HOST_IA32_PAT, low32 | ((u64) high32 << 32));
	}
}

static void set_cr4_guest_host_mask(struct vcpu_vmx *vmx)
{
	BUILD_BUG_ON(KVM_CR4_GUEST_OWNED_BITS & ~KVM_POSSIBLE_CR4_GUEST_BITS);

	vmx->vcpu.arch.cr4_guest_owned_bits = KVM_CR4_GUEST_OWNED_BITS;
	if (enable_ept)
		vmx->vcpu.arch.cr4_guest_owned_bits |= X86_CR4_PGE;
	if (is_guest_mode(&vmx->vcpu))
		vmx->vcpu.arch.cr4_guest_owned_bits &=
			~get_vmcs12(&vmx->vcpu)->cr4_guest_host_mask;
	vmcs_writel(CR4_GUEST_HOST_MASK, ~vmx->vcpu.arch.cr4_guest_owned_bits);
}

static u32 vmx_pin_based_exec_ctrl(struct vcpu_vmx *vmx)
{
	u32 pin_based_exec_ctrl = vmcs_config.pin_based_exec_ctrl;

	if (!kvm_vcpu_apicv_active(&vmx->vcpu))
		pin_based_exec_ctrl &= ~PIN_BASED_POSTED_INTR;

	if (!enable_vnmi)
		pin_based_exec_ctrl &= ~PIN_BASED_VIRTUAL_NMIS;

	/* Enable the preemption timer dynamically */
	pin_based_exec_ctrl &= ~PIN_BASED_VMX_PREEMPTION_TIMER;
	return pin_based_exec_ctrl;
}

static void vmx_refresh_apicv_exec_ctrl(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);

	vmcs_write32(PIN_BASED_VM_EXEC_CONTROL, vmx_pin_based_exec_ctrl(vmx));
	if (cpu_has_secondary_exec_ctrls()) {
		if (kvm_vcpu_apicv_active(vcpu))
			vmcs_set_bits(SECONDARY_VM_EXEC_CONTROL,
				      SECONDARY_EXEC_APIC_REGISTER_VIRT |
				      SECONDARY_EXEC_VIRTUAL_INTR_DELIVERY);
		else
			vmcs_clear_bits(SECONDARY_VM_EXEC_CONTROL,
					SECONDARY_EXEC_APIC_REGISTER_VIRT |
					SECONDARY_EXEC_VIRTUAL_INTR_DELIVERY);
	}

	if (cpu_has_vmx_msr_bitmap())
		vmx_update_msr_bitmap(vcpu);
}

static u32 vmx_exec_control(struct vcpu_vmx *vmx)
{
	u32 exec_control = vmcs_config.cpu_based_exec_ctrl;

	if (vmx->vcpu.arch.switch_db_regs & KVM_DEBUGREG_WONT_EXIT)
		exec_control &= ~CPU_BASED_MOV_DR_EXITING;

	if (!cpu_need_tpr_shadow(&vmx->vcpu)) {
		exec_control &= ~CPU_BASED_TPR_SHADOW;
#ifdef CONFIG_X86_64
		exec_control |= CPU_BASED_CR8_STORE_EXITING |
				CPU_BASED_CR8_LOAD_EXITING;
#endif
	}
	if (!enable_ept)
		exec_control |= CPU_BASED_CR3_STORE_EXITING |
				CPU_BASED_CR3_LOAD_EXITING  |
				CPU_BASED_INVLPG_EXITING;
	if (kvm_mwait_in_guest(vmx->vcpu.kvm))
		exec_control &= ~(CPU_BASED_MWAIT_EXITING |
				CPU_BASED_MONITOR_EXITING);
	if (kvm_hlt_in_guest(vmx->vcpu.kvm))
		exec_control &= ~CPU_BASED_HLT_EXITING;
	return exec_control;
}

static bool vmx_rdrand_supported(void)
{
	return vmcs_config.cpu_based_2nd_exec_ctrl &
		SECONDARY_EXEC_RDRAND_EXITING;
}

static bool vmx_rdseed_supported(void)
{
	return vmcs_config.cpu_based_2nd_exec_ctrl &
		SECONDARY_EXEC_RDSEED_EXITING;
}

static void vmx_compute_secondary_exec_control(struct vcpu_vmx *vmx)
{
	struct kvm_vcpu *vcpu = &vmx->vcpu;

	u32 exec_control = vmcs_config.cpu_based_2nd_exec_ctrl;

	if (!cpu_need_virtualize_apic_accesses(vcpu))
		exec_control &= ~SECONDARY_EXEC_VIRTUALIZE_APIC_ACCESSES;
	if (vmx->vpid == 0)
		exec_control &= ~SECONDARY_EXEC_ENABLE_VPID;
	if (!enable_ept) {
		exec_control &= ~SECONDARY_EXEC_ENABLE_EPT;
		enable_unrestricted_guest = 0;
	}
	if (!enable_unrestricted_guest)
		exec_control &= ~SECONDARY_EXEC_UNRESTRICTED_GUEST;
	if (kvm_pause_in_guest(vmx->vcpu.kvm))
		exec_control &= ~SECONDARY_EXEC_PAUSE_LOOP_EXITING;
	if (!kvm_vcpu_apicv_active(vcpu))
		exec_control &= ~(SECONDARY_EXEC_APIC_REGISTER_VIRT |
				  SECONDARY_EXEC_VIRTUAL_INTR_DELIVERY);
	exec_control &= ~SECONDARY_EXEC_VIRTUALIZE_X2APIC_MODE;

	/* SECONDARY_EXEC_DESC is enabled/disabled on writes to CR4.UMIP,
	 * in vmx_set_cr4.  */
	exec_control &= ~SECONDARY_EXEC_DESC;

	/* SECONDARY_EXEC_SHADOW_VMCS is enabled when L1 executes VMPTRLD
	   (handle_vmptrld).
	   We can NOT enable shadow_vmcs here because we don't have yet
	   a current VMCS12
	*/
	exec_control &= ~SECONDARY_EXEC_SHADOW_VMCS;

	if (!enable_pml)
		exec_control &= ~SECONDARY_EXEC_ENABLE_PML;

	if (vmx_xsaves_supported()) {
		/* Exposing XSAVES only when XSAVE is exposed */
		bool xsaves_enabled =
			guest_cpuid_has(vcpu, X86_FEATURE_XSAVE) &&
			guest_cpuid_has(vcpu, X86_FEATURE_XSAVES);

		if (!xsaves_enabled)
			exec_control &= ~SECONDARY_EXEC_XSAVES;

		if (nested) {
			if (xsaves_enabled)
				vmx->nested.msrs.secondary_ctls_high |=
					SECONDARY_EXEC_XSAVES;
			else
				vmx->nested.msrs.secondary_ctls_high &=
					~SECONDARY_EXEC_XSAVES;
		}
	}

	if (vmx_rdtscp_supported()) {
		bool rdtscp_enabled = guest_cpuid_has(vcpu, X86_FEATURE_RDTSCP);
		if (!rdtscp_enabled)
			exec_control &= ~SECONDARY_EXEC_RDTSCP;

		if (nested) {
			if (rdtscp_enabled)
				vmx->nested.msrs.secondary_ctls_high |=
					SECONDARY_EXEC_RDTSCP;
			else
				vmx->nested.msrs.secondary_ctls_high &=
					~SECONDARY_EXEC_RDTSCP;
		}
	}

	if (vmx_invpcid_supported()) {
		/* Exposing INVPCID only when PCID is exposed */
		bool invpcid_enabled =
			guest_cpuid_has(vcpu, X86_FEATURE_INVPCID) &&
			guest_cpuid_has(vcpu, X86_FEATURE_PCID);

		if (!invpcid_enabled) {
			exec_control &= ~SECONDARY_EXEC_ENABLE_INVPCID;
			guest_cpuid_clear(vcpu, X86_FEATURE_INVPCID);
		}

		if (nested) {
			if (invpcid_enabled)
				vmx->nested.msrs.secondary_ctls_high |=
					SECONDARY_EXEC_ENABLE_INVPCID;
			else
				vmx->nested.msrs.secondary_ctls_high &=
					~SECONDARY_EXEC_ENABLE_INVPCID;
		}
	}

	if (vmx_rdrand_supported()) {
		bool rdrand_enabled = guest_cpuid_has(vcpu, X86_FEATURE_RDRAND);
		if (rdrand_enabled)
			exec_control &= ~SECONDARY_EXEC_RDRAND_EXITING;

		if (nested) {
			if (rdrand_enabled)
				vmx->nested.msrs.secondary_ctls_high |=
					SECONDARY_EXEC_RDRAND_EXITING;
			else
				vmx->nested.msrs.secondary_ctls_high &=
					~SECONDARY_EXEC_RDRAND_EXITING;
		}
	}

	if (vmx_rdseed_supported()) {
		bool rdseed_enabled = guest_cpuid_has(vcpu, X86_FEATURE_RDSEED);
		if (rdseed_enabled)
			exec_control &= ~SECONDARY_EXEC_RDSEED_EXITING;

		if (nested) {
			if (rdseed_enabled)
				vmx->nested.msrs.secondary_ctls_high |=
					SECONDARY_EXEC_RDSEED_EXITING;
			else
				vmx->nested.msrs.secondary_ctls_high &=
					~SECONDARY_EXEC_RDSEED_EXITING;
		}
	}

	vmx->secondary_exec_control = exec_control;
}

static void ept_set_mmio_spte_mask(void)
{
	/*
	 * EPT Misconfigurations can be generated if the value of bits 2:0
	 * of an EPT paging-structure entry is 110b (write/execute).
	 */
	kvm_mmu_set_mmio_spte_mask(VMX_EPT_RWX_MASK,
				   VMX_EPT_MISCONFIG_WX_VALUE);
}

#define VMX_XSS_EXIT_BITMAP 0
/*
 * Sets up the vmcs for emulated real mode.
 */
static void vmx_vcpu_setup(struct vcpu_vmx *vmx)
{
	int i;

	if (enable_shadow_vmcs) {
		/*
		 * At vCPU creation, "VMWRITE to any supported field
		 * in the VMCS" is supported, so use the more
		 * permissive vmx_vmread_bitmap to specify both read
		 * and write permissions for the shadow VMCS.
		 */
		vmcs_write64(VMREAD_BITMAP, __pa(vmx_vmread_bitmap));
		vmcs_write64(VMWRITE_BITMAP, __pa(vmx_vmread_bitmap));
	}
	if (cpu_has_vmx_msr_bitmap())
		vmcs_write64(MSR_BITMAP, __pa(vmx->vmcs01.msr_bitmap));

	vmcs_write64(VMCS_LINK_POINTER, -1ull); /* 22.3.1.5 */

	/* Control */
	vmcs_write32(PIN_BASED_VM_EXEC_CONTROL, vmx_pin_based_exec_ctrl(vmx));
	vmx->hv_deadline_tsc = -1;

	vmcs_write32(CPU_BASED_VM_EXEC_CONTROL, vmx_exec_control(vmx));

	if (cpu_has_secondary_exec_ctrls()) {
		vmx_compute_secondary_exec_control(vmx);
		vmcs_write32(SECONDARY_VM_EXEC_CONTROL,
			     vmx->secondary_exec_control);
	}

	if (kvm_vcpu_apicv_active(&vmx->vcpu)) {
		vmcs_write64(EOI_EXIT_BITMAP0, 0);
		vmcs_write64(EOI_EXIT_BITMAP1, 0);
		vmcs_write64(EOI_EXIT_BITMAP2, 0);
		vmcs_write64(EOI_EXIT_BITMAP3, 0);

		vmcs_write16(GUEST_INTR_STATUS, 0);

		vmcs_write16(POSTED_INTR_NV, POSTED_INTR_VECTOR);
		vmcs_write64(POSTED_INTR_DESC_ADDR, __pa((&vmx->pi_desc)));
	}

	if (!kvm_pause_in_guest(vmx->vcpu.kvm)) {
		vmcs_write32(PLE_GAP, ple_gap);
		vmx->ple_window = ple_window;
		vmx->ple_window_dirty = true;
	}

	vmcs_write32(PAGE_FAULT_ERROR_CODE_MASK, 0);
	vmcs_write32(PAGE_FAULT_ERROR_CODE_MATCH, 0);
	vmcs_write32(CR3_TARGET_COUNT, 0);           /* 22.2.1 */

	vmcs_write16(HOST_FS_SELECTOR, 0);            /* 22.2.4 */
	vmcs_write16(HOST_GS_SELECTOR, 0);            /* 22.2.4 */
	vmx_set_constant_host_state(vmx);
	vmcs_writel(HOST_FS_BASE, 0); /* 22.2.4 */
	vmcs_writel(HOST_GS_BASE, 0); /* 22.2.4 */

	if (cpu_has_vmx_vmfunc())
		vmcs_write64(VM_FUNCTION_CONTROL, 0);

	vmcs_write32(VM_EXIT_MSR_STORE_COUNT, 0);
	vmcs_write32(VM_EXIT_MSR_LOAD_COUNT, 0);
	vmcs_write64(VM_EXIT_MSR_LOAD_ADDR, __pa(vmx->msr_autoload.host.val));
	vmcs_write32(VM_ENTRY_MSR_LOAD_COUNT, 0);
	vmcs_write64(VM_ENTRY_MSR_LOAD_ADDR, __pa(vmx->msr_autoload.guest.val));

	if (vmcs_config.vmentry_ctrl & VM_ENTRY_LOAD_IA32_PAT)
		vmcs_write64(GUEST_IA32_PAT, vmx->vcpu.arch.pat);

	for (i = 0; i < ARRAY_SIZE(vmx_msr_index); ++i) {
		u32 index = vmx_msr_index[i];
		u32 data_low, data_high;
		int j = vmx->nmsrs;

		if (rdmsr_safe(index, &data_low, &data_high) < 0)
			continue;
		if (wrmsr_safe(index, data_low, data_high) < 0)
			continue;
		vmx->guest_msrs[j].index = i;
		vmx->guest_msrs[j].data = 0;
		vmx->guest_msrs[j].mask = -1ull;
		++vmx->nmsrs;
	}

	vm_exit_controls_init(vmx, vmcs_config.vmexit_ctrl);

	/* 22.2.1, 20.8.1 */
	vm_entry_controls_init(vmx, vmcs_config.vmentry_ctrl);

	vmx->vcpu.arch.cr0_guest_owned_bits = X86_CR0_TS;
	vmcs_writel(CR0_GUEST_HOST_MASK, ~X86_CR0_TS);

	set_cr4_guest_host_mask(vmx);

	if (vmx_xsaves_supported())
		vmcs_write64(XSS_EXIT_BITMAP, VMX_XSS_EXIT_BITMAP);

	if (enable_pml) {
		ASSERT(vmx->pml_pg);
		vmcs_write64(PML_ADDRESS, page_to_phys(vmx->pml_pg));
		vmcs_write16(GUEST_PML_INDEX, PML_ENTITY_NUM - 1);
	}

	if (cpu_has_vmx_encls_vmexit())
		vmcs_write64(ENCLS_EXITING_BITMAP, -1ull);
}

static void vmx_vcpu_reset(struct kvm_vcpu *vcpu, bool init_event)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	struct msr_data apic_base_msr;
	u64 cr0;

	vmx->rmode.vm86_active = 0;
	vmx->spec_ctrl = 0;

	vcpu->arch.microcode_version = 0x100000000ULL;
	vmx->vcpu.arch.regs[VCPU_REGS_RDX] = get_rdx_init_val();
	kvm_set_cr8(vcpu, 0);

	if (!init_event) {
		apic_base_msr.data = APIC_DEFAULT_PHYS_BASE |
				     MSR_IA32_APICBASE_ENABLE;
		if (kvm_vcpu_is_reset_bsp(vcpu))
			apic_base_msr.data |= MSR_IA32_APICBASE_BSP;
		apic_base_msr.host_initiated = true;
		kvm_set_apic_base(vcpu, &apic_base_msr);
	}

	vmx_segment_cache_clear(vmx);

	seg_setup(VCPU_SREG_CS);
	vmcs_write16(GUEST_CS_SELECTOR, 0xf000);
	vmcs_writel(GUEST_CS_BASE, 0xffff0000ul);

	seg_setup(VCPU_SREG_DS);
	seg_setup(VCPU_SREG_ES);
	seg_setup(VCPU_SREG_FS);
	seg_setup(VCPU_SREG_GS);
	seg_setup(VCPU_SREG_SS);

	vmcs_write16(GUEST_TR_SELECTOR, 0);
	vmcs_writel(GUEST_TR_BASE, 0);
	vmcs_write32(GUEST_TR_LIMIT, 0xffff);
	vmcs_write32(GUEST_TR_AR_BYTES, 0x008b);

	vmcs_write16(GUEST_LDTR_SELECTOR, 0);
	vmcs_writel(GUEST_LDTR_BASE, 0);
	vmcs_write32(GUEST_LDTR_LIMIT, 0xffff);
	vmcs_write32(GUEST_LDTR_AR_BYTES, 0x00082);

	if (!init_event) {
		vmcs_write32(GUEST_SYSENTER_CS, 0);
		vmcs_writel(GUEST_SYSENTER_ESP, 0);
		vmcs_writel(GUEST_SYSENTER_EIP, 0);
		vmcs_write64(GUEST_IA32_DEBUGCTL, 0);
	}

	kvm_set_rflags(vcpu, X86_EFLAGS_FIXED);
	kvm_rip_write(vcpu, 0xfff0);

	vmcs_writel(GUEST_GDTR_BASE, 0);
	vmcs_write32(GUEST_GDTR_LIMIT, 0xffff);

	vmcs_writel(GUEST_IDTR_BASE, 0);
	vmcs_write32(GUEST_IDTR_LIMIT, 0xffff);

	vmcs_write32(GUEST_ACTIVITY_STATE, GUEST_ACTIVITY_ACTIVE);
	vmcs_write32(GUEST_INTERRUPTIBILITY_INFO, 0);
	vmcs_writel(GUEST_PENDING_DBG_EXCEPTIONS, 0);
	if (kvm_mpx_supported())
		vmcs_write64(GUEST_BNDCFGS, 0);

	setup_msrs(vmx);

	vmcs_write32(VM_ENTRY_INTR_INFO_FIELD, 0);  /* 22.2.1 */

	if (cpu_has_vmx_tpr_shadow() && !init_event) {
		vmcs_write64(VIRTUAL_APIC_PAGE_ADDR, 0);
		if (cpu_need_tpr_shadow(vcpu))
			vmcs_write64(VIRTUAL_APIC_PAGE_ADDR,
				     __pa(vcpu->arch.apic->regs));
		vmcs_write32(TPR_THRESHOLD, 0);
	}

	kvm_make_request(KVM_REQ_APIC_PAGE_RELOAD, vcpu);

	if (vmx->vpid != 0)
		vmcs_write16(VIRTUAL_PROCESSOR_ID, vmx->vpid);

	cr0 = X86_CR0_NW | X86_CR0_CD | X86_CR0_ET;
	vmx->vcpu.arch.cr0 = cr0;
	vmx_set_cr0(vcpu, cr0); /* enter rmode */
	vmx_set_cr4(vcpu, 0);
	vmx_set_efer(vcpu, 0);

	update_exception_bitmap(vcpu);

	vpid_sync_context(vmx->vpid);
	if (init_event)
		vmx_clear_hlt(vcpu);

	vmx_update_fb_clear_dis(vcpu, vmx);
}

/*
 * In nested virtualization, check if L1 asked to exit on external interrupts.
 * For most existing hypervisors, this will always return true.
 */
static bool nested_exit_on_intr(struct kvm_vcpu *vcpu)
{
	return get_vmcs12(vcpu)->pin_based_vm_exec_control &
		PIN_BASED_EXT_INTR_MASK;
}

/*
 * In nested virtualization, check if L1 has set
 * VM_EXIT_ACK_INTR_ON_EXIT
 */
static bool nested_exit_intr_ack_set(struct kvm_vcpu *vcpu)
{
	return get_vmcs12(vcpu)->vm_exit_controls &
		VM_EXIT_ACK_INTR_ON_EXIT;
}

static bool nested_exit_on_nmi(struct kvm_vcpu *vcpu)
{
	return nested_cpu_has_nmi_exiting(get_vmcs12(vcpu));
}

static void enable_irq_window(struct kvm_vcpu *vcpu)
{
	vmcs_set_bits(CPU_BASED_VM_EXEC_CONTROL,
		      CPU_BASED_VIRTUAL_INTR_PENDING);
}

static void enable_nmi_window(struct kvm_vcpu *vcpu)
{
	if (!enable_vnmi ||
	    vmcs_read32(GUEST_INTERRUPTIBILITY_INFO) & GUEST_INTR_STATE_STI) {
		enable_irq_window(vcpu);
		return;
	}

	vmcs_set_bits(CPU_BASED_VM_EXEC_CONTROL,
		      CPU_BASED_VIRTUAL_NMI_PENDING);
}

static void vmx_inject_irq(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	uint32_t intr;
	int irq = vcpu->arch.interrupt.nr;

	trace_kvm_inj_virq(irq);

	++vcpu->stat.irq_injections;
	if (vmx->rmode.vm86_active) {
		int inc_eip = 0;
		if (vcpu->arch.interrupt.soft)
			inc_eip = vcpu->arch.event_exit_inst_len;
		if (kvm_inject_realmode_interrupt(vcpu, irq, inc_eip) != EMULATE_DONE)
			kvm_make_request(KVM_REQ_TRIPLE_FAULT, vcpu);
		return;
	}
	intr = irq | INTR_INFO_VALID_MASK;
	if (vcpu->arch.interrupt.soft) {
		intr |= INTR_TYPE_SOFT_INTR;
		vmcs_write32(VM_ENTRY_INSTRUCTION_LEN,
			     vmx->vcpu.arch.event_exit_inst_len);
	} else
		intr |= INTR_TYPE_EXT_INTR;
	vmcs_write32(VM_ENTRY_INTR_INFO_FIELD, intr);

	vmx_clear_hlt(vcpu);
}

static void vmx_inject_nmi(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);

	if (!enable_vnmi) {
		/*
		 * Tracking the NMI-blocked state in software is built upon
		 * finding the next open IRQ window. This, in turn, depends on
		 * well-behaving guests: They have to keep IRQs disabled at
		 * least as long as the NMI handler runs. Otherwise we may
		 * cause NMI nesting, maybe breaking the guest. But as this is
		 * highly unlikely, we can live with the residual risk.
		 */
		vmx->loaded_vmcs->soft_vnmi_blocked = 1;
		vmx->loaded_vmcs->vnmi_blocked_time = 0;
	}

	++vcpu->stat.nmi_injections;
	vmx->loaded_vmcs->nmi_known_unmasked = false;

	if (vmx->rmode.vm86_active) {
		if (kvm_inject_realmode_interrupt(vcpu, NMI_VECTOR, 0) != EMULATE_DONE)
			kvm_make_request(KVM_REQ_TRIPLE_FAULT, vcpu);
		return;
	}

	vmcs_write32(VM_ENTRY_INTR_INFO_FIELD,
			INTR_TYPE_NMI_INTR | INTR_INFO_VALID_MASK | NMI_VECTOR);

	vmx_clear_hlt(vcpu);
}

static bool vmx_get_nmi_mask(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	bool masked;

	if (!enable_vnmi)
		return vmx->loaded_vmcs->soft_vnmi_blocked;
	if (vmx->loaded_vmcs->nmi_known_unmasked)
		return false;
	masked = vmcs_read32(GUEST_INTERRUPTIBILITY_INFO) & GUEST_INTR_STATE_NMI;
	vmx->loaded_vmcs->nmi_known_unmasked = !masked;
	return masked;
}

static void vmx_set_nmi_mask(struct kvm_vcpu *vcpu, bool masked)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);

	if (!enable_vnmi) {
		if (vmx->loaded_vmcs->soft_vnmi_blocked != masked) {
			vmx->loaded_vmcs->soft_vnmi_blocked = masked;
			vmx->loaded_vmcs->vnmi_blocked_time = 0;
		}
	} else {
		vmx->loaded_vmcs->nmi_known_unmasked = !masked;
		if (masked)
			vmcs_set_bits(GUEST_INTERRUPTIBILITY_INFO,
				      GUEST_INTR_STATE_NMI);
		else
			vmcs_clear_bits(GUEST_INTERRUPTIBILITY_INFO,
					GUEST_INTR_STATE_NMI);
	}
}

static int vmx_nmi_allowed(struct kvm_vcpu *vcpu)
{
	if (to_vmx(vcpu)->nested.nested_run_pending)
		return 0;

	if (!enable_vnmi &&
	    to_vmx(vcpu)->loaded_vmcs->soft_vnmi_blocked)
		return 0;

	return	!(vmcs_read32(GUEST_INTERRUPTIBILITY_INFO) &
		  (GUEST_INTR_STATE_MOV_SS | GUEST_INTR_STATE_STI
		   | GUEST_INTR_STATE_NMI));
}

static int vmx_interrupt_allowed(struct kvm_vcpu *vcpu)
{
	if (to_vmx(vcpu)->nested.nested_run_pending)
		return false;

	if (is_guest_mode(vcpu) && nested_exit_on_intr(vcpu))
		return true;

	return (vmcs_readl(GUEST_RFLAGS) & X86_EFLAGS_IF) &&
		!(vmcs_read32(GUEST_INTERRUPTIBILITY_INFO) &
			(GUEST_INTR_STATE_STI | GUEST_INTR_STATE_MOV_SS));
}

static int vmx_set_tss_addr(struct kvm *kvm, unsigned int addr)
{
	int ret;

	if (enable_unrestricted_guest)
		return 0;

	ret = x86_set_memory_region(kvm, TSS_PRIVATE_MEMSLOT, addr,
				    PAGE_SIZE * 3);
	if (ret)
		return ret;
	to_kvm_vmx(kvm)->tss_addr = addr;
	return init_rmode_tss(kvm);
}

static int vmx_set_identity_map_addr(struct kvm *kvm, u64 ident_addr)
{
	to_kvm_vmx(kvm)->ept_identity_map_addr = ident_addr;
	return 0;
}

static bool rmode_exception(struct kvm_vcpu *vcpu, int vec)
{
	switch (vec) {
	case BP_VECTOR:
		/*
		 * Update instruction length as we may reinject the exception
		 * from user space while in guest debugging mode.
		 */
		to_vmx(vcpu)->vcpu.arch.event_exit_inst_len =
			vmcs_read32(VM_EXIT_INSTRUCTION_LEN);
		if (vcpu->guest_debug & KVM_GUESTDBG_USE_SW_BP)
			return false;
		/* fall through */
	case DB_VECTOR:
		if (vcpu->guest_debug &
			(KVM_GUESTDBG_SINGLESTEP | KVM_GUESTDBG_USE_HW_BP))
			return false;
		/* fall through */
	case DE_VECTOR:
	case OF_VECTOR:
	case BR_VECTOR:
	case UD_VECTOR:
	case DF_VECTOR:
	case SS_VECTOR:
	case GP_VECTOR:
	case MF_VECTOR:
		return true;
	break;
	}
	return false;
}

static int handle_rmode_exception(struct kvm_vcpu *vcpu,
				  int vec, u32 err_code)
{
	/*
	 * Instruction with address size override prefix opcode 0x67
	 * Cause the #SS fault with 0 error code in VM86 mode.
	 */
	if (((vec == GP_VECTOR) || (vec == SS_VECTOR)) && err_code == 0) {
		if (kvm_emulate_instruction(vcpu, 0) == EMULATE_DONE) {
			if (vcpu->arch.halt_request) {
				vcpu->arch.halt_request = 0;
				return kvm_vcpu_halt(vcpu);
			}
			return 1;
		}
		return 0;
	}

	/*
	 * Forward all other exceptions that are valid in real mode.
	 * FIXME: Breaks guest debugging in real mode, needs to be fixed with
	 *        the required debugging infrastructure rework.
	 */
	kvm_queue_exception(vcpu, vec);
	return 1;
}

/*
 * Trigger machine check on the host. We assume all the MSRs are already set up
 * by the CPU and that we still run on the same CPU as the MCE occurred on.
 * We pass a fake environment to the machine check handler because we want
 * the guest to be always treated like user space, no matter what context
 * it used internally.
 */
static void kvm_machine_check(void)
{
#if defined(CONFIG_X86_MCE)
	struct pt_regs regs = {
		.cs = 3, /* Fake ring 3 no matter what the guest ran on */
		.flags = X86_EFLAGS_IF,
	};

	do_machine_check(&regs, 0);
#endif
}

static int handle_machine_check(struct kvm_vcpu *vcpu)
{
	/* already handled by vcpu_run */
	return 1;
}

static int handle_exception(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	struct kvm_run *kvm_run = vcpu->run;
	u32 intr_info, ex_no, error_code;
	unsigned long cr2, rip, dr6;
	u32 vect_info;
	enum emulation_result er;

	vect_info = vmx->idt_vectoring_info;
	intr_info = vmx->exit_intr_info;

	if (is_machine_check(intr_info))
		return handle_machine_check(vcpu);

	if (is_nmi(intr_info))
		return 1;  /* already handled by vmx_vcpu_run() */

	if (is_invalid_opcode(intr_info))
		return handle_ud(vcpu);

	error_code = 0;
	if (intr_info & INTR_INFO_DELIVER_CODE_MASK)
		error_code = vmcs_read32(VM_EXIT_INTR_ERROR_CODE);

	if (!vmx->rmode.vm86_active && is_gp_fault(intr_info)) {
		WARN_ON_ONCE(!enable_vmware_backdoor);
		er = kvm_emulate_instruction(vcpu,
			EMULTYPE_VMWARE | EMULTYPE_NO_UD_ON_FAIL);
		if (er == EMULATE_USER_EXIT)
			return 0;
		else if (er != EMULATE_DONE)
			kvm_queue_exception_e(vcpu, GP_VECTOR, error_code);
		return 1;
	}

	/*
	 * The #PF with PFEC.RSVD = 1 indicates the guest is accessing
	 * MMIO, it is better to report an internal error.
	 * See the comments in vmx_handle_exit.
	 */
	if ((vect_info & VECTORING_INFO_VALID_MASK) &&
	    !(is_page_fault(intr_info) && !(error_code & PFERR_RSVD_MASK))) {
		vcpu->run->exit_reason = KVM_EXIT_INTERNAL_ERROR;
		vcpu->run->internal.suberror = KVM_INTERNAL_ERROR_SIMUL_EX;
		vcpu->run->internal.ndata = 3;
		vcpu->run->internal.data[0] = vect_info;
		vcpu->run->internal.data[1] = intr_info;
		vcpu->run->internal.data[2] = error_code;
		return 0;
	}

	if (is_page_fault(intr_info)) {
		cr2 = vmcs_readl(EXIT_QUALIFICATION);
		/* EPT won't cause page fault directly */
		WARN_ON_ONCE(!vcpu->arch.apf.host_apf_reason && enable_ept);
		return kvm_handle_page_fault(vcpu, error_code, cr2, NULL, 0);
	}

	ex_no = intr_info & INTR_INFO_VECTOR_MASK;

	if (vmx->rmode.vm86_active && rmode_exception(vcpu, ex_no))
		return handle_rmode_exception(vcpu, ex_no, error_code);

	switch (ex_no) {
	case AC_VECTOR:
		kvm_queue_exception_e(vcpu, AC_VECTOR, error_code);
		return 1;
	case DB_VECTOR:
		dr6 = vmcs_readl(EXIT_QUALIFICATION);
		if (!(vcpu->guest_debug &
		      (KVM_GUESTDBG_SINGLESTEP | KVM_GUESTDBG_USE_HW_BP))) {
			vcpu->arch.dr6 &= ~15;
			vcpu->arch.dr6 |= dr6 | DR6_RTM;
			if (is_icebp(intr_info))
				skip_emulated_instruction(vcpu);

			kvm_queue_exception(vcpu, DB_VECTOR);
			return 1;
		}
		kvm_run->debug.arch.dr6 = dr6 | DR6_FIXED_1;
		kvm_run->debug.arch.dr7 = vmcs_readl(GUEST_DR7);
		/* fall through */
	case BP_VECTOR:
		/*
		 * Update instruction length as we may reinject #BP from
		 * user space while in guest debugging mode. Reading it for
		 * #DB as well causes no harm, it is not used in that case.
		 */
		vmx->vcpu.arch.event_exit_inst_len =
			vmcs_read32(VM_EXIT_INSTRUCTION_LEN);
		kvm_run->exit_reason = KVM_EXIT_DEBUG;
		rip = kvm_rip_read(vcpu);
		kvm_run->debug.arch.pc = vmcs_readl(GUEST_CS_BASE) + rip;
		kvm_run->debug.arch.exception = ex_no;
		break;
	default:
		kvm_run->exit_reason = KVM_EXIT_EXCEPTION;
		kvm_run->ex.exception = ex_no;
		kvm_run->ex.error_code = error_code;
		break;
	}
	return 0;
}

static int handle_external_interrupt(struct kvm_vcpu *vcpu)
{
	++vcpu->stat.irq_exits;
	return 1;
}

static int handle_triple_fault(struct kvm_vcpu *vcpu)
{
	vcpu->run->exit_reason = KVM_EXIT_SHUTDOWN;
	vcpu->mmio_needed = 0;
	return 0;
}

static int handle_io(struct kvm_vcpu *vcpu)
{
	unsigned long exit_qualification;
	int size, in, string;
	unsigned port;

	exit_qualification = vmcs_readl(EXIT_QUALIFICATION);
	string = (exit_qualification & 16) != 0;

	++vcpu->stat.io_exits;

	if (string)
		return kvm_emulate_instruction(vcpu, 0) == EMULATE_DONE;

	port = exit_qualification >> 16;
	size = (exit_qualification & 7) + 1;
	in = (exit_qualification & 8) != 0;

	return kvm_fast_pio(vcpu, size, port, in);
}

static void
vmx_patch_hypercall(struct kvm_vcpu *vcpu, unsigned char *hypercall)
{
	/*
	 * Patch in the VMCALL instruction:
	 */
	hypercall[0] = 0x0f;
	hypercall[1] = 0x01;
	hypercall[2] = 0xc1;
}

/* called to set cr0 as appropriate for a mov-to-cr0 exit. */
static int handle_set_cr0(struct kvm_vcpu *vcpu, unsigned long val)
{
	if (is_guest_mode(vcpu)) {
		struct vmcs12 *vmcs12 = get_vmcs12(vcpu);
		unsigned long orig_val = val;

		/*
		 * We get here when L2 changed cr0 in a way that did not change
		 * any of L1's shadowed bits (see nested_vmx_exit_handled_cr),
		 * but did change L0 shadowed bits. So we first calculate the
		 * effective cr0 value that L1 would like to write into the
		 * hardware. It consists of the L2-owned bits from the new
		 * value combined with the L1-owned bits from L1's guest_cr0.
		 */
		val = (val & ~vmcs12->cr0_guest_host_mask) |
			(vmcs12->guest_cr0 & vmcs12->cr0_guest_host_mask);

		if (!nested_guest_cr0_valid(vcpu, val))
			return 1;

		if (kvm_set_cr0(vcpu, val))
			return 1;
		vmcs_writel(CR0_READ_SHADOW, orig_val);
		return 0;
	} else {
		if (to_vmx(vcpu)->nested.vmxon &&
		    !nested_host_cr0_valid(vcpu, val))
			return 1;

		return kvm_set_cr0(vcpu, val);
	}
}

static int handle_set_cr4(struct kvm_vcpu *vcpu, unsigned long val)
{
	if (is_guest_mode(vcpu)) {
		struct vmcs12 *vmcs12 = get_vmcs12(vcpu);
		unsigned long orig_val = val;

		/* analogously to handle_set_cr0 */
		val = (val & ~vmcs12->cr4_guest_host_mask) |
			(vmcs12->guest_cr4 & vmcs12->cr4_guest_host_mask);
		if (kvm_set_cr4(vcpu, val))
			return 1;
		vmcs_writel(CR4_READ_SHADOW, orig_val);
		return 0;
	} else
		return kvm_set_cr4(vcpu, val);
}

static int handle_desc(struct kvm_vcpu *vcpu)
{
	WARN_ON(!(vcpu->arch.cr4 & X86_CR4_UMIP));
	return kvm_emulate_instruction(vcpu, 0) == EMULATE_DONE;
}

static int handle_cr(struct kvm_vcpu *vcpu)
{
	unsigned long exit_qualification, val;
	int cr;
	int reg;
	int err;
	int ret;

	exit_qualification = vmcs_readl(EXIT_QUALIFICATION);
	cr = exit_qualification & 15;
	reg = (exit_qualification >> 8) & 15;
	switch ((exit_qualification >> 4) & 3) {
	case 0: /* mov to cr */
		val = kvm_register_readl(vcpu, reg);
		trace_kvm_cr_write(cr, val);
		switch (cr) {
		case 0:
			err = handle_set_cr0(vcpu, val);
			return kvm_complete_insn_gp(vcpu, err);
		case 3:
			WARN_ON_ONCE(enable_unrestricted_guest);
			err = kvm_set_cr3(vcpu, val);
			return kvm_complete_insn_gp(vcpu, err);
		case 4:
			err = handle_set_cr4(vcpu, val);
			return kvm_complete_insn_gp(vcpu, err);
		case 8: {
				u8 cr8_prev = kvm_get_cr8(vcpu);
				u8 cr8 = (u8)val;
				err = kvm_set_cr8(vcpu, cr8);
				ret = kvm_complete_insn_gp(vcpu, err);
				if (lapic_in_kernel(vcpu))
					return ret;
				if (cr8_prev <= cr8)
					return ret;
				/*
				 * TODO: we might be squashing a
				 * KVM_GUESTDBG_SINGLESTEP-triggered
				 * KVM_EXIT_DEBUG here.
				 */
				vcpu->run->exit_reason = KVM_EXIT_SET_TPR;
				return 0;
			}
		}
		break;
	case 2: /* clts */
		WARN_ONCE(1, "Guest should always own CR0.TS");
		vmx_set_cr0(vcpu, kvm_read_cr0_bits(vcpu, ~X86_CR0_TS));
		trace_kvm_cr_write(0, kvm_read_cr0(vcpu));
		return kvm_skip_emulated_instruction(vcpu);
	case 1: /*mov from cr*/
		switch (cr) {
		case 3:
			WARN_ON_ONCE(enable_unrestricted_guest);
			val = kvm_read_cr3(vcpu);
			kvm_register_write(vcpu, reg, val);
			trace_kvm_cr_read(cr, val);
			return kvm_skip_emulated_instruction(vcpu);
		case 8:
			val = kvm_get_cr8(vcpu);
			kvm_register_write(vcpu, reg, val);
			trace_kvm_cr_read(cr, val);
			return kvm_skip_emulated_instruction(vcpu);
		}
		break;
	case 3: /* lmsw */
		val = (exit_qualification >> LMSW_SOURCE_DATA_SHIFT) & 0x0f;
		trace_kvm_cr_write(0, (kvm_read_cr0(vcpu) & ~0xful) | val);
		kvm_lmsw(vcpu, val);

		return kvm_skip_emulated_instruction(vcpu);
	default:
		break;
	}
	vcpu->run->exit_reason = 0;
	vcpu_unimpl(vcpu, "unhandled control register: op %d cr %d\n",
	       (int)(exit_qualification >> 4) & 3, cr);
	return 0;
}

static int handle_dr(struct kvm_vcpu *vcpu)
{
	unsigned long exit_qualification;
	int dr, dr7, reg;

	exit_qualification = vmcs_readl(EXIT_QUALIFICATION);
	dr = exit_qualification & DEBUG_REG_ACCESS_NUM;

	/* First, if DR does not exist, trigger UD */
	if (!kvm_require_dr(vcpu, dr))
		return 1;

	/* Do not handle if the CPL > 0, will trigger GP on re-entry */
	if (!kvm_require_cpl(vcpu, 0))
		return 1;
	dr7 = vmcs_readl(GUEST_DR7);
	if (dr7 & DR7_GD) {
		/*
		 * As the vm-exit takes precedence over the debug trap, we
		 * need to emulate the latter, either for the host or the
		 * guest debugging itself.
		 */
		if (vcpu->guest_debug & KVM_GUESTDBG_USE_HW_BP) {
			vcpu->run->debug.arch.dr6 = vcpu->arch.dr6;
			vcpu->run->debug.arch.dr7 = dr7;
			vcpu->run->debug.arch.pc = kvm_get_linear_rip(vcpu);
			vcpu->run->debug.arch.exception = DB_VECTOR;
			vcpu->run->exit_reason = KVM_EXIT_DEBUG;
			return 0;
		} else {
			vcpu->arch.dr6 &= ~15;
			vcpu->arch.dr6 |= DR6_BD | DR6_RTM;
			kvm_queue_exception(vcpu, DB_VECTOR);
			return 1;
		}
	}

	if (vcpu->guest_debug == 0) {
		vmcs_clear_bits(CPU_BASED_VM_EXEC_CONTROL,
				CPU_BASED_MOV_DR_EXITING);

		/*
		 * No more DR vmexits; force a reload of the debug registers
		 * and reenter on this instruction.  The next vmexit will
		 * retrieve the full state of the debug registers.
		 */
		vcpu->arch.switch_db_regs |= KVM_DEBUGREG_WONT_EXIT;
		return 1;
	}

	reg = DEBUG_REG_ACCESS_REG(exit_qualification);
	if (exit_qualification & TYPE_MOV_FROM_DR) {
		unsigned long val;

		if (kvm_get_dr(vcpu, dr, &val))
			return 1;
		kvm_register_write(vcpu, reg, val);
	} else
		if (kvm_set_dr(vcpu, dr, kvm_register_readl(vcpu, reg)))
			return 1;

	return kvm_skip_emulated_instruction(vcpu);
}

static u64 vmx_get_dr6(struct kvm_vcpu *vcpu)
{
	return vcpu->arch.dr6;
}

static void vmx_set_dr6(struct kvm_vcpu *vcpu, unsigned long val)
{
}

static void vmx_sync_dirty_debug_regs(struct kvm_vcpu *vcpu)
{
	get_debugreg(vcpu->arch.db[0], 0);
	get_debugreg(vcpu->arch.db[1], 1);
	get_debugreg(vcpu->arch.db[2], 2);
	get_debugreg(vcpu->arch.db[3], 3);
	get_debugreg(vcpu->arch.dr6, 6);
	vcpu->arch.dr7 = vmcs_readl(GUEST_DR7);

	vcpu->arch.switch_db_regs &= ~KVM_DEBUGREG_WONT_EXIT;
	vmcs_set_bits(CPU_BASED_VM_EXEC_CONTROL, CPU_BASED_MOV_DR_EXITING);
}

static void vmx_set_dr7(struct kvm_vcpu *vcpu, unsigned long val)
{
	vmcs_writel(GUEST_DR7, val);
}

static int handle_cpuid(struct kvm_vcpu *vcpu)
{
	return kvm_emulate_cpuid(vcpu);
}

static int handle_rdmsr(struct kvm_vcpu *vcpu)
{
	u32 ecx = vcpu->arch.regs[VCPU_REGS_RCX];
	struct msr_data msr_info;

	msr_info.index = ecx;
	msr_info.host_initiated = false;
	if (vmx_get_msr(vcpu, &msr_info)) {
		trace_kvm_msr_read_ex(ecx);
		kvm_inject_gp(vcpu, 0);
		return 1;
	}

	trace_kvm_msr_read(ecx, msr_info.data);

	/* FIXME: handling of bits 32:63 of rax, rdx */
	vcpu->arch.regs[VCPU_REGS_RAX] = msr_info.data & -1u;
	vcpu->arch.regs[VCPU_REGS_RDX] = (msr_info.data >> 32) & -1u;
	return kvm_skip_emulated_instruction(vcpu);
}

static int handle_wrmsr(struct kvm_vcpu *vcpu)
{
	struct msr_data msr;
	u32 ecx = vcpu->arch.regs[VCPU_REGS_RCX];
	u64 data = (vcpu->arch.regs[VCPU_REGS_RAX] & -1u)
		| ((u64)(vcpu->arch.regs[VCPU_REGS_RDX] & -1u) << 32);

	msr.data = data;
	msr.index = ecx;
	msr.host_initiated = false;
	if (kvm_set_msr(vcpu, &msr) != 0) {
		trace_kvm_msr_write_ex(ecx, data);
		kvm_inject_gp(vcpu, 0);
		return 1;
	}

	trace_kvm_msr_write(ecx, data);
	return kvm_skip_emulated_instruction(vcpu);
}

static int handle_tpr_below_threshold(struct kvm_vcpu *vcpu)
{
	kvm_apic_update_ppr(vcpu);
	return 1;
}

static int handle_interrupt_window(struct kvm_vcpu *vcpu)
{
	vmcs_clear_bits(CPU_BASED_VM_EXEC_CONTROL,
			CPU_BASED_VIRTUAL_INTR_PENDING);

	kvm_make_request(KVM_REQ_EVENT, vcpu);

	++vcpu->stat.irq_window_exits;
	return 1;
}

static int handle_halt(struct kvm_vcpu *vcpu)
{
	return kvm_emulate_halt(vcpu);
}

static int handle_vmcall(struct kvm_vcpu *vcpu)
{
	return kvm_emulate_hypercall(vcpu);
}

static int handle_invd(struct kvm_vcpu *vcpu)
{
	return kvm_emulate_instruction(vcpu, 0) == EMULATE_DONE;
}

static int handle_invlpg(struct kvm_vcpu *vcpu)
{
	unsigned long exit_qualification = vmcs_readl(EXIT_QUALIFICATION);

	kvm_mmu_invlpg(vcpu, exit_qualification);
	return kvm_skip_emulated_instruction(vcpu);
}

static int handle_rdpmc(struct kvm_vcpu *vcpu)
{
	int err;

	err = kvm_rdpmc(vcpu);
	return kvm_complete_insn_gp(vcpu, err);
}

static int handle_wbinvd(struct kvm_vcpu *vcpu)
{
	return kvm_emulate_wbinvd(vcpu);
}

static int handle_xsetbv(struct kvm_vcpu *vcpu)
{
	u64 new_bv = kvm_read_edx_eax(vcpu);
	u32 index = kvm_register_read(vcpu, VCPU_REGS_RCX);

	if (kvm_set_xcr(vcpu, index, new_bv) == 0)
		return kvm_skip_emulated_instruction(vcpu);
	return 1;
}

static int handle_xsaves(struct kvm_vcpu *vcpu)
{
	kvm_skip_emulated_instruction(vcpu);
	WARN(1, "this should never happen\n");
	return 1;
}

static int handle_xrstors(struct kvm_vcpu *vcpu)
{
	kvm_skip_emulated_instruction(vcpu);
	WARN(1, "this should never happen\n");
	return 1;
}

static int handle_apic_access(struct kvm_vcpu *vcpu)
{
	if (likely(fasteoi)) {
		unsigned long exit_qualification = vmcs_readl(EXIT_QUALIFICATION);
		int access_type, offset;

		access_type = exit_qualification & APIC_ACCESS_TYPE;
		offset = exit_qualification & APIC_ACCESS_OFFSET;
		/*
		 * Sane guest uses MOV to write EOI, with written value
		 * not cared. So make a short-circuit here by avoiding
		 * heavy instruction emulation.
		 */
		if ((access_type == TYPE_LINEAR_APIC_INST_WRITE) &&
		    (offset == APIC_EOI)) {
			kvm_lapic_set_eoi(vcpu);
			return kvm_skip_emulated_instruction(vcpu);
		}
	}
	return kvm_emulate_instruction(vcpu, 0) == EMULATE_DONE;
}

static int handle_apic_eoi_induced(struct kvm_vcpu *vcpu)
{
	unsigned long exit_qualification = vmcs_readl(EXIT_QUALIFICATION);
	int vector = exit_qualification & 0xff;

	/* EOI-induced VM exit is trap-like and thus no need to adjust IP */
	kvm_apic_set_eoi_accelerated(vcpu, vector);
	return 1;
}

static int handle_apic_write(struct kvm_vcpu *vcpu)
{
	unsigned long exit_qualification = vmcs_readl(EXIT_QUALIFICATION);
	u32 offset = exit_qualification & 0xfff;

	/* APIC-write VM exit is trap-like and thus no need to adjust IP */
	kvm_apic_write_nodecode(vcpu, offset);
	return 1;
}

static int handle_task_switch(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	unsigned long exit_qualification;
	bool has_error_code = false;
	u32 error_code = 0;
	u16 tss_selector;
	int reason, type, idt_v, idt_index;

	idt_v = (vmx->idt_vectoring_info & VECTORING_INFO_VALID_MASK);
	idt_index = (vmx->idt_vectoring_info & VECTORING_INFO_VECTOR_MASK);
	type = (vmx->idt_vectoring_info & VECTORING_INFO_TYPE_MASK);

	exit_qualification = vmcs_readl(EXIT_QUALIFICATION);

	reason = (u32)exit_qualification >> 30;
	if (reason == TASK_SWITCH_GATE && idt_v) {
		switch (type) {
		case INTR_TYPE_NMI_INTR:
			vcpu->arch.nmi_injected = false;
			vmx_set_nmi_mask(vcpu, true);
			break;
		case INTR_TYPE_EXT_INTR:
		case INTR_TYPE_SOFT_INTR:
			kvm_clear_interrupt_queue(vcpu);
			break;
		case INTR_TYPE_HARD_EXCEPTION:
			if (vmx->idt_vectoring_info &
			    VECTORING_INFO_DELIVER_CODE_MASK) {
				has_error_code = true;
				error_code =
					vmcs_read32(IDT_VECTORING_ERROR_CODE);
			}
			/* fall through */
		case INTR_TYPE_SOFT_EXCEPTION:
			kvm_clear_exception_queue(vcpu);
			break;
		default:
			break;
		}
	}
	tss_selector = exit_qualification;

	if (!idt_v || (type != INTR_TYPE_HARD_EXCEPTION &&
		       type != INTR_TYPE_EXT_INTR &&
		       type != INTR_TYPE_NMI_INTR))
		skip_emulated_instruction(vcpu);

	if (kvm_task_switch(vcpu, tss_selector,
			    type == INTR_TYPE_SOFT_INTR ? idt_index : -1, reason,
			    has_error_code, error_code) == EMULATE_FAIL) {
		vcpu->run->exit_reason = KVM_EXIT_INTERNAL_ERROR;
		vcpu->run->internal.suberror = KVM_INTERNAL_ERROR_EMULATION;
		vcpu->run->internal.ndata = 0;
		return 0;
	}

	/*
	 * TODO: What about debug traps on tss switch?
	 *       Are we supposed to inject them and update dr6?
	 */

	return 1;
}

static int handle_ept_violation(struct kvm_vcpu *vcpu)
{
	unsigned long exit_qualification;
	gpa_t gpa;
	u64 error_code;

	exit_qualification = vmcs_readl(EXIT_QUALIFICATION);

	/*
	 * EPT violation happened while executing iret from NMI,
	 * "blocked by NMI" bit has to be set before next VM entry.
	 * There are errata that may cause this bit to not be set:
	 * AAK134, BY25.
	 */
	if (!(to_vmx(vcpu)->idt_vectoring_info & VECTORING_INFO_VALID_MASK) &&
			enable_vnmi &&
			(exit_qualification & INTR_INFO_UNBLOCK_NMI))
		vmcs_set_bits(GUEST_INTERRUPTIBILITY_INFO, GUEST_INTR_STATE_NMI);

	gpa = vmcs_read64(GUEST_PHYSICAL_ADDRESS);
	trace_kvm_page_fault(gpa, exit_qualification);

	/* Is it a read fault? */
	error_code = (exit_qualification & EPT_VIOLATION_ACC_READ)
		     ? PFERR_USER_MASK : 0;
	/* Is it a write fault? */
	error_code |= (exit_qualification & EPT_VIOLATION_ACC_WRITE)
		      ? PFERR_WRITE_MASK : 0;
	/* Is it a fetch fault? */
	error_code |= (exit_qualification & EPT_VIOLATION_ACC_INSTR)
		      ? PFERR_FETCH_MASK : 0;
	/* ept page table entry is present? */
	error_code |= (exit_qualification &
		       (EPT_VIOLATION_READABLE | EPT_VIOLATION_WRITABLE |
			EPT_VIOLATION_EXECUTABLE))
		      ? PFERR_PRESENT_MASK : 0;

	error_code |= (exit_qualification & 0x100) != 0 ?
	       PFERR_GUEST_FINAL_MASK : PFERR_GUEST_PAGE_MASK;

	vcpu->arch.exit_qualification = exit_qualification;
	return kvm_mmu_page_fault(vcpu, gpa, error_code, NULL, 0);
}

static int handle_ept_misconfig(struct kvm_vcpu *vcpu)
{
	gpa_t gpa;

	/*
	 * A nested guest cannot optimize MMIO vmexits, because we have an
	 * nGPA here instead of the required GPA.
	 */
	gpa = vmcs_read64(GUEST_PHYSICAL_ADDRESS);
	if (!is_guest_mode(vcpu) &&
	    !kvm_io_bus_write(vcpu, KVM_FAST_MMIO_BUS, gpa, 0, NULL)) {
		trace_kvm_fast_mmio(gpa);
		/*
		 * Doing kvm_skip_emulated_instruction() depends on undefined
		 * behavior: Intel's manual doesn't mandate
		 * VM_EXIT_INSTRUCTION_LEN to be set in VMCS when EPT MISCONFIG
		 * occurs and while on real hardware it was observed to be set,
		 * other hypervisors (namely Hyper-V) don't set it, we end up
		 * advancing IP with some random value. Disable fast mmio when
		 * running nested and keep it for real hardware in hope that
		 * VM_EXIT_INSTRUCTION_LEN will always be set correctly.
		 */
		if (!static_cpu_has(X86_FEATURE_HYPERVISOR))
			return kvm_skip_emulated_instruction(vcpu);
		else
			return kvm_emulate_instruction(vcpu, EMULTYPE_SKIP) ==
								EMULATE_DONE;
	}

	return kvm_mmu_page_fault(vcpu, gpa, PFERR_RSVD_MASK, NULL, 0);
}

static int handle_nmi_window(struct kvm_vcpu *vcpu)
{
	WARN_ON_ONCE(!enable_vnmi);
	vmcs_clear_bits(CPU_BASED_VM_EXEC_CONTROL,
			CPU_BASED_VIRTUAL_NMI_PENDING);
	++vcpu->stat.nmi_window_exits;
	kvm_make_request(KVM_REQ_EVENT, vcpu);

	return 1;
}

static int handle_invalid_guest_state(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	enum emulation_result err = EMULATE_DONE;
	int ret = 1;
	u32 cpu_exec_ctrl;
	bool intr_window_requested;
	unsigned count = 130;

	/*
	 * We should never reach the point where we are emulating L2
	 * due to invalid guest state as that means we incorrectly
	 * allowed a nested VMEntry with an invalid vmcs12.
	 */
	WARN_ON_ONCE(vmx->emulation_required && vmx->nested.nested_run_pending);

	cpu_exec_ctrl = vmcs_read32(CPU_BASED_VM_EXEC_CONTROL);
	intr_window_requested = cpu_exec_ctrl & CPU_BASED_VIRTUAL_INTR_PENDING;

	while (vmx->emulation_required && count-- != 0) {
		if (intr_window_requested && vmx_interrupt_allowed(vcpu))
			return handle_interrupt_window(&vmx->vcpu);

		if (kvm_test_request(KVM_REQ_EVENT, vcpu))
			return 1;

		err = kvm_emulate_instruction(vcpu, 0);

		if (err == EMULATE_USER_EXIT) {
			++vcpu->stat.mmio_exits;
			ret = 0;
			goto out;
		}

		if (err != EMULATE_DONE)
			goto emulation_error;

		if (vmx->emulation_required && !vmx->rmode.vm86_active &&
		    vcpu->arch.exception.pending)
			goto emulation_error;

		if (vcpu->arch.halt_request) {
			vcpu->arch.halt_request = 0;
			ret = kvm_vcpu_halt(vcpu);
			goto out;
		}

		if (signal_pending(current))
			goto out;
		if (need_resched())
			schedule();
	}

out:
	return ret;

emulation_error:
	vcpu->run->exit_reason = KVM_EXIT_INTERNAL_ERROR;
	vcpu->run->internal.suberror = KVM_INTERNAL_ERROR_EMULATION;
	vcpu->run->internal.ndata = 0;
	return 0;
}

static void grow_ple_window(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	int old = vmx->ple_window;

	vmx->ple_window = __grow_ple_window(old, ple_window,
					    ple_window_grow,
					    ple_window_max);

	if (vmx->ple_window != old)
		vmx->ple_window_dirty = true;

	trace_kvm_ple_window_grow(vcpu->vcpu_id, vmx->ple_window, old);
}

static void shrink_ple_window(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	int old = vmx->ple_window;

	vmx->ple_window = __shrink_ple_window(old, ple_window,
					      ple_window_shrink,
					      ple_window);

	if (vmx->ple_window != old)
		vmx->ple_window_dirty = true;

	trace_kvm_ple_window_shrink(vcpu->vcpu_id, vmx->ple_window, old);
}

/*
 * Handler for POSTED_INTERRUPT_WAKEUP_VECTOR.
 */
static void wakeup_handler(void)
{
	struct kvm_vcpu *vcpu;
	int cpu = smp_processor_id();

	spin_lock(&per_cpu(blocked_vcpu_on_cpu_lock, cpu));
	list_for_each_entry(vcpu, &per_cpu(blocked_vcpu_on_cpu, cpu),
			blocked_vcpu_list) {
		struct pi_desc *pi_desc = vcpu_to_pi_desc(vcpu);

		if (pi_test_on(pi_desc) == 1)
			kvm_vcpu_kick(vcpu);
	}
	spin_unlock(&per_cpu(blocked_vcpu_on_cpu_lock, cpu));
}

static void vmx_enable_tdp(void)
{
	kvm_mmu_set_mask_ptes(VMX_EPT_READABLE_MASK,
		enable_ept_ad_bits ? VMX_EPT_ACCESS_BIT : 0ull,
		enable_ept_ad_bits ? VMX_EPT_DIRTY_BIT : 0ull,
		0ull, VMX_EPT_EXECUTABLE_MASK,
		cpu_has_vmx_ept_execute_only() ? 0ull : VMX_EPT_READABLE_MASK,
		VMX_EPT_RWX_MASK, 0ull);

	ept_set_mmio_spte_mask();
	kvm_enable_tdp();
}

static __init int hardware_setup(void)
{
	unsigned long host_bndcfgs;
	int r = -ENOMEM, i;

	rdmsrl_safe(MSR_EFER, &host_efer);

	for (i = 0; i < ARRAY_SIZE(vmx_msr_index); ++i)
		kvm_define_shared_msr(i, vmx_msr_index[i]);

	for (i = 0; i < VMX_BITMAP_NR; i++) {
		vmx_bitmap[i] = (unsigned long *)__get_free_page(GFP_KERNEL);
		if (!vmx_bitmap[i])
			goto out;
	}

	memset(vmx_vmread_bitmap, 0xff, PAGE_SIZE);
	memset(vmx_vmwrite_bitmap, 0xff, PAGE_SIZE);

	if (setup_vmcs_config(&vmcs_config) < 0) {
		r = -EIO;
		goto out;
	}

	if (boot_cpu_has(X86_FEATURE_NX))
		kvm_enable_efer_bits(EFER_NX);

	if (boot_cpu_has(X86_FEATURE_MPX)) {
		rdmsrl(MSR_IA32_BNDCFGS, host_bndcfgs);
		WARN_ONCE(host_bndcfgs, "KVM: BNDCFGS in host will be lost");
	}

	if (boot_cpu_has(X86_FEATURE_XSAVES))
		rdmsrl(MSR_IA32_XSS, host_xss);

	if (!cpu_has_vmx_vpid() || !cpu_has_vmx_invvpid() ||
		!(cpu_has_vmx_invvpid_single() || cpu_has_vmx_invvpid_global()))
		enable_vpid = 0;

	if (!cpu_has_vmx_ept() ||
	    !cpu_has_vmx_ept_4levels() ||
	    !cpu_has_vmx_ept_mt_wb() ||
	    !cpu_has_vmx_invept_global())
		enable_ept = 0;

	if (!cpu_has_vmx_ept_ad_bits() || !enable_ept)
		enable_ept_ad_bits = 0;

	if (!cpu_has_vmx_unrestricted_guest() || !enable_ept)
		enable_unrestricted_guest = 0;

	if (!cpu_has_vmx_flexpriority())
		flexpriority_enabled = 0;

	if (!cpu_has_virtual_nmis())
		enable_vnmi = 0;

	/*
	 * set_apic_access_page_addr() is used to reload apic access
	 * page upon invalidation.  No need to do anything if not
	 * using the APIC_ACCESS_ADDR VMCS field.
	 */
	if (!flexpriority_enabled)
		kvm_x86_ops->set_apic_access_page_addr = NULL;

	if (!cpu_has_vmx_tpr_shadow())
		kvm_x86_ops->update_cr8_intercept = NULL;

	if (enable_ept && !cpu_has_vmx_ept_2m_page())
		kvm_disable_largepages();

#if IS_ENABLED(CONFIG_HYPERV)
	if (ms_hyperv.nested_features & HV_X64_NESTED_GUEST_MAPPING_FLUSH
	    && enable_ept)
		kvm_x86_ops->tlb_remote_flush = vmx_hv_remote_flush_tlb;
#endif

	if (!cpu_has_vmx_ple()) {
		ple_gap = 0;
		ple_window = 0;
		ple_window_grow = 0;
		ple_window_max = 0;
		ple_window_shrink = 0;
	}

	if (!cpu_has_vmx_apicv()) {
		enable_apicv = 0;
		kvm_x86_ops->sync_pir_to_irr = NULL;
	}

	if (cpu_has_vmx_tsc_scaling()) {
		kvm_has_tsc_control = true;
		kvm_max_tsc_scaling_ratio = KVM_VMX_TSC_MULTIPLIER_MAX;
		kvm_tsc_scaling_ratio_frac_bits = 48;
	}

	set_bit(0, vmx_vpid_bitmap); /* 0 is reserved for host */

	if (enable_ept)
		vmx_enable_tdp();
	else
		kvm_disable_tdp();

	if (!nested) {
		kvm_x86_ops->get_nested_state = NULL;
		kvm_x86_ops->set_nested_state = NULL;
	}

	/*
	 * Only enable PML when hardware supports PML feature, and both EPT
	 * and EPT A/D bit features are enabled -- PML depends on them to work.
	 */
	if (!enable_ept || !enable_ept_ad_bits || !cpu_has_vmx_pml())
		enable_pml = 0;

	if (!enable_pml) {
		kvm_x86_ops->slot_enable_log_dirty = NULL;
		kvm_x86_ops->slot_disable_log_dirty = NULL;
		kvm_x86_ops->flush_log_dirty = NULL;
		kvm_x86_ops->enable_log_dirty_pt_masked = NULL;
	}

	if (!cpu_has_vmx_preemption_timer())
		kvm_x86_ops->request_immediate_exit = __kvm_request_immediate_exit;

	if (cpu_has_vmx_preemption_timer() && enable_preemption_timer) {
		u64 vmx_msr;

		rdmsrl(MSR_IA32_VMX_MISC, vmx_msr);
		cpu_preemption_timer_multi =
			 vmx_msr & VMX_MISC_PREEMPTION_TIMER_RATE_MASK;
	} else {
		kvm_x86_ops->set_hv_timer = NULL;
		kvm_x86_ops->cancel_hv_timer = NULL;
	}

	if (!cpu_has_vmx_shadow_vmcs())
		enable_shadow_vmcs = 0;
	if (enable_shadow_vmcs)
		init_vmcs_shadow_fields();

	kvm_set_posted_intr_wakeup_handler(wakeup_handler);
	nested_vmx_setup_ctls_msrs(&vmcs_config.nested, enable_apicv);

	kvm_mce_cap_supported |= MCG_LMCE_P;

	r = alloc_kvm_area();
	if (r)
		goto out;
	return 0;

out:
	for (i = 0; i < VMX_BITMAP_NR; i++)
		free_page((unsigned long)vmx_bitmap[i]);

	return r;
}

static __exit void hardware_unsetup(void)
{
	int i;

	for (i = 0; i < VMX_BITMAP_NR; i++)
		free_page((unsigned long)vmx_bitmap[i]);

	free_kvm_area();
}

/*
 * Indicate a busy-waiting vcpu in spinlock. We do not enable the PAUSE
 * exiting, so only get here on cpu with PAUSE-Loop-Exiting.
 */
static int handle_pause(struct kvm_vcpu *vcpu)
{
	if (!kvm_pause_in_guest(vcpu->kvm))
		grow_ple_window(vcpu);

	/*
	 * Intel sdm vol3 ch-25.1.3 says: The "PAUSE-loop exiting"
	 * VM-execution control is ignored if CPL > 0. OTOH, KVM
	 * never set PAUSE_EXITING and just set PLE if supported,
	 * so the vcpu must be CPL=0 if it gets a PAUSE exit.
	 */
	kvm_vcpu_on_spin(vcpu, true);
	return kvm_skip_emulated_instruction(vcpu);
}

static int handle_nop(struct kvm_vcpu *vcpu)
{
	return kvm_skip_emulated_instruction(vcpu);
}

static int handle_mwait(struct kvm_vcpu *vcpu)
{
	printk_once(KERN_WARNING "kvm: MWAIT instruction emulated as NOP!\n");
	return handle_nop(vcpu);
}

static int handle_invalid_op(struct kvm_vcpu *vcpu)
{
	kvm_queue_exception(vcpu, UD_VECTOR);
	return 1;
}

static int handle_monitor_trap(struct kvm_vcpu *vcpu)
{
	return 1;
}

static int handle_monitor(struct kvm_vcpu *vcpu)
{
	printk_once(KERN_WARNING "kvm: MONITOR instruction emulated as NOP!\n");
	return handle_nop(vcpu);
}

/*
 * The following 3 functions, nested_vmx_succeed()/failValid()/failInvalid(),
 * set the success or error code of an emulated VMX instruction, as specified
 * by Vol 2B, VMX Instruction Reference, "Conventions".
 */
static void nested_vmx_succeed(struct kvm_vcpu *vcpu)
{
	vmx_set_rflags(vcpu, vmx_get_rflags(vcpu)
			& ~(X86_EFLAGS_CF | X86_EFLAGS_PF | X86_EFLAGS_AF |
			    X86_EFLAGS_ZF | X86_EFLAGS_SF | X86_EFLAGS_OF));
}

static void nested_vmx_failInvalid(struct kvm_vcpu *vcpu)
{
	vmx_set_rflags(vcpu, (vmx_get_rflags(vcpu)
			& ~(X86_EFLAGS_PF | X86_EFLAGS_AF | X86_EFLAGS_ZF |
			    X86_EFLAGS_SF | X86_EFLAGS_OF))
			| X86_EFLAGS_CF);
}

static void nested_vmx_failValid(struct kvm_vcpu *vcpu,
					u32 vm_instruction_error)
{
	if (to_vmx(vcpu)->nested.current_vmptr == -1ull) {
		/*
		 * failValid writes the error number to the current VMCS, which
		 * can't be done there isn't a current VMCS.
		 */
		nested_vmx_failInvalid(vcpu);
		return;
	}
	vmx_set_rflags(vcpu, (vmx_get_rflags(vcpu)
			& ~(X86_EFLAGS_CF | X86_EFLAGS_PF | X86_EFLAGS_AF |
			    X86_EFLAGS_SF | X86_EFLAGS_OF))
			| X86_EFLAGS_ZF);
	get_vmcs12(vcpu)->vm_instruction_error = vm_instruction_error;
	/*
	 * We don't need to force a shadow sync because
	 * VM_INSTRUCTION_ERROR is not shadowed
	 */
}

static void nested_vmx_abort(struct kvm_vcpu *vcpu, u32 indicator)
{
	/* TODO: not to reset guest simply here. */
	kvm_make_request(KVM_REQ_TRIPLE_FAULT, vcpu);
	pr_debug_ratelimited("kvm: nested vmx abort, indicator %d\n", indicator);
}

static enum hrtimer_restart vmx_preemption_timer_fn(struct hrtimer *timer)
{
	struct vcpu_vmx *vmx =
		container_of(timer, struct vcpu_vmx, nested.preemption_timer);

	vmx->nested.preemption_timer_expired = true;
	kvm_make_request(KVM_REQ_EVENT, &vmx->vcpu);
	kvm_vcpu_kick(&vmx->vcpu);

	return HRTIMER_NORESTART;
}

/*
 * Decode the memory-address operand of a vmx instruction, as recorded on an
 * exit caused by such an instruction (run by a guest hypervisor).
 * On success, returns 0. When the operand is invalid, returns 1 and throws
 * #UD or #GP.
 */
static int get_vmx_mem_address(struct kvm_vcpu *vcpu,
				 unsigned long exit_qualification,
				 u32 vmx_instruction_info, bool wr, gva_t *ret)
{
	gva_t off;
	bool exn;
	struct kvm_segment s;

	/*
	 * According to Vol. 3B, "Information for VM Exits Due to Instruction
	 * Execution", on an exit, vmx_instruction_info holds most of the
	 * addressing components of the operand. Only the displacement part
	 * is put in exit_qualification (see 3B, "Basic VM-Exit Information").
	 * For how an actual address is calculated from all these components,
	 * refer to Vol. 1, "Operand Addressing".
	 */
	int  scaling = vmx_instruction_info & 3;
	int  addr_size = (vmx_instruction_info >> 7) & 7;
	bool is_reg = vmx_instruction_info & (1u << 10);
	int  seg_reg = (vmx_instruction_info >> 15) & 7;
	int  index_reg = (vmx_instruction_info >> 18) & 0xf;
	bool index_is_valid = !(vmx_instruction_info & (1u << 22));
	int  base_reg       = (vmx_instruction_info >> 23) & 0xf;
	bool base_is_valid  = !(vmx_instruction_info & (1u << 27));

	if (is_reg) {
		kvm_queue_exception(vcpu, UD_VECTOR);
		return 1;
	}

	/* Addr = segment_base + offset */
	/* offset = base + [index * scale] + displacement */
	off = exit_qualification; /* holds the displacement */
	if (addr_size == 1)
		off = (gva_t)sign_extend64(off, 31);
	else if (addr_size == 0)
		off = (gva_t)sign_extend64(off, 15);
	if (base_is_valid)
		off += kvm_register_read(vcpu, base_reg);
	if (index_is_valid)
		off += kvm_register_read(vcpu, index_reg)<<scaling;
	vmx_get_segment(vcpu, &s, seg_reg);

	/*
	 * The effective address, i.e. @off, of a memory operand is truncated
	 * based on the address size of the instruction.  Note that this is
	 * the *effective address*, i.e. the address prior to accounting for
	 * the segment's base.
	 */
	if (addr_size == 1) /* 32 bit */
		off &= 0xffffffff;
	else if (addr_size == 0) /* 16 bit */
		off &= 0xffff;

	/* Checks for #GP/#SS exceptions. */
	exn = false;
	if (is_long_mode(vcpu)) {
		/*
		 * The virtual/linear address is never truncated in 64-bit
		 * mode, e.g. a 32-bit address size can yield a 64-bit virtual
		 * address when using FS/GS with a non-zero base.
		 */
		*ret = s.base + off;

		/* Long mode: #GP(0)/#SS(0) if the memory address is in a
		 * non-canonical form. This is the only check on the memory
		 * destination for long mode!
		 */
		exn = is_noncanonical_address(*ret, vcpu);
	} else if (is_protmode(vcpu)) {
		/*
		 * When not in long mode, the virtual/linear address is
		 * unconditionally truncated to 32 bits regardless of the
		 * address size.
		 */
		*ret = (s.base + off) & 0xffffffff;

		/* Protected mode: apply checks for segment validity in the
		 * following order:
		 * - segment type check (#GP(0) may be thrown)
		 * - usability check (#GP(0)/#SS(0))
		 * - limit check (#GP(0)/#SS(0))
		 */
		if (wr)
			/* #GP(0) if the destination operand is located in a
			 * read-only data segment or any code segment.
			 */
			exn = ((s.type & 0xa) == 0 || (s.type & 8));
		else
			/* #GP(0) if the source operand is located in an
			 * execute-only code segment
			 */
			exn = ((s.type & 0xa) == 8);
		if (exn) {
			kvm_queue_exception_e(vcpu, GP_VECTOR, 0);
			return 1;
		}
		/* Protected mode: #GP(0)/#SS(0) if the segment is unusable.
		 */
		exn = (s.unusable != 0);

		/*
		 * Protected mode: #GP(0)/#SS(0) if the memory operand is
		 * outside the segment limit.  All CPUs that support VMX ignore
		 * limit checks for flat segments, i.e. segments with base==0,
		 * limit==0xffffffff and of type expand-up data or code.
		 */
		if (!(s.base == 0 && s.limit == 0xffffffff &&
		     ((s.type & 8) || !(s.type & 4))))
			exn = exn || (off + sizeof(u64) > s.limit);
	}
	if (exn) {
		kvm_queue_exception_e(vcpu,
				      seg_reg == VCPU_SREG_SS ?
						SS_VECTOR : GP_VECTOR,
				      0);
		return 1;
	}

	return 0;
}

static int nested_vmx_get_vmptr(struct kvm_vcpu *vcpu, gpa_t *vmpointer)
{
	gva_t gva;
	struct x86_exception e;

	if (get_vmx_mem_address(vcpu, vmcs_readl(EXIT_QUALIFICATION),
			vmcs_read32(VMX_INSTRUCTION_INFO), false, &gva))
		return 1;

	if (kvm_read_guest_virt(vcpu, gva, vmpointer, sizeof(*vmpointer), &e)) {
		kvm_inject_page_fault(vcpu, &e);
		return 1;
	}

	return 0;
}

/*
 * Allocate a shadow VMCS and associate it with the currently loaded
 * VMCS, unless such a shadow VMCS already exists. The newly allocated
 * VMCS is also VMCLEARed, so that it is ready for use.
 */
static struct vmcs *alloc_shadow_vmcs(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	struct loaded_vmcs *loaded_vmcs = vmx->loaded_vmcs;

	/*
	 * We should allocate a shadow vmcs for vmcs01 only when L1
	 * executes VMXON and free it when L1 executes VMXOFF.
	 * As it is invalid to execute VMXON twice, we shouldn't reach
	 * here when vmcs01 already have an allocated shadow vmcs.
	 */
	WARN_ON(loaded_vmcs == &vmx->vmcs01 && loaded_vmcs->shadow_vmcs);

	if (!loaded_vmcs->shadow_vmcs) {
		loaded_vmcs->shadow_vmcs = alloc_vmcs(true);
		if (loaded_vmcs->shadow_vmcs)
			vmcs_clear(loaded_vmcs->shadow_vmcs);
	}
	return loaded_vmcs->shadow_vmcs;
}

static int enter_vmx_operation(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	int r;

	r = alloc_loaded_vmcs(&vmx->nested.vmcs02);
	if (r < 0)
		goto out_vmcs02;

	vmx->nested.cached_vmcs12 = kzalloc(VMCS12_SIZE, GFP_KERNEL);
	if (!vmx->nested.cached_vmcs12)
		goto out_cached_vmcs12;

	vmx->nested.cached_shadow_vmcs12 = kzalloc(VMCS12_SIZE, GFP_KERNEL);
	if (!vmx->nested.cached_shadow_vmcs12)
		goto out_cached_shadow_vmcs12;

	if (enable_shadow_vmcs && !alloc_shadow_vmcs(vcpu))
		goto out_shadow_vmcs;

	hrtimer_init(&vmx->nested.preemption_timer, CLOCK_MONOTONIC,
		     HRTIMER_MODE_REL_PINNED);
	vmx->nested.preemption_timer.function = vmx_preemption_timer_fn;

	vmx->nested.vpid02 = allocate_vpid();

	vmx->nested.vmxon = true;
	return 0;

out_shadow_vmcs:
	kfree(vmx->nested.cached_shadow_vmcs12);

out_cached_shadow_vmcs12:
	kfree(vmx->nested.cached_vmcs12);

out_cached_vmcs12:
	free_loaded_vmcs(&vmx->nested.vmcs02);

out_vmcs02:
	return -ENOMEM;
}

/*
 * Emulate the VMXON instruction.
 * Currently, we just remember that VMX is active, and do not save or even
 * inspect the argument to VMXON (the so-called "VMXON pointer") because we
 * do not currently need to store anything in that guest-allocated memory
 * region. Consequently, VMCLEAR and VMPTRLD also do not verify that the their
 * argument is different from the VMXON pointer (which the spec says they do).
 */
static int handle_vmon(struct kvm_vcpu *vcpu)
{
	int ret;
	gpa_t vmptr;
	struct page *page;
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	const u64 VMXON_NEEDED_FEATURES = FEATURE_CONTROL_LOCKED
		| FEATURE_CONTROL_VMXON_ENABLED_OUTSIDE_SMX;

	/*
	 * The Intel VMX Instruction Reference lists a bunch of bits that are
	 * prerequisite to running VMXON, most notably cr4.VMXE must be set to
	 * 1 (see vmx_set_cr4() for when we allow the guest to set this).
	 * Otherwise, we should fail with #UD.  But most faulting conditions
	 * have already been checked by hardware, prior to the VM-exit for
	 * VMXON.  We do test guest cr4.VMXE because processor CR4 always has
	 * that bit set to 1 in non-root mode.
	 */
	if (!kvm_read_cr4_bits(vcpu, X86_CR4_VMXE)) {
		kvm_queue_exception(vcpu, UD_VECTOR);
		return 1;
	}

	/* CPL=0 must be checked manually. */
	if (vmx_get_cpl(vcpu)) {
		kvm_inject_gp(vcpu, 0);
		return 1;
	}

	if (vmx->nested.vmxon) {
		nested_vmx_failValid(vcpu, VMXERR_VMXON_IN_VMX_ROOT_OPERATION);
		return kvm_skip_emulated_instruction(vcpu);
	}

	if ((vmx->msr_ia32_feature_control & VMXON_NEEDED_FEATURES)
			!= VMXON_NEEDED_FEATURES) {
		kvm_inject_gp(vcpu, 0);
		return 1;
	}

	if (nested_vmx_get_vmptr(vcpu, &vmptr))
		return 1;

	/*
	 * SDM 3: 24.11.5
	 * The first 4 bytes of VMXON region contain the supported
	 * VMCS revision identifier
	 *
	 * Note - IA32_VMX_BASIC[48] will never be 1 for the nested case;
	 * which replaces physical address width with 32
	 */
	if (!PAGE_ALIGNED(vmptr) || (vmptr >> cpuid_maxphyaddr(vcpu))) {
		nested_vmx_failInvalid(vcpu);
		return kvm_skip_emulated_instruction(vcpu);
	}

	page = kvm_vcpu_gpa_to_page(vcpu, vmptr);
	if (is_error_page(page)) {
		nested_vmx_failInvalid(vcpu);
		return kvm_skip_emulated_instruction(vcpu);
	}
	if (*(u32 *)kmap(page) != VMCS12_REVISION) {
		kunmap(page);
		kvm_release_page_clean(page);
		nested_vmx_failInvalid(vcpu);
		return kvm_skip_emulated_instruction(vcpu);
	}
	kunmap(page);
	kvm_release_page_clean(page);

	vmx->nested.vmxon_ptr = vmptr;
	ret = enter_vmx_operation(vcpu);
	if (ret)
		return ret;

	nested_vmx_succeed(vcpu);
	return kvm_skip_emulated_instruction(vcpu);
}

/*
 * Intel's VMX Instruction Reference specifies a common set of prerequisites
 * for running VMX instructions (except VMXON, whose prerequisites are
 * slightly different). It also specifies what exception to inject otherwise.
 * Note that many of these exceptions have priority over VM exits, so they
 * don't have to be checked again here.
 */
static int nested_vmx_check_permission(struct kvm_vcpu *vcpu)
{
	if (!to_vmx(vcpu)->nested.vmxon) {
		kvm_queue_exception(vcpu, UD_VECTOR);
		return 0;
	}

	if (vmx_get_cpl(vcpu)) {
		kvm_inject_gp(vcpu, 0);
		return 0;
	}

	return 1;
}

static void vmx_disable_shadow_vmcs(struct vcpu_vmx *vmx)
{
	vmcs_clear_bits(SECONDARY_VM_EXEC_CONTROL, SECONDARY_EXEC_SHADOW_VMCS);
	vmcs_write64(VMCS_LINK_POINTER, -1ull);
	vmx->nested.sync_shadow_vmcs = false;
}

static inline void nested_release_vmcs12(struct vcpu_vmx *vmx)
{
	if (vmx->nested.current_vmptr == -1ull)
		return;

	if (enable_shadow_vmcs) {
		/* copy to memory all shadowed fields in case
		   they were modified */
		copy_shadow_to_vmcs12(vmx);
		vmx_disable_shadow_vmcs(vmx);
	}
	vmx->nested.posted_intr_nv = -1;

	/* Flush VMCS12 to guest memory */
	kvm_vcpu_write_guest_page(&vmx->vcpu,
				  vmx->nested.current_vmptr >> PAGE_SHIFT,
				  vmx->nested.cached_vmcs12, 0, VMCS12_SIZE);

	vmx->nested.current_vmptr = -1ull;
}

/*
 * Free whatever needs to be freed from vmx->nested when L1 goes down, or
 * just stops using VMX.
 */
static void free_nested(struct vcpu_vmx *vmx)
{
	if (!vmx->nested.vmxon && !vmx->nested.smm.vmxon)
		return;

	kvm_clear_request(KVM_REQ_GET_VMCS12_PAGES, &vmx->vcpu);

	hrtimer_cancel(&vmx->nested.preemption_timer);
	vmx->nested.vmxon = false;
	vmx->nested.smm.vmxon = false;
	free_vpid(vmx->nested.vpid02);
	vmx->nested.posted_intr_nv = -1;
	vmx->nested.current_vmptr = -1ull;
	if (enable_shadow_vmcs) {
		vmx_disable_shadow_vmcs(vmx);
		vmcs_clear(vmx->vmcs01.shadow_vmcs);
		free_vmcs(vmx->vmcs01.shadow_vmcs);
		vmx->vmcs01.shadow_vmcs = NULL;
	}
	kfree(vmx->nested.cached_vmcs12);
	kfree(vmx->nested.cached_shadow_vmcs12);
	/* Unpin physical memory we referred to in the vmcs02 */
	if (vmx->nested.apic_access_page) {
		kvm_release_page_dirty(vmx->nested.apic_access_page);
		vmx->nested.apic_access_page = NULL;
	}
	if (vmx->nested.virtual_apic_page) {
		kvm_release_page_dirty(vmx->nested.virtual_apic_page);
		vmx->nested.virtual_apic_page = NULL;
	}
	if (vmx->nested.pi_desc_page) {
		kunmap(vmx->nested.pi_desc_page);
		kvm_release_page_dirty(vmx->nested.pi_desc_page);
		vmx->nested.pi_desc_page = NULL;
		vmx->nested.pi_desc = NULL;
	}

	free_loaded_vmcs(&vmx->nested.vmcs02);
}

/* Emulate the VMXOFF instruction */
static int handle_vmoff(struct kvm_vcpu *vcpu)
{
	if (!nested_vmx_check_permission(vcpu))
		return 1;
	free_nested(to_vmx(vcpu));
	nested_vmx_succeed(vcpu);
	return kvm_skip_emulated_instruction(vcpu);
}

/* Emulate the VMCLEAR instruction */
static int handle_vmclear(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	u32 zero = 0;
	gpa_t vmptr;

	if (!nested_vmx_check_permission(vcpu))
		return 1;

	if (nested_vmx_get_vmptr(vcpu, &vmptr))
		return 1;

	if (!PAGE_ALIGNED(vmptr) || (vmptr >> cpuid_maxphyaddr(vcpu))) {
		nested_vmx_failValid(vcpu, VMXERR_VMCLEAR_INVALID_ADDRESS);
		return kvm_skip_emulated_instruction(vcpu);
	}

	if (vmptr == vmx->nested.vmxon_ptr) {
		nested_vmx_failValid(vcpu, VMXERR_VMCLEAR_VMXON_POINTER);
		return kvm_skip_emulated_instruction(vcpu);
	}

	if (vmptr == vmx->nested.current_vmptr)
		nested_release_vmcs12(vmx);

	kvm_vcpu_write_guest(vcpu,
			vmptr + offsetof(struct vmcs12, launch_state),
			&zero, sizeof(zero));

	nested_vmx_succeed(vcpu);
	return kvm_skip_emulated_instruction(vcpu);
}

static int nested_vmx_run(struct kvm_vcpu *vcpu, bool launch);

/* Emulate the VMLAUNCH instruction */
static int handle_vmlaunch(struct kvm_vcpu *vcpu)
{
	return nested_vmx_run(vcpu, true);
}

/* Emulate the VMRESUME instruction */
static int handle_vmresume(struct kvm_vcpu *vcpu)
{

	return nested_vmx_run(vcpu, false);
}

/*
 * Read a vmcs12 field. Since these can have varying lengths and we return
 * one type, we chose the biggest type (u64) and zero-extend the return value
 * to that size. Note that the caller, handle_vmread, might need to use only
 * some of the bits we return here (e.g., on 32-bit guests, only 32 bits of
 * 64-bit fields are to be returned).
 */
static inline int vmcs12_read_any(struct vmcs12 *vmcs12,
				  unsigned long field, u64 *ret)
{
	short offset = vmcs_field_to_offset(field);
	char *p;

	if (offset < 0)
		return offset;

	p = (char *)vmcs12 + offset;

	switch (vmcs_field_width(field)) {
	case VMCS_FIELD_WIDTH_NATURAL_WIDTH:
		*ret = *((natural_width *)p);
		return 0;
	case VMCS_FIELD_WIDTH_U16:
		*ret = *((u16 *)p);
		return 0;
	case VMCS_FIELD_WIDTH_U32:
		*ret = *((u32 *)p);
		return 0;
	case VMCS_FIELD_WIDTH_U64:
		*ret = *((u64 *)p);
		return 0;
	default:
		WARN_ON(1);
		return -ENOENT;
	}
}


static inline int vmcs12_write_any(struct vmcs12 *vmcs12,
				   unsigned long field, u64 field_value){
	short offset = vmcs_field_to_offset(field);
	char *p = (char *)vmcs12 + offset;
	if (offset < 0)
		return offset;

	switch (vmcs_field_width(field)) {
	case VMCS_FIELD_WIDTH_U16:
		*(u16 *)p = field_value;
		return 0;
	case VMCS_FIELD_WIDTH_U32:
		*(u32 *)p = field_value;
		return 0;
	case VMCS_FIELD_WIDTH_U64:
		*(u64 *)p = field_value;
		return 0;
	case VMCS_FIELD_WIDTH_NATURAL_WIDTH:
		*(natural_width *)p = field_value;
		return 0;
	default:
		WARN_ON(1);
		return -ENOENT;
	}

}

/*
 * Copy the writable VMCS shadow fields back to the VMCS12, in case
 * they have been modified by the L1 guest. Note that the "read-only"
 * VM-exit information fields are actually writable if the vCPU is
 * configured to support "VMWRITE to any supported field in the VMCS."
 */
static void copy_shadow_to_vmcs12(struct vcpu_vmx *vmx)
{
	const u16 *fields[] = {
		shadow_read_write_fields,
		shadow_read_only_fields
	};
	const int max_fields[] = {
		max_shadow_read_write_fields,
		max_shadow_read_only_fields
	};
	int i, q;
	unsigned long field;
	u64 field_value;
	struct vmcs *shadow_vmcs = vmx->vmcs01.shadow_vmcs;

	if (WARN_ON(!shadow_vmcs))
		return;

	preempt_disable();

	vmcs_load(shadow_vmcs);

	for (q = 0; q < ARRAY_SIZE(fields); q++) {
		for (i = 0; i < max_fields[q]; i++) {
			field = fields[q][i];
			field_value = __vmcs_readl(field);
			vmcs12_write_any(get_vmcs12(&vmx->vcpu), field, field_value);
		}
		/*
		 * Skip the VM-exit information fields if they are read-only.
		 */
		if (!nested_cpu_has_vmwrite_any_field(&vmx->vcpu))
			break;
	}

	vmcs_clear(shadow_vmcs);
	vmcs_load(vmx->loaded_vmcs->vmcs);

	preempt_enable();
}

static void copy_vmcs12_to_shadow(struct vcpu_vmx *vmx)
{
	const u16 *fields[] = {
		shadow_read_write_fields,
		shadow_read_only_fields
	};
	const int max_fields[] = {
		max_shadow_read_write_fields,
		max_shadow_read_only_fields
	};
	int i, q;
	unsigned long field;
	u64 field_value = 0;
	struct vmcs *shadow_vmcs = vmx->vmcs01.shadow_vmcs;

	if (WARN_ON(!shadow_vmcs))
		return;

	vmcs_load(shadow_vmcs);

	for (q = 0; q < ARRAY_SIZE(fields); q++) {
		for (i = 0; i < max_fields[q]; i++) {
			field = fields[q][i];
			vmcs12_read_any(get_vmcs12(&vmx->vcpu), field, &field_value);
			__vmcs_writel(field, field_value);
		}
	}

	vmcs_clear(shadow_vmcs);
	vmcs_load(vmx->loaded_vmcs->vmcs);
}

/*
 * VMX instructions which assume a current vmcs12 (i.e., that VMPTRLD was
 * used before) all generate the same failure when it is missing.
 */
static int nested_vmx_check_vmcs12(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	if (vmx->nested.current_vmptr == -1ull) {
		nested_vmx_failInvalid(vcpu);
		return 0;
	}
	return 1;
}

static int handle_vmread(struct kvm_vcpu *vcpu)
{
	unsigned long field;
	u64 field_value;
	unsigned long exit_qualification = vmcs_readl(EXIT_QUALIFICATION);
	u32 vmx_instruction_info = vmcs_read32(VMX_INSTRUCTION_INFO);
	gva_t gva = 0;
	struct vmcs12 *vmcs12;
	struct x86_exception e;

	if (!nested_vmx_check_permission(vcpu))
		return 1;

	if (!nested_vmx_check_vmcs12(vcpu))
		return kvm_skip_emulated_instruction(vcpu);

	if (!is_guest_mode(vcpu))
		vmcs12 = get_vmcs12(vcpu);
	else {
		/*
		 * When vmcs->vmcs_link_pointer is -1ull, any VMREAD
		 * to shadowed-field sets the ALU flags for VMfailInvalid.
		 */
		if (get_vmcs12(vcpu)->vmcs_link_pointer == -1ull) {
			nested_vmx_failInvalid(vcpu);
			return kvm_skip_emulated_instruction(vcpu);
		}
		vmcs12 = get_shadow_vmcs12(vcpu);
	}

	/* Decode instruction info and find the field to read */
	field = kvm_register_readl(vcpu, (((vmx_instruction_info) >> 28) & 0xf));
	/* Read the field, zero-extended to a u64 field_value */
	if (vmcs12_read_any(vmcs12, field, &field_value) < 0) {
		nested_vmx_failValid(vcpu, VMXERR_UNSUPPORTED_VMCS_COMPONENT);
		return kvm_skip_emulated_instruction(vcpu);
	}
	/*
	 * Now copy part of this value to register or memory, as requested.
	 * Note that the number of bits actually copied is 32 or 64 depending
	 * on the guest's mode (32 or 64 bit), not on the given field's length.
	 */
	if (vmx_instruction_info & (1u << 10)) {
		kvm_register_writel(vcpu, (((vmx_instruction_info) >> 3) & 0xf),
			field_value);
	} else {
		if (get_vmx_mem_address(vcpu, exit_qualification,
				vmx_instruction_info, true, &gva))
			return 1;
		/* _system ok, nested_vmx_check_permission has verified cpl=0 */
		if (kvm_write_guest_virt_system(vcpu, gva, &field_value,
						(is_long_mode(vcpu) ? 8 : 4),
						&e)) {
			kvm_inject_page_fault(vcpu, &e);
			return 1;
		}
	}

	nested_vmx_succeed(vcpu);
	return kvm_skip_emulated_instruction(vcpu);
}


static int handle_vmwrite(struct kvm_vcpu *vcpu)
{
	unsigned long field;
	gva_t gva;
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	unsigned long exit_qualification = vmcs_readl(EXIT_QUALIFICATION);
	u32 vmx_instruction_info = vmcs_read32(VMX_INSTRUCTION_INFO);

	/* The value to write might be 32 or 64 bits, depending on L1's long
	 * mode, and eventually we need to write that into a field of several
	 * possible lengths. The code below first zero-extends the value to 64
	 * bit (field_value), and then copies only the appropriate number of
	 * bits into the vmcs12 field.
	 */
	u64 field_value = 0;
	struct x86_exception e;
	struct vmcs12 *vmcs12;

	if (!nested_vmx_check_permission(vcpu))
		return 1;

	if (!nested_vmx_check_vmcs12(vcpu))
		return kvm_skip_emulated_instruction(vcpu);

	if (vmx_instruction_info & (1u << 10))
		field_value = kvm_register_readl(vcpu,
			(((vmx_instruction_info) >> 3) & 0xf));
	else {
		if (get_vmx_mem_address(vcpu, exit_qualification,
				vmx_instruction_info, false, &gva))
			return 1;
		if (kvm_read_guest_virt(vcpu, gva, &field_value,
					(is_64_bit_mode(vcpu) ? 8 : 4), &e)) {
			kvm_inject_page_fault(vcpu, &e);
			return 1;
		}
	}


	field = kvm_register_readl(vcpu, (((vmx_instruction_info) >> 28) & 0xf));
	/*
	 * If the vCPU supports "VMWRITE to any supported field in the
	 * VMCS," then the "read-only" fields are actually read/write.
	 */
	if (vmcs_field_readonly(field) &&
	    !nested_cpu_has_vmwrite_any_field(vcpu)) {
		nested_vmx_failValid(vcpu,
			VMXERR_VMWRITE_READ_ONLY_VMCS_COMPONENT);
		return kvm_skip_emulated_instruction(vcpu);
	}

	if (!is_guest_mode(vcpu))
		vmcs12 = get_vmcs12(vcpu);
	else {
		/*
		 * When vmcs->vmcs_link_pointer is -1ull, any VMWRITE
		 * to shadowed-field sets the ALU flags for VMfailInvalid.
		 */
		if (get_vmcs12(vcpu)->vmcs_link_pointer == -1ull) {
			nested_vmx_failInvalid(vcpu);
			return kvm_skip_emulated_instruction(vcpu);
		}
		vmcs12 = get_shadow_vmcs12(vcpu);

	}

	if (vmcs12_write_any(vmcs12, field, field_value) < 0) {
		nested_vmx_failValid(vcpu, VMXERR_UNSUPPORTED_VMCS_COMPONENT);
		return kvm_skip_emulated_instruction(vcpu);
	}

	/*
	 * Do not track vmcs12 dirty-state if in guest-mode
	 * as we actually dirty shadow vmcs12 instead of vmcs12.
	 */
	if (!is_guest_mode(vcpu)) {
		switch (field) {
#define SHADOW_FIELD_RW(x) case x:
#include "vmx_shadow_fields.h"
			/*
			 * The fields that can be updated by L1 without a vmexit are
			 * always updated in the vmcs02, the others go down the slow
			 * path of prepare_vmcs02.
			 */
			break;
		default:
			vmx->nested.dirty_vmcs12 = true;
			break;
		}
	}

	nested_vmx_succeed(vcpu);
	return kvm_skip_emulated_instruction(vcpu);
}

static void set_current_vmptr(struct vcpu_vmx *vmx, gpa_t vmptr)
{
	vmx->nested.current_vmptr = vmptr;
	if (enable_shadow_vmcs) {
		vmcs_set_bits(SECONDARY_VM_EXEC_CONTROL,
			      SECONDARY_EXEC_SHADOW_VMCS);
		vmcs_write64(VMCS_LINK_POINTER,
			     __pa(vmx->vmcs01.shadow_vmcs));
		vmx->nested.sync_shadow_vmcs = true;
	}
	vmx->nested.dirty_vmcs12 = true;
}

/* Emulate the VMPTRLD instruction */
static int handle_vmptrld(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	gpa_t vmptr;

	if (!nested_vmx_check_permission(vcpu))
		return 1;

	if (nested_vmx_get_vmptr(vcpu, &vmptr))
		return 1;

	if (!PAGE_ALIGNED(vmptr) || (vmptr >> cpuid_maxphyaddr(vcpu))) {
		nested_vmx_failValid(vcpu, VMXERR_VMPTRLD_INVALID_ADDRESS);
		return kvm_skip_emulated_instruction(vcpu);
	}

	if (vmptr == vmx->nested.vmxon_ptr) {
		nested_vmx_failValid(vcpu, VMXERR_VMPTRLD_VMXON_POINTER);
		return kvm_skip_emulated_instruction(vcpu);
	}

	if (vmx->nested.current_vmptr != vmptr) {
		struct vmcs12 *new_vmcs12;
		struct page *page;
		page = kvm_vcpu_gpa_to_page(vcpu, vmptr);
		if (is_error_page(page)) {
			nested_vmx_failInvalid(vcpu);
			return kvm_skip_emulated_instruction(vcpu);
		}
		new_vmcs12 = kmap(page);
		if (new_vmcs12->hdr.revision_id != VMCS12_REVISION ||
		    (new_vmcs12->hdr.shadow_vmcs &&
		     !nested_cpu_has_vmx_shadow_vmcs(vcpu))) {
			kunmap(page);
			kvm_release_page_clean(page);
			nested_vmx_failValid(vcpu,
				VMXERR_VMPTRLD_INCORRECT_VMCS_REVISION_ID);
			return kvm_skip_emulated_instruction(vcpu);
		}

		nested_release_vmcs12(vmx);
		/*
		 * Load VMCS12 from guest memory since it is not already
		 * cached.
		 */
		memcpy(vmx->nested.cached_vmcs12, new_vmcs12, VMCS12_SIZE);
		kunmap(page);
		kvm_release_page_clean(page);

		set_current_vmptr(vmx, vmptr);
	}

	nested_vmx_succeed(vcpu);
	return kvm_skip_emulated_instruction(vcpu);
}

/* Emulate the VMPTRST instruction */
static int handle_vmptrst(struct kvm_vcpu *vcpu)
{
	unsigned long exit_qual = vmcs_readl(EXIT_QUALIFICATION);
	u32 instr_info = vmcs_read32(VMX_INSTRUCTION_INFO);
	gpa_t current_vmptr = to_vmx(vcpu)->nested.current_vmptr;
	struct x86_exception e;
	gva_t gva;

	if (!nested_vmx_check_permission(vcpu))
		return 1;

	if (get_vmx_mem_address(vcpu, exit_qual, instr_info, true, &gva))
		return 1;
	/* *_system ok, nested_vmx_check_permission has verified cpl=0 */
	if (kvm_write_guest_virt_system(vcpu, gva, (void *)&current_vmptr,
					sizeof(gpa_t), &e)) {
		kvm_inject_page_fault(vcpu, &e);
		return 1;
	}
	nested_vmx_succeed(vcpu);
	return kvm_skip_emulated_instruction(vcpu);
}

/* Emulate the INVEPT instruction */
static int handle_invept(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	u32 vmx_instruction_info, types;
	unsigned long type;
	gva_t gva;
	struct x86_exception e;
	struct {
		u64 eptp, gpa;
	} operand;

	if (!(vmx->nested.msrs.secondary_ctls_high &
	      SECONDARY_EXEC_ENABLE_EPT) ||
	    !(vmx->nested.msrs.ept_caps & VMX_EPT_INVEPT_BIT)) {
		kvm_queue_exception(vcpu, UD_VECTOR);
		return 1;
	}

	if (!nested_vmx_check_permission(vcpu))
		return 1;

	vmx_instruction_info = vmcs_read32(VMX_INSTRUCTION_INFO);
	type = kvm_register_readl(vcpu, (vmx_instruction_info >> 28) & 0xf);

	types = (vmx->nested.msrs.ept_caps >> VMX_EPT_EXTENT_SHIFT) & 6;

	if (type >= 32 || !(types & (1 << type))) {
		nested_vmx_failValid(vcpu,
				VMXERR_INVALID_OPERAND_TO_INVEPT_INVVPID);
		return kvm_skip_emulated_instruction(vcpu);
	}

	/* According to the Intel VMX instruction reference, the memory
	 * operand is read even if it isn't needed (e.g., for type==global)
	 */
	if (get_vmx_mem_address(vcpu, vmcs_readl(EXIT_QUALIFICATION),
			vmx_instruction_info, false, &gva))
		return 1;
	if (kvm_read_guest_virt(vcpu, gva, &operand, sizeof(operand), &e)) {
		kvm_inject_page_fault(vcpu, &e);
		return 1;
	}

	switch (type) {
	case VMX_EPT_EXTENT_GLOBAL:
	/*
	 * TODO: track mappings and invalidate
	 * single context requests appropriately
	 */
	case VMX_EPT_EXTENT_CONTEXT:
		kvm_mmu_sync_roots(vcpu);
		kvm_make_request(KVM_REQ_TLB_FLUSH, vcpu);
		nested_vmx_succeed(vcpu);
		break;
	default:
		BUG_ON(1);
		break;
	}

	return kvm_skip_emulated_instruction(vcpu);
}

static int handle_invvpid(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	u32 vmx_instruction_info;
	unsigned long type, types;
	gva_t gva;
	struct x86_exception e;
	struct {
		u64 vpid;
		u64 gla;
	} operand;

	if (!(vmx->nested.msrs.secondary_ctls_high &
	      SECONDARY_EXEC_ENABLE_VPID) ||
			!(vmx->nested.msrs.vpid_caps & VMX_VPID_INVVPID_BIT)) {
		kvm_queue_exception(vcpu, UD_VECTOR);
		return 1;
	}

	if (!nested_vmx_check_permission(vcpu))
		return 1;

	vmx_instruction_info = vmcs_read32(VMX_INSTRUCTION_INFO);
	type = kvm_register_readl(vcpu, (vmx_instruction_info >> 28) & 0xf);

	types = (vmx->nested.msrs.vpid_caps &
			VMX_VPID_EXTENT_SUPPORTED_MASK) >> 8;

	if (type >= 32 || !(types & (1 << type))) {
		nested_vmx_failValid(vcpu,
			VMXERR_INVALID_OPERAND_TO_INVEPT_INVVPID);
		return kvm_skip_emulated_instruction(vcpu);
	}

	/* according to the intel vmx instruction reference, the memory
	 * operand is read even if it isn't needed (e.g., for type==global)
	 */
	if (get_vmx_mem_address(vcpu, vmcs_readl(EXIT_QUALIFICATION),
			vmx_instruction_info, false, &gva))
		return 1;
	if (kvm_read_guest_virt(vcpu, gva, &operand, sizeof(operand), &e)) {
		kvm_inject_page_fault(vcpu, &e);
		return 1;
	}
	if (operand.vpid >> 16) {
		nested_vmx_failValid(vcpu,
			VMXERR_INVALID_OPERAND_TO_INVEPT_INVVPID);
		return kvm_skip_emulated_instruction(vcpu);
	}

	switch (type) {
	case VMX_VPID_EXTENT_INDIVIDUAL_ADDR:
		if (!operand.vpid ||
		    is_noncanonical_address(operand.gla, vcpu)) {
			nested_vmx_failValid(vcpu,
				VMXERR_INVALID_OPERAND_TO_INVEPT_INVVPID);
			return kvm_skip_emulated_instruction(vcpu);
		}
		if (cpu_has_vmx_invvpid_individual_addr() &&
		    vmx->nested.vpid02) {
			__invvpid(VMX_VPID_EXTENT_INDIVIDUAL_ADDR,
				vmx->nested.vpid02, operand.gla);
		} else
			__vmx_flush_tlb(vcpu, vmx->nested.vpid02, true);
		break;
	case VMX_VPID_EXTENT_SINGLE_CONTEXT:
	case VMX_VPID_EXTENT_SINGLE_NON_GLOBAL:
		if (!operand.vpid) {
			nested_vmx_failValid(vcpu,
				VMXERR_INVALID_OPERAND_TO_INVEPT_INVVPID);
			return kvm_skip_emulated_instruction(vcpu);
		}
		__vmx_flush_tlb(vcpu, vmx->nested.vpid02, true);
		break;
	case VMX_VPID_EXTENT_ALL_CONTEXT:
		__vmx_flush_tlb(vcpu, vmx->nested.vpid02, true);
		break;
	default:
		WARN_ON_ONCE(1);
		return kvm_skip_emulated_instruction(vcpu);
	}

	nested_vmx_succeed(vcpu);

	return kvm_skip_emulated_instruction(vcpu);
}

static int handle_invpcid(struct kvm_vcpu *vcpu)
{
	u32 vmx_instruction_info;
	unsigned long type;
	bool pcid_enabled;
	gva_t gva;
	struct x86_exception e;
	unsigned i;
	unsigned long roots_to_free = 0;
	struct {
		u64 pcid;
		u64 gla;
	} operand;

	if (!guest_cpuid_has(vcpu, X86_FEATURE_INVPCID)) {
		kvm_queue_exception(vcpu, UD_VECTOR);
		return 1;
	}

	vmx_instruction_info = vmcs_read32(VMX_INSTRUCTION_INFO);
	type = kvm_register_readl(vcpu, (vmx_instruction_info >> 28) & 0xf);

	if (type > 3) {
		kvm_inject_gp(vcpu, 0);
		return 1;
	}

	/* According to the Intel instruction reference, the memory operand
	 * is read even if it isn't needed (e.g., for type==all)
	 */
	if (get_vmx_mem_address(vcpu, vmcs_readl(EXIT_QUALIFICATION),
				vmx_instruction_info, false, &gva))
		return 1;

	if (kvm_read_guest_virt(vcpu, gva, &operand, sizeof(operand), &e)) {
		kvm_inject_page_fault(vcpu, &e);
		return 1;
	}

	if (operand.pcid >> 12 != 0) {
		kvm_inject_gp(vcpu, 0);
		return 1;
	}

	pcid_enabled = kvm_read_cr4_bits(vcpu, X86_CR4_PCIDE);

	switch (type) {
	case INVPCID_TYPE_INDIV_ADDR:
		if ((!pcid_enabled && (operand.pcid != 0)) ||
		    is_noncanonical_address(operand.gla, vcpu)) {
			kvm_inject_gp(vcpu, 0);
			return 1;
		}
		kvm_mmu_invpcid_gva(vcpu, operand.gla, operand.pcid);
		return kvm_skip_emulated_instruction(vcpu);

	case INVPCID_TYPE_SINGLE_CTXT:
		if (!pcid_enabled && (operand.pcid != 0)) {
			kvm_inject_gp(vcpu, 0);
			return 1;
		}

		if (kvm_get_active_pcid(vcpu) == operand.pcid) {
			kvm_mmu_sync_roots(vcpu);
			kvm_make_request(KVM_REQ_TLB_FLUSH, vcpu);
		}

		for (i = 0; i < KVM_MMU_NUM_PREV_ROOTS; i++)
			if (kvm_get_pcid(vcpu, vcpu->arch.mmu.prev_roots[i].cr3)
			    == operand.pcid)
				roots_to_free |= KVM_MMU_ROOT_PREVIOUS(i);

		kvm_mmu_free_roots(vcpu, roots_to_free);
		/*
		 * If neither the current cr3 nor any of the prev_roots use the
		 * given PCID, then nothing needs to be done here because a
		 * resync will happen anyway before switching to any other CR3.
		 */

		return kvm_skip_emulated_instruction(vcpu);

	case INVPCID_TYPE_ALL_NON_GLOBAL:
		/*
		 * Currently, KVM doesn't mark global entries in the shadow
		 * page tables, so a non-global flush just degenerates to a
		 * global flush. If needed, we could optimize this later by
		 * keeping track of global entries in shadow page tables.
		 */

		/* fall-through */
	case INVPCID_TYPE_ALL_INCL_GLOBAL:
		kvm_mmu_unload(vcpu);
		return kvm_skip_emulated_instruction(vcpu);

	default:
		BUG(); /* We have already checked above that type <= 3 */
	}
}

static int handle_pml_full(struct kvm_vcpu *vcpu)
{
	unsigned long exit_qualification;

	trace_kvm_pml_full(vcpu->vcpu_id);

	exit_qualification = vmcs_readl(EXIT_QUALIFICATION);

	/*
	 * PML buffer FULL happened while executing iret from NMI,
	 * "blocked by NMI" bit has to be set before next VM entry.
	 */
	if (!(to_vmx(vcpu)->idt_vectoring_info & VECTORING_INFO_VALID_MASK) &&
			enable_vnmi &&
			(exit_qualification & INTR_INFO_UNBLOCK_NMI))
		vmcs_set_bits(GUEST_INTERRUPTIBILITY_INFO,
				GUEST_INTR_STATE_NMI);

	/*
	 * PML buffer already flushed at beginning of VMEXIT. Nothing to do
	 * here.., and there's no userspace involvement needed for PML.
	 */
	return 1;
}

static int handle_preemption_timer(struct kvm_vcpu *vcpu)
{
	if (!to_vmx(vcpu)->req_immediate_exit)
		kvm_lapic_expired_hv_timer(vcpu);
	return 1;
}

static bool valid_ept_address(struct kvm_vcpu *vcpu, u64 address)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	int maxphyaddr = cpuid_maxphyaddr(vcpu);

	/* Check for memory type validity */
	switch (address & VMX_EPTP_MT_MASK) {
	case VMX_EPTP_MT_UC:
		if (!(vmx->nested.msrs.ept_caps & VMX_EPTP_UC_BIT))
			return false;
		break;
	case VMX_EPTP_MT_WB:
		if (!(vmx->nested.msrs.ept_caps & VMX_EPTP_WB_BIT))
			return false;
		break;
	default:
		return false;
	}

	/* only 4 levels page-walk length are valid */
	if ((address & VMX_EPTP_PWL_MASK) != VMX_EPTP_PWL_4)
		return false;

	/* Reserved bits should not be set */
	if (address >> maxphyaddr || ((address >> 7) & 0x1f))
		return false;

	/* AD, if set, should be supported */
	if (address & VMX_EPTP_AD_ENABLE_BIT) {
		if (!(vmx->nested.msrs.ept_caps & VMX_EPT_AD_BIT))
			return false;
	}

	return true;
}

static int nested_vmx_eptp_switching(struct kvm_vcpu *vcpu,
				     struct vmcs12 *vmcs12)
{
	u32 index = vcpu->arch.regs[VCPU_REGS_RCX];
	u64 address;
	bool accessed_dirty;
	struct kvm_mmu *mmu = vcpu->arch.walk_mmu;

	if (!nested_cpu_has_eptp_switching(vmcs12) ||
	    !nested_cpu_has_ept(vmcs12))
		return 1;

	if (index >= VMFUNC_EPTP_ENTRIES)
		return 1;


	if (kvm_vcpu_read_guest_page(vcpu, vmcs12->eptp_list_address >> PAGE_SHIFT,
				     &address, index * 8, 8))
		return 1;

	accessed_dirty = !!(address & VMX_EPTP_AD_ENABLE_BIT);

	/*
	 * If the (L2) guest does a vmfunc to the currently
	 * active ept pointer, we don't have to do anything else
	 */
	if (vmcs12->ept_pointer != address) {
		if (!valid_ept_address(vcpu, address))
			return 1;

		kvm_mmu_unload(vcpu);
		mmu->ept_ad = accessed_dirty;
		mmu->base_role.ad_disabled = !accessed_dirty;
		vmcs12->ept_pointer = address;
		/*
		 * TODO: Check what's the correct approach in case
		 * mmu reload fails. Currently, we just let the next
		 * reload potentially fail
		 */
		kvm_mmu_reload(vcpu);
	}

	return 0;
}

static int handle_vmfunc(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	struct vmcs12 *vmcs12;
	u32 function = vcpu->arch.regs[VCPU_REGS_RAX];

	/*
	 * VMFUNC is only supported for nested guests, but we always enable the
	 * secondary control for simplicity; for non-nested mode, fake that we
	 * didn't by injecting #UD.
	 */
	if (!is_guest_mode(vcpu)) {
		kvm_queue_exception(vcpu, UD_VECTOR);
		return 1;
	}

	vmcs12 = get_vmcs12(vcpu);
	if ((vmcs12->vm_function_control & (1 << function)) == 0)
		goto fail;

	switch (function) {
	case 0:
		if (nested_vmx_eptp_switching(vcpu, vmcs12))
			goto fail;
		break;
	default:
		goto fail;
	}
	return kvm_skip_emulated_instruction(vcpu);

fail:
	nested_vmx_vmexit(vcpu, vmx->exit_reason,
			  vmcs_read32(VM_EXIT_INTR_INFO),
			  vmcs_readl(EXIT_QUALIFICATION));
	return 1;
}

static int handle_encls(struct kvm_vcpu *vcpu)
{
	/*
	 * SGX virtualization is not yet supported.  There is no software
	 * enable bit for SGX, so we have to trap ENCLS and inject a #UD
	 * to prevent the guest from executing ENCLS.
	 */
	kvm_queue_exception(vcpu, UD_VECTOR);
	return 1;
}

/*
 * The exit handlers return 1 if the exit was handled fully and guest execution
 * may resume.  Otherwise they set the kvm_run parameter to indicate what needs
 * to be done to userspace and return 0.
 */
static int (*const kvm_vmx_exit_handlers[])(struct kvm_vcpu *vcpu) = {
	[EXIT_REASON_EXCEPTION_NMI]           = handle_exception,
	[EXIT_REASON_EXTERNAL_INTERRUPT]      = handle_external_interrupt,
	[EXIT_REASON_TRIPLE_FAULT]            = handle_triple_fault,
	[EXIT_REASON_NMI_WINDOW]	      = handle_nmi_window,
	[EXIT_REASON_IO_INSTRUCTION]          = handle_io,
	[EXIT_REASON_CR_ACCESS]               = handle_cr,
	[EXIT_REASON_DR_ACCESS]               = handle_dr,
	[EXIT_REASON_CPUID]                   = handle_cpuid,
	[EXIT_REASON_MSR_READ]                = handle_rdmsr,
	[EXIT_REASON_MSR_WRITE]               = handle_wrmsr,
	[EXIT_REASON_PENDING_INTERRUPT]       = handle_interrupt_window,
	[EXIT_REASON_HLT]                     = handle_halt,
	[EXIT_REASON_INVD]		      = handle_invd,
	[EXIT_REASON_INVLPG]		      = handle_invlpg,
	[EXIT_REASON_RDPMC]                   = handle_rdpmc,
	[EXIT_REASON_VMCALL]                  = handle_vmcall,
	[EXIT_REASON_VMCLEAR]	              = handle_vmclear,
	[EXIT_REASON_VMLAUNCH]                = handle_vmlaunch,
	[EXIT_REASON_VMPTRLD]                 = handle_vmptrld,
	[EXIT_REASON_VMPTRST]                 = handle_vmptrst,
	[EXIT_REASON_VMREAD]                  = handle_vmread,
	[EXIT_REASON_VMRESUME]                = handle_vmresume,
	[EXIT_REASON_VMWRITE]                 = handle_vmwrite,
	[EXIT_REASON_VMOFF]                   = handle_vmoff,
	[EXIT_REASON_VMON]                    = handle_vmon,
	[EXIT_REASON_TPR_BELOW_THRESHOLD]     = handle_tpr_below_threshold,
	[EXIT_REASON_APIC_ACCESS]             = handle_apic_access,
	[EXIT_REASON_APIC_WRITE]              = handle_apic_write,
	[EXIT_REASON_EOI_INDUCED]             = handle_apic_eoi_induced,
	[EXIT_REASON_WBINVD]                  = handle_wbinvd,
	[EXIT_REASON_XSETBV]                  = handle_xsetbv,
	[EXIT_REASON_TASK_SWITCH]             = handle_task_switch,
	[EXIT_REASON_MCE_DURING_VMENTRY]      = handle_machine_check,
	[EXIT_REASON_GDTR_IDTR]		      = handle_desc,
	[EXIT_REASON_LDTR_TR]		      = handle_desc,
	[EXIT_REASON_EPT_VIOLATION]	      = handle_ept_violation,
	[EXIT_REASON_EPT_MISCONFIG]           = handle_ept_misconfig,
	[EXIT_REASON_PAUSE_INSTRUCTION]       = handle_pause,
	[EXIT_REASON_MWAIT_INSTRUCTION]	      = handle_mwait,
	[EXIT_REASON_MONITOR_TRAP_FLAG]       = handle_monitor_trap,
	[EXIT_REASON_MONITOR_INSTRUCTION]     = handle_monitor,
	[EXIT_REASON_INVEPT]                  = handle_invept,
	[EXIT_REASON_INVVPID]                 = handle_invvpid,
	[EXIT_REASON_RDRAND]                  = handle_invalid_op,
	[EXIT_REASON_RDSEED]                  = handle_invalid_op,
	[EXIT_REASON_XSAVES]                  = handle_xsaves,
	[EXIT_REASON_XRSTORS]                 = handle_xrstors,
	[EXIT_REASON_PML_FULL]		      = handle_pml_full,
	[EXIT_REASON_INVPCID]                 = handle_invpcid,
	[EXIT_REASON_VMFUNC]                  = handle_vmfunc,
	[EXIT_REASON_PREEMPTION_TIMER]	      = handle_preemption_timer,
	[EXIT_REASON_ENCLS]		      = handle_encls,
};

static const int kvm_vmx_max_exit_handlers =
	ARRAY_SIZE(kvm_vmx_exit_handlers);

/*
 * Return true if an IO instruction with the specified port and size should cause
 * a VM-exit into L1.
 */
bool nested_vmx_check_io_bitmaps(struct kvm_vcpu *vcpu, unsigned int port,
				 int size)
{
	struct vmcs12 *vmcs12 = get_vmcs12(vcpu);
	gpa_t bitmap, last_bitmap;
	u8 b;

	last_bitmap = (gpa_t)-1;
	b = -1;

	while (size > 0) {
		if (port < 0x8000)
			bitmap = vmcs12->io_bitmap_a;
		else if (port < 0x10000)
			bitmap = vmcs12->io_bitmap_b;
		else
			return true;
		bitmap += (port & 0x7fff) / 8;

		if (last_bitmap != bitmap)
			if (kvm_vcpu_read_guest(vcpu, bitmap, &b, 1))
				return true;
		if (b & (1 << (port & 7)))
			return true;

		port++;
		size--;
		last_bitmap = bitmap;
	}

	return false;
}

/*
 * Return 1 if we should exit from L2 to L1 to handle an MSR access access,
 * rather than handle it ourselves in L0. I.e., check whether L1 expressed
 * disinterest in the current event (read or write a specific MSR) by using an
 * MSR bitmap. This may be the case even when L0 doesn't use MSR bitmaps.
 */
static bool nested_vmx_exit_handled_msr(struct kvm_vcpu *vcpu,
	struct vmcs12 *vmcs12, u32 exit_reason)
{
	u32 msr_index = vcpu->arch.regs[VCPU_REGS_RCX];
	gpa_t bitmap;

	if (!nested_cpu_has(vmcs12, CPU_BASED_USE_MSR_BITMAPS))
		return true;

	/*
	 * The MSR_BITMAP page is divided into four 1024-byte bitmaps,
	 * for the four combinations of read/write and low/high MSR numbers.
	 * First we need to figure out which of the four to use:
	 */
	bitmap = vmcs12->msr_bitmap;
	if (exit_reason == EXIT_REASON_MSR_WRITE)
		bitmap += 2048;
	if (msr_index >= 0xc0000000) {
		msr_index -= 0xc0000000;
		bitmap += 1024;
	}

	/* Then read the msr_index'th bit from this bitmap: */
	if (msr_index < 1024*8) {
		unsigned char b;
		if (kvm_vcpu_read_guest(vcpu, bitmap + msr_index/8, &b, 1))
			return true;
		return 1 & (b >> (msr_index & 7));
	} else
		return true; /* let L1 handle the wrong parameter */
}

/*
 * Return 1 if we should exit from L2 to L1 to handle a CR access exit,
 * rather than handle it ourselves in L0. I.e., check if L1 wanted to
 * intercept (via guest_host_mask etc.) the current event.
 */
static bool nested_vmx_exit_handled_cr(struct kvm_vcpu *vcpu,
	struct vmcs12 *vmcs12)
{
	unsigned long exit_qualification = vmcs_readl(EXIT_QUALIFICATION);
	int cr = exit_qualification & 15;
	int reg;
	unsigned long val;

	switch ((exit_qualification >> 4) & 3) {
	case 0: /* mov to cr */
		reg = (exit_qualification >> 8) & 15;
		val = kvm_register_readl(vcpu, reg);
		switch (cr) {
		case 0:
			if (vmcs12->cr0_guest_host_mask &
			    (val ^ vmcs12->cr0_read_shadow))
				return true;
			break;
		case 3:
			if ((vmcs12->cr3_target_count >= 1 &&
					vmcs12->cr3_target_value0 == val) ||
				(vmcs12->cr3_target_count >= 2 &&
					vmcs12->cr3_target_value1 == val) ||
				(vmcs12->cr3_target_count >= 3 &&
					vmcs12->cr3_target_value2 == val) ||
				(vmcs12->cr3_target_count >= 4 &&
					vmcs12->cr3_target_value3 == val))
				return false;
			if (nested_cpu_has(vmcs12, CPU_BASED_CR3_LOAD_EXITING))
				return true;
			break;
		case 4:
			if (vmcs12->cr4_guest_host_mask &
			    (vmcs12->cr4_read_shadow ^ val))
				return true;
			break;
		case 8:
			if (nested_cpu_has(vmcs12, CPU_BASED_CR8_LOAD_EXITING))
				return true;
			break;
		}
		break;
	case 2: /* clts */
		if ((vmcs12->cr0_guest_host_mask & X86_CR0_TS) &&
		    (vmcs12->cr0_read_shadow & X86_CR0_TS))
			return true;
		break;
	case 1: /* mov from cr */
		switch (cr) {
		case 3:
			if (vmcs12->cpu_based_vm_exec_control &
			    CPU_BASED_CR3_STORE_EXITING)
				return true;
			break;
		case 8:
			if (vmcs12->cpu_based_vm_exec_control &
			    CPU_BASED_CR8_STORE_EXITING)
				return true;
			break;
		}
		break;
	case 3: /* lmsw */
		/*
		 * lmsw can change bits 1..3 of cr0, and only set bit 0 of
		 * cr0. Other attempted changes are ignored, with no exit.
		 */
		val = (exit_qualification >> LMSW_SOURCE_DATA_SHIFT) & 0x0f;
		if (vmcs12->cr0_guest_host_mask & 0xe &
		    (val ^ vmcs12->cr0_read_shadow))
			return true;
		if ((vmcs12->cr0_guest_host_mask & 0x1) &&
		    !(vmcs12->cr0_read_shadow & 0x1) &&
		    (val & 0x1))
			return true;
		break;
	}
	return false;
}

static bool nested_vmx_exit_handled_vmcs_access(struct kvm_vcpu *vcpu,
	struct vmcs12 *vmcs12, gpa_t bitmap)
{
	u32 vmx_instruction_info;
	unsigned long field;
	u8 b;

	if (!nested_cpu_has_shadow_vmcs(vmcs12))
		return true;

	/* Decode instruction info and find the field to access */
	vmx_instruction_info = vmcs_read32(VMX_INSTRUCTION_INFO);
	field = kvm_register_read(vcpu, (((vmx_instruction_info) >> 28) & 0xf));

	/* Out-of-range fields always cause a VM exit from L2 to L1 */
	if (field >> 15)
		return true;

	if (kvm_vcpu_read_guest(vcpu, bitmap + field/8, &b, 1))
		return true;

	return 1 & (b >> (field & 7));
}

/*
 * Return 1 if we should exit from L2 to L1 to handle an exit, or 0 if we
 * should handle it ourselves in L0 (and then continue L2). Only call this
 * when in is_guest_mode (L2).
 */
static bool nested_vmx_exit_reflected(struct kvm_vcpu *vcpu, u32 exit_reason)
{
	u32 intr_info = vmcs_read32(VM_EXIT_INTR_INFO);
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	struct vmcs12 *vmcs12 = get_vmcs12(vcpu);

	if (vmx->nested.nested_run_pending)
		return false;

	if (unlikely(vmx->fail)) {
		pr_info_ratelimited("%s failed vm entry %x\n", __func__,
				    vmcs_read32(VM_INSTRUCTION_ERROR));
		return true;
	}

	/*
	 * The host physical addresses of some pages of guest memory
	 * are loaded into the vmcs02 (e.g. vmcs12's Virtual APIC
	 * Page). The CPU may write to these pages via their host
	 * physical address while L2 is running, bypassing any
	 * address-translation-based dirty tracking (e.g. EPT write
	 * protection).
	 *
	 * Mark them dirty on every exit from L2 to prevent them from
	 * getting out of sync with dirty tracking.
	 */
	nested_mark_vmcs12_pages_dirty(vcpu);

	trace_kvm_nested_vmexit(kvm_rip_read(vcpu), exit_reason,
				vmcs_readl(EXIT_QUALIFICATION),
				vmx->idt_vectoring_info,
				intr_info,
				vmcs_read32(VM_EXIT_INTR_ERROR_CODE),
				KVM_ISA_VMX);

	switch ((u16)exit_reason) {
	case EXIT_REASON_EXCEPTION_NMI:
		if (is_nmi(intr_info))
			return false;
		else if (is_page_fault(intr_info))
			return !vmx->vcpu.arch.apf.host_apf_reason && enable_ept;
		else if (is_no_device(intr_info) &&
			 !(vmcs12->guest_cr0 & X86_CR0_TS))
			return false;
		else if (is_debug(intr_info) &&
			 vcpu->guest_debug &
			 (KVM_GUESTDBG_SINGLESTEP | KVM_GUESTDBG_USE_HW_BP))
			return false;
		else if (is_breakpoint(intr_info) &&
			 vcpu->guest_debug & KVM_GUESTDBG_USE_SW_BP)
			return false;
		return vmcs12->exception_bitmap &
				(1u << (intr_info & INTR_INFO_VECTOR_MASK));
	case EXIT_REASON_EXTERNAL_INTERRUPT:
		return false;
	case EXIT_REASON_TRIPLE_FAULT:
		return true;
	case EXIT_REASON_PENDING_INTERRUPT:
		return nested_cpu_has(vmcs12, CPU_BASED_VIRTUAL_INTR_PENDING);
	case EXIT_REASON_NMI_WINDOW:
		return nested_cpu_has(vmcs12, CPU_BASED_VIRTUAL_NMI_PENDING);
	case EXIT_REASON_TASK_SWITCH:
		return true;
	case EXIT_REASON_CPUID:
		return true;
	case EXIT_REASON_HLT:
		return nested_cpu_has(vmcs12, CPU_BASED_HLT_EXITING);
	case EXIT_REASON_INVD:
		return true;
	case EXIT_REASON_INVLPG:
		return nested_cpu_has(vmcs12, CPU_BASED_INVLPG_EXITING);
	case EXIT_REASON_RDPMC:
		return nested_cpu_has(vmcs12, CPU_BASED_RDPMC_EXITING);
	case EXIT_REASON_RDRAND:
		return nested_cpu_has2(vmcs12, SECONDARY_EXEC_RDRAND_EXITING);
	case EXIT_REASON_RDSEED:
		return nested_cpu_has2(vmcs12, SECONDARY_EXEC_RDSEED_EXITING);
	case EXIT_REASON_RDTSC: case EXIT_REASON_RDTSCP:
		return nested_cpu_has(vmcs12, CPU_BASED_RDTSC_EXITING);
	case EXIT_REASON_VMREAD:
		return nested_vmx_exit_handled_vmcs_access(vcpu, vmcs12,
			vmcs12->vmread_bitmap);
	case EXIT_REASON_VMWRITE:
		return nested_vmx_exit_handled_vmcs_access(vcpu, vmcs12,
			vmcs12->vmwrite_bitmap);
	case EXIT_REASON_VMCALL: case EXIT_REASON_VMCLEAR:
	case EXIT_REASON_VMLAUNCH: case EXIT_REASON_VMPTRLD:
	case EXIT_REASON_VMPTRST: case EXIT_REASON_VMRESUME:
	case EXIT_REASON_VMOFF: case EXIT_REASON_VMON:
	case EXIT_REASON_INVEPT: case EXIT_REASON_INVVPID:
		/*
		 * VMX instructions trap unconditionally. This allows L1 to
		 * emulate them for its L2 guest, i.e., allows 3-level nesting!
		 */
		return true;
	case EXIT_REASON_CR_ACCESS:
		return nested_vmx_exit_handled_cr(vcpu, vmcs12);
	case EXIT_REASON_DR_ACCESS:
		return nested_cpu_has(vmcs12, CPU_BASED_MOV_DR_EXITING);
	case EXIT_REASON_IO_INSTRUCTION:
		return nested_vmx_exit_handled_io(vcpu, vmcs12);
	case EXIT_REASON_GDTR_IDTR: case EXIT_REASON_LDTR_TR:
		return nested_cpu_has2(vmcs12, SECONDARY_EXEC_DESC);
	case EXIT_REASON_MSR_READ:
	case EXIT_REASON_MSR_WRITE:
		return nested_vmx_exit_handled_msr(vcpu, vmcs12, exit_reason);
	case EXIT_REASON_INVALID_STATE:
		return true;
	case EXIT_REASON_MWAIT_INSTRUCTION:
		return nested_cpu_has(vmcs12, CPU_BASED_MWAIT_EXITING);
	case EXIT_REASON_MONITOR_TRAP_FLAG:
		return nested_cpu_has(vmcs12, CPU_BASED_MONITOR_TRAP_FLAG);
	case EXIT_REASON_MONITOR_INSTRUCTION:
		return nested_cpu_has(vmcs12, CPU_BASED_MONITOR_EXITING);
	case EXIT_REASON_PAUSE_INSTRUCTION:
		return nested_cpu_has(vmcs12, CPU_BASED_PAUSE_EXITING) ||
			nested_cpu_has2(vmcs12,
				SECONDARY_EXEC_PAUSE_LOOP_EXITING);
	case EXIT_REASON_MCE_DURING_VMENTRY:
		return false;
	case EXIT_REASON_TPR_BELOW_THRESHOLD:
		return nested_cpu_has(vmcs12, CPU_BASED_TPR_SHADOW);
	case EXIT_REASON_APIC_ACCESS:
	case EXIT_REASON_APIC_WRITE:
	case EXIT_REASON_EOI_INDUCED:
		/*
		 * The controls for "virtualize APIC accesses," "APIC-
		 * register virtualization," and "virtual-interrupt
		 * delivery" only come from vmcs12.
		 */
		return true;
	case EXIT_REASON_EPT_VIOLATION:
		/*
		 * L0 always deals with the EPT violation. If nested EPT is
		 * used, and the nested mmu code discovers that the address is
		 * missing in the guest EPT table (EPT12), the EPT violation
		 * will be injected with nested_ept_inject_page_fault()
		 */
		return false;
	case EXIT_REASON_EPT_MISCONFIG:
		/*
		 * L2 never uses directly L1's EPT, but rather L0's own EPT
		 * table (shadow on EPT) or a merged EPT table that L0 built
		 * (EPT on EPT). So any problems with the structure of the
		 * table is L0's fault.
		 */
		return false;
	case EXIT_REASON_INVPCID:
		return
			nested_cpu_has2(vmcs12, SECONDARY_EXEC_ENABLE_INVPCID) &&
			nested_cpu_has(vmcs12, CPU_BASED_INVLPG_EXITING);
	case EXIT_REASON_WBINVD:
		return nested_cpu_has2(vmcs12, SECONDARY_EXEC_WBINVD_EXITING);
	case EXIT_REASON_XSETBV:
		return true;
	case EXIT_REASON_XSAVES: case EXIT_REASON_XRSTORS:
		/*
		 * This should never happen, since it is not possible to
		 * set XSS to a non-zero value---neither in L1 nor in L2.
		 * If if it were, XSS would have to be checked against
		 * the XSS exit bitmap in vmcs12.
		 */
		return nested_cpu_has2(vmcs12, SECONDARY_EXEC_XSAVES);
	case EXIT_REASON_PREEMPTION_TIMER:
		return false;
	case EXIT_REASON_PML_FULL:
		/* We emulate PML support to L1. */
		return false;
	case EXIT_REASON_VMFUNC:
		/* VM functions are emulated through L2->L0 vmexits. */
		return false;
	case EXIT_REASON_ENCLS:
		/* SGX is never exposed to L1 */
		return false;
	default:
		return true;
	}
}

static int nested_vmx_reflect_vmexit(struct kvm_vcpu *vcpu, u32 exit_reason)
{
	u32 exit_intr_info = vmcs_read32(VM_EXIT_INTR_INFO);

	/*
	 * At this point, the exit interruption info in exit_intr_info
	 * is only valid for EXCEPTION_NMI exits.  For EXTERNAL_INTERRUPT
	 * we need to query the in-kernel LAPIC.
	 */
	WARN_ON(exit_reason == EXIT_REASON_EXTERNAL_INTERRUPT);
	if ((exit_intr_info &
	     (INTR_INFO_VALID_MASK | INTR_INFO_DELIVER_CODE_MASK)) ==
	    (INTR_INFO_VALID_MASK | INTR_INFO_DELIVER_CODE_MASK)) {
		struct vmcs12 *vmcs12 = get_vmcs12(vcpu);
		vmcs12->vm_exit_intr_error_code =
			vmcs_read32(VM_EXIT_INTR_ERROR_CODE);
	}

	nested_vmx_vmexit(vcpu, exit_reason, exit_intr_info,
			  vmcs_readl(EXIT_QUALIFICATION));
	return 1;
}

static void vmx_get_exit_info(struct kvm_vcpu *vcpu, u64 *info1, u64 *info2)
{
	*info1 = vmcs_readl(EXIT_QUALIFICATION);
	*info2 = vmcs_read32(VM_EXIT_INTR_INFO);
}

static void vmx_destroy_pml_buffer(struct vcpu_vmx *vmx)
{
	if (vmx->pml_pg) {
		__free_page(vmx->pml_pg);
		vmx->pml_pg = NULL;
	}
}

static void vmx_flush_pml_buffer(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	u64 *pml_buf;
	u16 pml_idx;

	pml_idx = vmcs_read16(GUEST_PML_INDEX);

	/* Do nothing if PML buffer is empty */
	if (pml_idx == (PML_ENTITY_NUM - 1))
		return;

	/* PML index always points to next available PML buffer entity */
	if (pml_idx >= PML_ENTITY_NUM)
		pml_idx = 0;
	else
		pml_idx++;

	pml_buf = page_address(vmx->pml_pg);
	for (; pml_idx < PML_ENTITY_NUM; pml_idx++) {
		u64 gpa;

		gpa = pml_buf[pml_idx];
		WARN_ON(gpa & (PAGE_SIZE - 1));
		kvm_vcpu_mark_page_dirty(vcpu, gpa >> PAGE_SHIFT);
	}

	/* reset PML index */
	vmcs_write16(GUEST_PML_INDEX, PML_ENTITY_NUM - 1);
}

/*
 * Flush all vcpus' PML buffer and update logged GPAs to dirty_bitmap.
 * Called before reporting dirty_bitmap to userspace.
 */
static void kvm_flush_pml_buffers(struct kvm *kvm)
{
	int i;
	struct kvm_vcpu *vcpu;
	/*
	 * We only need to kick vcpu out of guest mode here, as PML buffer
	 * is flushed at beginning of all VMEXITs, and it's obvious that only
	 * vcpus running in guest are possible to have unflushed GPAs in PML
	 * buffer.
	 */
	kvm_for_each_vcpu(i, vcpu, kvm)
		kvm_vcpu_kick(vcpu);
}

static void vmx_dump_sel(char *name, uint32_t sel)
{
	pr_err("%s sel=0x%04x, attr=0x%05x, limit=0x%08x, base=0x%016lx\n",
	       name, vmcs_read16(sel),
	       vmcs_read32(sel + GUEST_ES_AR_BYTES - GUEST_ES_SELECTOR),
	       vmcs_read32(sel + GUEST_ES_LIMIT - GUEST_ES_SELECTOR),
	       vmcs_readl(sel + GUEST_ES_BASE - GUEST_ES_SELECTOR));
}

static void vmx_dump_dtsel(char *name, uint32_t limit)
{
	pr_err("%s                           limit=0x%08x, base=0x%016lx\n",
	       name, vmcs_read32(limit),
	       vmcs_readl(limit + GUEST_GDTR_BASE - GUEST_GDTR_LIMIT));
}

static void dump_vmcs(void)
{
	u32 vmentry_ctl = vmcs_read32(VM_ENTRY_CONTROLS);
	u32 vmexit_ctl = vmcs_read32(VM_EXIT_CONTROLS);
	u32 cpu_based_exec_ctrl = vmcs_read32(CPU_BASED_VM_EXEC_CONTROL);
	u32 pin_based_exec_ctrl = vmcs_read32(PIN_BASED_VM_EXEC_CONTROL);
	u32 secondary_exec_control = 0;
	unsigned long cr4 = vmcs_readl(GUEST_CR4);
	u64 efer = vmcs_read64(GUEST_IA32_EFER);
	int i, n;

	if (cpu_has_secondary_exec_ctrls())
		secondary_exec_control = vmcs_read32(SECONDARY_VM_EXEC_CONTROL);

	pr_err("*** Guest State ***\n");
	pr_err("CR0: actual=0x%016lx, shadow=0x%016lx, gh_mask=%016lx\n",
	       vmcs_readl(GUEST_CR0), vmcs_readl(CR0_READ_SHADOW),
	       vmcs_readl(CR0_GUEST_HOST_MASK));
	pr_err("CR4: actual=0x%016lx, shadow=0x%016lx, gh_mask=%016lx\n",
	       cr4, vmcs_readl(CR4_READ_SHADOW), vmcs_readl(CR4_GUEST_HOST_MASK));
	pr_err("CR3 = 0x%016lx\n", vmcs_readl(GUEST_CR3));
	if ((secondary_exec_control & SECONDARY_EXEC_ENABLE_EPT) &&
	    (cr4 & X86_CR4_PAE) && !(efer & EFER_LMA))
	{
		pr_err("PDPTR0 = 0x%016llx  PDPTR1 = 0x%016llx\n",
		       vmcs_read64(GUEST_PDPTR0), vmcs_read64(GUEST_PDPTR1));
		pr_err("PDPTR2 = 0x%016llx  PDPTR3 = 0x%016llx\n",
		       vmcs_read64(GUEST_PDPTR2), vmcs_read64(GUEST_PDPTR3));
	}
	pr_err("RSP = 0x%016lx  RIP = 0x%016lx\n",
	       vmcs_readl(GUEST_RSP), vmcs_readl(GUEST_RIP));
	pr_err("RFLAGS=0x%08lx         DR7 = 0x%016lx\n",
	       vmcs_readl(GUEST_RFLAGS), vmcs_readl(GUEST_DR7));
	pr_err("Sysenter RSP=%016lx CS:RIP=%04x:%016lx\n",
	       vmcs_readl(GUEST_SYSENTER_ESP),
	       vmcs_read32(GUEST_SYSENTER_CS), vmcs_readl(GUEST_SYSENTER_EIP));
	vmx_dump_sel("CS:  ", GUEST_CS_SELECTOR);
	vmx_dump_sel("DS:  ", GUEST_DS_SELECTOR);
	vmx_dump_sel("SS:  ", GUEST_SS_SELECTOR);
	vmx_dump_sel("ES:  ", GUEST_ES_SELECTOR);
	vmx_dump_sel("FS:  ", GUEST_FS_SELECTOR);
	vmx_dump_sel("GS:  ", GUEST_GS_SELECTOR);
	vmx_dump_dtsel("GDTR:", GUEST_GDTR_LIMIT);
	vmx_dump_sel("LDTR:", GUEST_LDTR_SELECTOR);
	vmx_dump_dtsel("IDTR:", GUEST_IDTR_LIMIT);
	vmx_dump_sel("TR:  ", GUEST_TR_SELECTOR);
	if ((vmexit_ctl & (VM_EXIT_SAVE_IA32_PAT | VM_EXIT_SAVE_IA32_EFER)) ||
	    (vmentry_ctl & (VM_ENTRY_LOAD_IA32_PAT | VM_ENTRY_LOAD_IA32_EFER)))
		pr_err("EFER =     0x%016llx  PAT = 0x%016llx\n",
		       efer, vmcs_read64(GUEST_IA32_PAT));
	pr_err("DebugCtl = 0x%016llx  DebugExceptions = 0x%016lx\n",
	       vmcs_read64(GUEST_IA32_DEBUGCTL),
	       vmcs_readl(GUEST_PENDING_DBG_EXCEPTIONS));
	if (cpu_has_load_perf_global_ctrl &&
	    vmentry_ctl & VM_ENTRY_LOAD_IA32_PERF_GLOBAL_CTRL)
		pr_err("PerfGlobCtl = 0x%016llx\n",
		       vmcs_read64(GUEST_IA32_PERF_GLOBAL_CTRL));
	if (vmentry_ctl & VM_ENTRY_LOAD_BNDCFGS)
		pr_err("BndCfgS = 0x%016llx\n", vmcs_read64(GUEST_BNDCFGS));
	pr_err("Interruptibility = %08x  ActivityState = %08x\n",
	       vmcs_read32(GUEST_INTERRUPTIBILITY_INFO),
	       vmcs_read32(GUEST_ACTIVITY_STATE));
	if (secondary_exec_control & SECONDARY_EXEC_VIRTUAL_INTR_DELIVERY)
		pr_err("InterruptStatus = %04x\n",
		       vmcs_read16(GUEST_INTR_STATUS));

	pr_err("*** Host State ***\n");
	pr_err("RIP = 0x%016lx  RSP = 0x%016lx\n",
	       vmcs_readl(HOST_RIP), vmcs_readl(HOST_RSP));
	pr_err("CS=%04x SS=%04x DS=%04x ES=%04x FS=%04x GS=%04x TR=%04x\n",
	       vmcs_read16(HOST_CS_SELECTOR), vmcs_read16(HOST_SS_SELECTOR),
	       vmcs_read16(HOST_DS_SELECTOR), vmcs_read16(HOST_ES_SELECTOR),
	       vmcs_read16(HOST_FS_SELECTOR), vmcs_read16(HOST_GS_SELECTOR),
	       vmcs_read16(HOST_TR_SELECTOR));
	pr_err("FSBase=%016lx GSBase=%016lx TRBase=%016lx\n",
	       vmcs_readl(HOST_FS_BASE), vmcs_readl(HOST_GS_BASE),
	       vmcs_readl(HOST_TR_BASE));
	pr_err("GDTBase=%016lx IDTBase=%016lx\n",
	       vmcs_readl(HOST_GDTR_BASE), vmcs_readl(HOST_IDTR_BASE));
	pr_err("CR0=%016lx CR3=%016lx CR4=%016lx\n",
	       vmcs_readl(HOST_CR0), vmcs_readl(HOST_CR3),
	       vmcs_readl(HOST_CR4));
	pr_err("Sysenter RSP=%016lx CS:RIP=%04x:%016lx\n",
	       vmcs_readl(HOST_IA32_SYSENTER_ESP),
	       vmcs_read32(HOST_IA32_SYSENTER_CS),
	       vmcs_readl(HOST_IA32_SYSENTER_EIP));
	if (vmexit_ctl & (VM_EXIT_LOAD_IA32_PAT | VM_EXIT_LOAD_IA32_EFER))
		pr_err("EFER = 0x%016llx  PAT = 0x%016llx\n",
		       vmcs_read64(HOST_IA32_EFER),
		       vmcs_read64(HOST_IA32_PAT));
	if (cpu_has_load_perf_global_ctrl &&
	    vmexit_ctl & VM_EXIT_LOAD_IA32_PERF_GLOBAL_CTRL)
		pr_err("PerfGlobCtl = 0x%016llx\n",
		       vmcs_read64(HOST_IA32_PERF_GLOBAL_CTRL));

	pr_err("*** Control State ***\n");
	pr_err("PinBased=%08x CPUBased=%08x SecondaryExec=%08x\n",
	       pin_based_exec_ctrl, cpu_based_exec_ctrl, secondary_exec_control);
	pr_err("EntryControls=%08x ExitControls=%08x\n", vmentry_ctl, vmexit_ctl);
	pr_err("ExceptionBitmap=%08x PFECmask=%08x PFECmatch=%08x\n",
	       vmcs_read32(EXCEPTION_BITMAP),
	       vmcs_read32(PAGE_FAULT_ERROR_CODE_MASK),
	       vmcs_read32(PAGE_FAULT_ERROR_CODE_MATCH));
	pr_err("VMEntry: intr_info=%08x errcode=%08x ilen=%08x\n",
	       vmcs_read32(VM_ENTRY_INTR_INFO_FIELD),
	       vmcs_read32(VM_ENTRY_EXCEPTION_ERROR_CODE),
	       vmcs_read32(VM_ENTRY_INSTRUCTION_LEN));
	pr_err("VMExit: intr_info=%08x errcode=%08x ilen=%08x\n",
	       vmcs_read32(VM_EXIT_INTR_INFO),
	       vmcs_read32(VM_EXIT_INTR_ERROR_CODE),
	       vmcs_read32(VM_EXIT_INSTRUCTION_LEN));
	pr_err("        reason=%08x qualification=%016lx\n",
	       vmcs_read32(VM_EXIT_REASON), vmcs_readl(EXIT_QUALIFICATION));
	pr_err("IDTVectoring: info=%08x errcode=%08x\n",
	       vmcs_read32(IDT_VECTORING_INFO_FIELD),
	       vmcs_read32(IDT_VECTORING_ERROR_CODE));
	pr_err("TSC Offset = 0x%016llx\n", vmcs_read64(TSC_OFFSET));
	if (secondary_exec_control & SECONDARY_EXEC_TSC_SCALING)
		pr_err("TSC Multiplier = 0x%016llx\n",
		       vmcs_read64(TSC_MULTIPLIER));
	if (cpu_based_exec_ctrl & CPU_BASED_TPR_SHADOW)
		pr_err("TPR Threshold = 0x%02x\n", vmcs_read32(TPR_THRESHOLD));
	if (pin_based_exec_ctrl & PIN_BASED_POSTED_INTR)
		pr_err("PostedIntrVec = 0x%02x\n", vmcs_read16(POSTED_INTR_NV));
	if ((secondary_exec_control & SECONDARY_EXEC_ENABLE_EPT))
		pr_err("EPT pointer = 0x%016llx\n", vmcs_read64(EPT_POINTER));
	n = vmcs_read32(CR3_TARGET_COUNT);
	for (i = 0; i + 1 < n; i += 4)
		pr_err("CR3 target%u=%016lx target%u=%016lx\n",
		       i, vmcs_readl(CR3_TARGET_VALUE0 + i * 2),
		       i + 1, vmcs_readl(CR3_TARGET_VALUE0 + i * 2 + 2));
	if (i < n)
		pr_err("CR3 target%u=%016lx\n",
		       i, vmcs_readl(CR3_TARGET_VALUE0 + i * 2));
	if (secondary_exec_control & SECONDARY_EXEC_PAUSE_LOOP_EXITING)
		pr_err("PLE Gap=%08x Window=%08x\n",
		       vmcs_read32(PLE_GAP), vmcs_read32(PLE_WINDOW));
	if (secondary_exec_control & SECONDARY_EXEC_ENABLE_VPID)
		pr_err("Virtual processor ID = 0x%04x\n",
		       vmcs_read16(VIRTUAL_PROCESSOR_ID));
}

/*
 * The guest has exited.  See if we can fix it or if we need userspace
 * assistance.
 */
static int vmx_handle_exit(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	u32 exit_reason = vmx->exit_reason;
	u32 vectoring_info = vmx->idt_vectoring_info;

	trace_kvm_exit(exit_reason, vcpu, KVM_ISA_VMX);

	/*
	 * Flush logged GPAs PML buffer, this will make dirty_bitmap more
	 * updated. Another good is, in kvm_vm_ioctl_get_dirty_log, before
	 * querying dirty_bitmap, we only need to kick all vcpus out of guest
	 * mode as if vcpus is in root mode, the PML buffer must has been
	 * flushed already.
	 */
	if (enable_pml)
		vmx_flush_pml_buffer(vcpu);

	/* If guest state is invalid, start emulating */
	if (vmx->emulation_required)
		return handle_invalid_guest_state(vcpu);

	if (is_guest_mode(vcpu) && nested_vmx_exit_reflected(vcpu, exit_reason))
		return nested_vmx_reflect_vmexit(vcpu, exit_reason);

	if (exit_reason & VMX_EXIT_REASONS_FAILED_VMENTRY) {
		dump_vmcs();
		vcpu->run->exit_reason = KVM_EXIT_FAIL_ENTRY;
		vcpu->run->fail_entry.hardware_entry_failure_reason
			= exit_reason;
		return 0;
	}

	if (unlikely(vmx->fail)) {
		vcpu->run->exit_reason = KVM_EXIT_FAIL_ENTRY;
		vcpu->run->fail_entry.hardware_entry_failure_reason
			= vmcs_read32(VM_INSTRUCTION_ERROR);
		return 0;
	}

	/*
	 * Note:
	 * Do not try to fix EXIT_REASON_EPT_MISCONFIG if it caused by
	 * delivery event since it indicates guest is accessing MMIO.
	 * The vm-exit can be triggered again after return to guest that
	 * will cause infinite loop.
	 */
	if ((vectoring_info & VECTORING_INFO_VALID_MASK) &&
			(exit_reason != EXIT_REASON_EXCEPTION_NMI &&
			exit_reason != EXIT_REASON_EPT_VIOLATION &&
			exit_reason != EXIT_REASON_PML_FULL &&
			exit_reason != EXIT_REASON_APIC_ACCESS &&
			exit_reason != EXIT_REASON_TASK_SWITCH)) {
		vcpu->run->exit_reason = KVM_EXIT_INTERNAL_ERROR;
		vcpu->run->internal.suberror = KVM_INTERNAL_ERROR_DELIVERY_EV;
		vcpu->run->internal.ndata = 3;
		vcpu->run->internal.data[0] = vectoring_info;
		vcpu->run->internal.data[1] = exit_reason;
		vcpu->run->internal.data[2] = vcpu->arch.exit_qualification;
		if (exit_reason == EXIT_REASON_EPT_MISCONFIG) {
			vcpu->run->internal.ndata++;
			vcpu->run->internal.data[3] =
				vmcs_read64(GUEST_PHYSICAL_ADDRESS);
		}
		return 0;
	}

	if (unlikely(!enable_vnmi &&
		     vmx->loaded_vmcs->soft_vnmi_blocked)) {
		if (vmx_interrupt_allowed(vcpu)) {
			vmx->loaded_vmcs->soft_vnmi_blocked = 0;
		} else if (vmx->loaded_vmcs->vnmi_blocked_time > 1000000000LL &&
			   vcpu->arch.nmi_pending) {
			/*
			 * This CPU don't support us in finding the end of an
			 * NMI-blocked window if the guest runs with IRQs
			 * disabled. So we pull the trigger after 1 s of
			 * futile waiting, but inform the user about this.
			 */
			printk(KERN_WARNING "%s: Breaking out of NMI-blocked "
			       "state on VCPU %d after 1 s timeout\n",
			       __func__, vcpu->vcpu_id);
			vmx->loaded_vmcs->soft_vnmi_blocked = 0;
		}
	}

	if (exit_reason < kvm_vmx_max_exit_handlers
	    && kvm_vmx_exit_handlers[exit_reason])
		return kvm_vmx_exit_handlers[exit_reason](vcpu);
	else {
		vcpu_unimpl(vcpu, "vmx: unexpected exit reason 0x%x\n",
				exit_reason);
		kvm_queue_exception(vcpu, UD_VECTOR);
		return 1;
	}
}

/*
 * Software based L1D cache flush which is used when microcode providing
 * the cache control MSR is not loaded.
 *
 * The L1D cache is 32 KiB on Nehalem and later microarchitectures, but to
 * flush it is required to read in 64 KiB because the replacement algorithm
 * is not exactly LRU. This could be sized at runtime via topology
 * information but as all relevant affected CPUs have 32KiB L1D cache size
 * there is no point in doing so.
 */
static void vmx_l1d_flush(struct kvm_vcpu *vcpu)
{
	int size = PAGE_SIZE << L1D_CACHE_ORDER;

	/*
	 * This code is only executed when the the flush mode is 'cond' or
	 * 'always'
	 */
	if (static_branch_likely(&vmx_l1d_flush_cond)) {
		bool flush_l1d;

		/*
		 * Clear the per-vcpu flush bit, it gets set again
		 * either from vcpu_run() or from one of the unsafe
		 * VMEXIT handlers.
		 */
		flush_l1d = vcpu->arch.l1tf_flush_l1d;
		vcpu->arch.l1tf_flush_l1d = false;

		/*
		 * Clear the per-cpu flush bit, it gets set again from
		 * the interrupt handlers.
		 */
		flush_l1d |= kvm_get_cpu_l1tf_flush_l1d();
		kvm_clear_cpu_l1tf_flush_l1d();

		if (!flush_l1d)
			return;
	}

	vcpu->stat.l1d_flush++;

	if (static_cpu_has(X86_FEATURE_FLUSH_L1D)) {
		wrmsrl(MSR_IA32_FLUSH_CMD, L1D_FLUSH);
		return;
	}

	asm volatile(
		/* First ensure the pages are in the TLB */
		"xorl	%%eax, %%eax\n"
		".Lpopulate_tlb:\n\t"
		"movzbl	(%[flush_pages], %%" _ASM_AX "), %%ecx\n\t"
		"addl	$4096, %%eax\n\t"
		"cmpl	%%eax, %[size]\n\t"
		"jne	.Lpopulate_tlb\n\t"
		"xorl	%%eax, %%eax\n\t"
		"cpuid\n\t"
		/* Now fill the cache */
		"xorl	%%eax, %%eax\n"
		".Lfill_cache:\n"
		"movzbl	(%[flush_pages], %%" _ASM_AX "), %%ecx\n\t"
		"addl	$64, %%eax\n\t"
		"cmpl	%%eax, %[size]\n\t"
		"jne	.Lfill_cache\n\t"
		"lfence\n"
		:: [flush_pages] "r" (vmx_l1d_flush_pages),
		    [size] "r" (size)
		: "eax", "ebx", "ecx", "edx");
}

static void update_cr8_intercept(struct kvm_vcpu *vcpu, int tpr, int irr)
{
	struct vmcs12 *vmcs12 = get_vmcs12(vcpu);

	if (is_guest_mode(vcpu) &&
		nested_cpu_has(vmcs12, CPU_BASED_TPR_SHADOW))
		return;

	if (irr == -1 || tpr < irr) {
		vmcs_write32(TPR_THRESHOLD, 0);
		return;
	}

	vmcs_write32(TPR_THRESHOLD, irr);
}

static void vmx_set_virtual_apic_mode(struct kvm_vcpu *vcpu)
{
	u32 sec_exec_control;

	if (!lapic_in_kernel(vcpu))
		return;

	if (!flexpriority_enabled &&
	    !cpu_has_vmx_virtualize_x2apic_mode())
		return;

	/* Postpone execution until vmcs01 is the current VMCS. */
	if (is_guest_mode(vcpu)) {
		to_vmx(vcpu)->nested.change_vmcs01_virtual_apic_mode = true;
		return;
	}

	sec_exec_control = vmcs_read32(SECONDARY_VM_EXEC_CONTROL);
	sec_exec_control &= ~(SECONDARY_EXEC_VIRTUALIZE_APIC_ACCESSES |
			      SECONDARY_EXEC_VIRTUALIZE_X2APIC_MODE);

	switch (kvm_get_apic_mode(vcpu)) {
	case LAPIC_MODE_INVALID:
		WARN_ONCE(true, "Invalid local APIC state");
	case LAPIC_MODE_DISABLED:
		break;
	case LAPIC_MODE_XAPIC:
		if (flexpriority_enabled) {
			sec_exec_control |=
				SECONDARY_EXEC_VIRTUALIZE_APIC_ACCESSES;
			vmx_flush_tlb(vcpu, true);
		}
		break;
	case LAPIC_MODE_X2APIC:
		if (cpu_has_vmx_virtualize_x2apic_mode())
			sec_exec_control |=
				SECONDARY_EXEC_VIRTUALIZE_X2APIC_MODE;
		break;
	}
	vmcs_write32(SECONDARY_VM_EXEC_CONTROL, sec_exec_control);

	vmx_update_msr_bitmap(vcpu);
}

static void vmx_set_apic_access_page_addr(struct kvm_vcpu *vcpu, hpa_t hpa)
{
	if (!is_guest_mode(vcpu)) {
		vmcs_write64(APIC_ACCESS_ADDR, hpa);
		vmx_flush_tlb(vcpu, true);
	}
}

static void vmx_hwapic_isr_update(struct kvm_vcpu *vcpu, int max_isr)
{
	u16 status;
	u8 old;

	if (max_isr == -1)
		max_isr = 0;

	status = vmcs_read16(GUEST_INTR_STATUS);
	old = status >> 8;
	if (max_isr != old) {
		status &= 0xff;
		status |= max_isr << 8;
		vmcs_write16(GUEST_INTR_STATUS, status);
	}
}

static void vmx_set_rvi(int vector)
{
	u16 status;
	u8 old;

	if (vector == -1)
		vector = 0;

	status = vmcs_read16(GUEST_INTR_STATUS);
	old = (u8)status & 0xff;
	if ((u8)vector != old) {
		status &= ~0xff;
		status |= (u8)vector;
		vmcs_write16(GUEST_INTR_STATUS, status);
	}
}

static void vmx_hwapic_irr_update(struct kvm_vcpu *vcpu, int max_irr)
{
	/*
	 * When running L2, updating RVI is only relevant when
	 * vmcs12 virtual-interrupt-delivery enabled.
	 * However, it can be enabled only when L1 also
	 * intercepts external-interrupts and in that case
	 * we should not update vmcs02 RVI but instead intercept
	 * interrupt. Therefore, do nothing when running L2.
	 */
	if (!is_guest_mode(vcpu))
		vmx_set_rvi(max_irr);
}

static int vmx_sync_pir_to_irr(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	int max_irr;
	bool max_irr_updated;

	WARN_ON(!vcpu->arch.apicv_active);
	if (pi_test_on(&vmx->pi_desc)) {
		pi_clear_on(&vmx->pi_desc);
		/*
		 * IOMMU can write to PIR.ON, so the barrier matters even on UP.
		 * But on x86 this is just a compiler barrier anyway.
		 */
		smp_mb__after_atomic();
		max_irr_updated =
			kvm_apic_update_irr(vcpu, vmx->pi_desc.pir, &max_irr);

		/*
		 * If we are running L2 and L1 has a new pending interrupt
		 * which can be injected, we should re-evaluate
		 * what should be done with this new L1 interrupt.
		 * If L1 intercepts external-interrupts, we should
		 * exit from L2 to L1. Otherwise, interrupt should be
		 * delivered directly to L2.
		 */
		if (is_guest_mode(vcpu) && max_irr_updated) {
			if (nested_exit_on_intr(vcpu))
				kvm_vcpu_exiting_guest_mode(vcpu);
			else
				kvm_make_request(KVM_REQ_EVENT, vcpu);
		}
	} else {
		max_irr = kvm_lapic_find_highest_irr(vcpu);
	}
	vmx_hwapic_irr_update(vcpu, max_irr);
	return max_irr;
}

static u8 vmx_has_apicv_interrupt(struct kvm_vcpu *vcpu)
{
	u8 rvi = vmx_get_rvi();
	u8 vppr = kvm_lapic_get_reg(vcpu->arch.apic, APIC_PROCPRI);

	return ((rvi & 0xf0) > (vppr & 0xf0));
}

static bool vmx_dy_apicv_has_pending_interrupt(struct kvm_vcpu *vcpu)
{
	return pi_test_on(vcpu_to_pi_desc(vcpu));
}

static void vmx_load_eoi_exitmap(struct kvm_vcpu *vcpu, u64 *eoi_exit_bitmap)
{
	if (!kvm_vcpu_apicv_active(vcpu))
		return;

	vmcs_write64(EOI_EXIT_BITMAP0, eoi_exit_bitmap[0]);
	vmcs_write64(EOI_EXIT_BITMAP1, eoi_exit_bitmap[1]);
	vmcs_write64(EOI_EXIT_BITMAP2, eoi_exit_bitmap[2]);
	vmcs_write64(EOI_EXIT_BITMAP3, eoi_exit_bitmap[3]);
}

static void vmx_apicv_post_state_restore(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);

	pi_clear_on(&vmx->pi_desc);
	memset(vmx->pi_desc.pir, 0, sizeof(vmx->pi_desc.pir));
}

static void vmx_complete_atomic_exit(struct vcpu_vmx *vmx)
{
	if (vmx->exit_reason != EXIT_REASON_EXCEPTION_NMI)
		return;

	vmx->exit_intr_info = vmcs_read32(VM_EXIT_INTR_INFO);

	/* if exit due to PF check for async PF */
	if (is_page_fault(vmx->exit_intr_info))
		vmx->vcpu.arch.apf.host_apf_reason = kvm_read_and_reset_pf_reason();

	/* Handle machine checks before interrupts are enabled */
	if (is_machine_check(vmx->exit_intr_info))
		kvm_machine_check();

	/* We need to handle NMIs before interrupts are enabled */
	if (is_nmi(vmx->exit_intr_info)) {
		kvm_before_interrupt(&vmx->vcpu);
		asm("int $2");
		kvm_after_interrupt(&vmx->vcpu);
	}
}

static void vmx_handle_external_intr(struct kvm_vcpu *vcpu)
{
	u32 exit_intr_info = vmcs_read32(VM_EXIT_INTR_INFO);

	if ((exit_intr_info & (INTR_INFO_VALID_MASK | INTR_INFO_INTR_TYPE_MASK))
			== (INTR_INFO_VALID_MASK | INTR_TYPE_EXT_INTR)) {
		unsigned int vector;
		unsigned long entry;
		gate_desc *desc;
		struct vcpu_vmx *vmx = to_vmx(vcpu);
#ifdef CONFIG_X86_64
		unsigned long tmp;
#endif

		vector =  exit_intr_info & INTR_INFO_VECTOR_MASK;
		desc = (gate_desc *)vmx->host_idt_base + vector;
		entry = gate_offset(desc);
		asm volatile(
#ifdef CONFIG_X86_64
			"mov %%" _ASM_SP ", %[sp]\n\t"
			"and $0xfffffffffffffff0, %%" _ASM_SP "\n\t"
			"push $%c[ss]\n\t"
			"push %[sp]\n\t"
#endif
			"pushf\n\t"
			__ASM_SIZE(push) " $%c[cs]\n\t"
			CALL_NOSPEC
			:
#ifdef CONFIG_X86_64
			[sp]"=&r"(tmp),
#endif
			ASM_CALL_CONSTRAINT
			:
			THUNK_TARGET(entry),
			[ss]"i"(__KERNEL_DS),
			[cs]"i"(__KERNEL_CS)
			);
	}
}
STACK_FRAME_NON_STANDARD(vmx_handle_external_intr);

static bool vmx_has_emulated_msr(int index)
{
	switch (index) {
	case MSR_IA32_SMBASE:
		/*
		 * We cannot do SMM unless we can run the guest in big
		 * real mode.
		 */
		return enable_unrestricted_guest || emulate_invalid_guest_state;
	case MSR_AMD64_VIRT_SPEC_CTRL:
		/* This is AMD only.  */
		return false;
	default:
		return true;
	}
}

static bool vmx_mpx_supported(void)
{
	return (vmcs_config.vmexit_ctrl & VM_EXIT_CLEAR_BNDCFGS) &&
		(vmcs_config.vmentry_ctrl & VM_ENTRY_LOAD_BNDCFGS);
}

static bool vmx_xsaves_supported(void)
{
	return vmcs_config.cpu_based_2nd_exec_ctrl &
		SECONDARY_EXEC_XSAVES;
}

static void vmx_recover_nmi_blocking(struct vcpu_vmx *vmx)
{
	u32 exit_intr_info;
	bool unblock_nmi;
	u8 vector;
	bool idtv_info_valid;

	idtv_info_valid = vmx->idt_vectoring_info & VECTORING_INFO_VALID_MASK;

	if (enable_vnmi) {
		if (vmx->loaded_vmcs->nmi_known_unmasked)
			return;
		/*
		 * Can't use vmx->exit_intr_info since we're not sure what
		 * the exit reason is.
		 */
		exit_intr_info = vmcs_read32(VM_EXIT_INTR_INFO);
		unblock_nmi = (exit_intr_info & INTR_INFO_UNBLOCK_NMI) != 0;
		vector = exit_intr_info & INTR_INFO_VECTOR_MASK;
		/*
		 * SDM 3: 27.7.1.2 (September 2008)
		 * Re-set bit "block by NMI" before VM entry if vmexit caused by
		 * a guest IRET fault.
		 * SDM 3: 23.2.2 (September 2008)
		 * Bit 12 is undefined in any of the following cases:
		 *  If the VM exit sets the valid bit in the IDT-vectoring
		 *   information field.
		 *  If the VM exit is due to a double fault.
		 */
		if ((exit_intr_info & INTR_INFO_VALID_MASK) && unblock_nmi &&
		    vector != DF_VECTOR && !idtv_info_valid)
			vmcs_set_bits(GUEST_INTERRUPTIBILITY_INFO,
				      GUEST_INTR_STATE_NMI);
		else
			vmx->loaded_vmcs->nmi_known_unmasked =
				!(vmcs_read32(GUEST_INTERRUPTIBILITY_INFO)
				  & GUEST_INTR_STATE_NMI);
	} else if (unlikely(vmx->loaded_vmcs->soft_vnmi_blocked))
		vmx->loaded_vmcs->vnmi_blocked_time +=
			ktime_to_ns(ktime_sub(ktime_get(),
					      vmx->loaded_vmcs->entry_time));
}

static void __vmx_complete_interrupts(struct kvm_vcpu *vcpu,
				      u32 idt_vectoring_info,
				      int instr_len_field,
				      int error_code_field)
{
	u8 vector;
	int type;
	bool idtv_info_valid;

	idtv_info_valid = idt_vectoring_info & VECTORING_INFO_VALID_MASK;

	vcpu->arch.nmi_injected = false;
	kvm_clear_exception_queue(vcpu);
	kvm_clear_interrupt_queue(vcpu);

	if (!idtv_info_valid)
		return;

	kvm_make_request(KVM_REQ_EVENT, vcpu);

	vector = idt_vectoring_info & VECTORING_INFO_VECTOR_MASK;
	type = idt_vectoring_info & VECTORING_INFO_TYPE_MASK;

	switch (type) {
	case INTR_TYPE_NMI_INTR:
		vcpu->arch.nmi_injected = true;
		/*
		 * SDM 3: 27.7.1.2 (September 2008)
		 * Clear bit "block by NMI" before VM entry if a NMI
		 * delivery faulted.
		 */
		vmx_set_nmi_mask(vcpu, false);
		break;
	case INTR_TYPE_SOFT_EXCEPTION:
		vcpu->arch.event_exit_inst_len = vmcs_read32(instr_len_field);
		/* fall through */
	case INTR_TYPE_HARD_EXCEPTION:
		if (idt_vectoring_info & VECTORING_INFO_DELIVER_CODE_MASK) {
			u32 err = vmcs_read32(error_code_field);
			kvm_requeue_exception_e(vcpu, vector, err);
		} else
			kvm_requeue_exception(vcpu, vector);
		break;
	case INTR_TYPE_SOFT_INTR:
		vcpu->arch.event_exit_inst_len = vmcs_read32(instr_len_field);
		/* fall through */
	case INTR_TYPE_EXT_INTR:
		kvm_queue_interrupt(vcpu, vector, type == INTR_TYPE_SOFT_INTR);
		break;
	default:
		break;
	}
}

static void vmx_complete_interrupts(struct vcpu_vmx *vmx)
{
	__vmx_complete_interrupts(&vmx->vcpu, vmx->idt_vectoring_info,
				  VM_EXIT_INSTRUCTION_LEN,
				  IDT_VECTORING_ERROR_CODE);
}

static void vmx_cancel_injection(struct kvm_vcpu *vcpu)
{
	__vmx_complete_interrupts(vcpu,
				  vmcs_read32(VM_ENTRY_INTR_INFO_FIELD),
				  VM_ENTRY_INSTRUCTION_LEN,
				  VM_ENTRY_EXCEPTION_ERROR_CODE);

	vmcs_write32(VM_ENTRY_INTR_INFO_FIELD, 0);
}

static void atomic_switch_perf_msrs(struct vcpu_vmx *vmx)
{
	int i, nr_msrs;
	struct perf_guest_switch_msr *msrs;

	msrs = perf_guest_get_msrs(&nr_msrs);

	if (!msrs)
		return;

	for (i = 0; i < nr_msrs; i++)
		if (msrs[i].host == msrs[i].guest)
			clear_atomic_switch_msr(vmx, msrs[i].msr);
		else
			add_atomic_switch_msr(vmx, msrs[i].msr, msrs[i].guest,
					msrs[i].host, false);
}

static void vmx_arm_hv_timer(struct vcpu_vmx *vmx, u32 val)
{
	vmcs_write32(VMX_PREEMPTION_TIMER_VALUE, val);
	if (!vmx->loaded_vmcs->hv_timer_armed)
		vmcs_set_bits(PIN_BASED_VM_EXEC_CONTROL,
			      PIN_BASED_VMX_PREEMPTION_TIMER);
	vmx->loaded_vmcs->hv_timer_armed = true;
}

static void vmx_update_hv_timer(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	u64 tscl;
	u32 delta_tsc;

	if (vmx->req_immediate_exit) {
		vmx_arm_hv_timer(vmx, 0);
		return;
	}

	if (vmx->hv_deadline_tsc != -1) {
		tscl = rdtsc();
		if (vmx->hv_deadline_tsc > tscl)
			/* set_hv_timer ensures the delta fits in 32-bits */
			delta_tsc = (u32)((vmx->hv_deadline_tsc - tscl) >>
				cpu_preemption_timer_multi);
		else
			delta_tsc = 0;

		vmx_arm_hv_timer(vmx, delta_tsc);
		return;
	}

	if (vmx->loaded_vmcs->hv_timer_armed)
		vmcs_clear_bits(PIN_BASED_VM_EXEC_CONTROL,
				PIN_BASED_VMX_PREEMPTION_TIMER);
	vmx->loaded_vmcs->hv_timer_armed = false;
}

u64 __always_inline vmx_spec_ctrl_restore_host(struct vcpu_vmx *vmx)
{
	u64 guestval, hostval = this_cpu_read(x86_spec_ctrl_current);

	if (!cpu_feature_enabled(X86_FEATURE_MSR_SPEC_CTRL))
		return 0;

	guestval = __rdmsr(MSR_IA32_SPEC_CTRL);

	/*
	 *
	 * For legacy IBRS, the IBRS bit always needs to be written after
	 * transitioning from a less privileged predictor mode, regardless of
	 * whether the guest/host values differ.
	 */
	if (cpu_feature_enabled(X86_FEATURE_KERNEL_IBRS) ||
	    guestval != hostval)
		native_wrmsrl(MSR_IA32_SPEC_CTRL, hostval);

	barrier_nospec();

	return guestval;
}

static void __noclone vmx_vcpu_run(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	unsigned long cr3, cr4, evmcs_rsp;
	u64 spec_ctrl;

	/* Record the guest's net vcpu time for enforced NMI injections. */
	if (unlikely(!enable_vnmi &&
		     vmx->loaded_vmcs->soft_vnmi_blocked))
		vmx->loaded_vmcs->entry_time = ktime_get();

	/* Don't enter VMX if guest state is invalid, let the exit handler
	   start emulation until we arrive back to a valid state */
	if (vmx->emulation_required)
		return;

	if (vmx->ple_window_dirty) {
		vmx->ple_window_dirty = false;
		vmcs_write32(PLE_WINDOW, vmx->ple_window);
	}

	if (vmx->nested.sync_shadow_vmcs) {
		copy_vmcs12_to_shadow(vmx);
		vmx->nested.sync_shadow_vmcs = false;
	}

	if (test_bit(VCPU_REGS_RSP, (unsigned long *)&vcpu->arch.regs_dirty))
		vmcs_writel(GUEST_RSP, vcpu->arch.regs[VCPU_REGS_RSP]);
	if (test_bit(VCPU_REGS_RIP, (unsigned long *)&vcpu->arch.regs_dirty))
		vmcs_writel(GUEST_RIP, vcpu->arch.regs[VCPU_REGS_RIP]);

	cr3 = __get_current_cr3_fast();
	if (unlikely(cr3 != vmx->loaded_vmcs->host_state.cr3)) {
		vmcs_writel(HOST_CR3, cr3);
		vmx->loaded_vmcs->host_state.cr3 = cr3;
	}

	cr4 = cr4_read_shadow();
	if (unlikely(cr4 != vmx->loaded_vmcs->host_state.cr4)) {
		vmcs_writel(HOST_CR4, cr4);
		vmx->loaded_vmcs->host_state.cr4 = cr4;
	}

	/* When single-stepping over STI and MOV SS, we must clear the
	 * corresponding interruptibility bits in the guest state. Otherwise
	 * vmentry fails as it then expects bit 14 (BS) in pending debug
	 * exceptions being set, but that's not correct for the guest debugging
	 * case. */
	if (vcpu->guest_debug & KVM_GUESTDBG_SINGLESTEP)
		vmx_set_interrupt_shadow(vcpu, 0);

	kvm_load_guest_xcr0(vcpu);

	if (static_cpu_has(X86_FEATURE_PKU) &&
	    kvm_read_cr4_bits(vcpu, X86_CR4_PKE) &&
	    vcpu->arch.pkru != vmx->host_pkru)
		__write_pkru(vcpu->arch.pkru);

	atomic_switch_perf_msrs(vmx);

	vmx_update_hv_timer(vcpu);

	/*
	 * If this vCPU has touched SPEC_CTRL, restore the guest's value if
	 * it's non-zero. Since vmentry is serialising on affected CPUs, there
	 * is no need to worry about the conditional branch over the wrmsr
	 * being speculatively taken.
	 */
	x86_spec_ctrl_set_guest(vmx->spec_ctrl, 0);

	vmx->__launched = vmx->loaded_vmcs->launched;

	evmcs_rsp = static_branch_unlikely(&enable_evmcs) ?
		(unsigned long)&current_evmcs->host_rsp : 0;

	/* L1D Flush includes CPU buffer clear to mitigate MDS */
	if (static_branch_unlikely(&vmx_l1d_should_flush))
		vmx_l1d_flush(vcpu);
	else if (static_branch_unlikely(&mds_user_clear))
		mds_clear_cpu_buffers();
	else if (static_branch_unlikely(&mmio_stale_data_clear) &&
		 kvm_arch_has_assigned_device(vcpu->kvm))
		mds_clear_cpu_buffers();

	vmx_disable_fb_clear(vmx);

	asm volatile (
		/* Store host registers */
		"push %%" _ASM_DX "; push %%" _ASM_BP ";"
		"push %%" _ASM_CX " \n\t" /* placeholder for guest rcx */
		"push %%" _ASM_CX " \n\t"
		"cmp %%" _ASM_SP ", %c[host_rsp](%%" _ASM_CX ") \n\t"
		"je 1f \n\t"
		"mov %%" _ASM_SP ", %c[host_rsp](%%" _ASM_CX ") \n\t"
		/* Avoid VMWRITE when Enlightened VMCS is in use */
		"test %%" _ASM_SI ", %%" _ASM_SI " \n\t"
		"jz 2f \n\t"
		"mov %%" _ASM_SP ", (%%" _ASM_SI ") \n\t"
		"jmp 1f \n\t"
		"2: \n\t"
		__ex(ASM_VMX_VMWRITE_RSP_RDX) "\n\t"
		"1: \n\t"
		/* Reload cr2 if changed */
		"mov %c[cr2](%%" _ASM_CX "), %%" _ASM_AX " \n\t"
		"mov %%cr2, %%" _ASM_DX " \n\t"
		"cmp %%" _ASM_AX ", %%" _ASM_DX " \n\t"
		"je 3f \n\t"
		"mov %%" _ASM_AX", %%cr2 \n\t"
		"3: \n\t"
		/* Check if vmlaunch of vmresume is needed */
		"cmpb $0, %c[launched](%%" _ASM_CX ") \n\t"
		/* Load guest registers.  Don't clobber flags. */
		"mov %c[rax](%%" _ASM_CX "), %%" _ASM_AX " \n\t"
		"mov %c[rbx](%%" _ASM_CX "), %%" _ASM_BX " \n\t"
		"mov %c[rdx](%%" _ASM_CX "), %%" _ASM_DX " \n\t"
		"mov %c[rsi](%%" _ASM_CX "), %%" _ASM_SI " \n\t"
		"mov %c[rdi](%%" _ASM_CX "), %%" _ASM_DI " \n\t"
		"mov %c[rbp](%%" _ASM_CX "), %%" _ASM_BP " \n\t"
#ifdef CONFIG_X86_64
		"mov %c[r8](%%" _ASM_CX "),  %%r8  \n\t"
		"mov %c[r9](%%" _ASM_CX "),  %%r9  \n\t"
		"mov %c[r10](%%" _ASM_CX "), %%r10 \n\t"
		"mov %c[r11](%%" _ASM_CX "), %%r11 \n\t"
		"mov %c[r12](%%" _ASM_CX "), %%r12 \n\t"
		"mov %c[r13](%%" _ASM_CX "), %%r13 \n\t"
		"mov %c[r14](%%" _ASM_CX "), %%r14 \n\t"
		"mov %c[r15](%%" _ASM_CX "), %%r15 \n\t"
#endif
		/* Load guest RCX.  This kills the vmx_vcpu pointer! */
		"mov %c[rcx](%%" _ASM_CX "), %%" _ASM_CX " \n\t"

		/* Enter guest mode */
		"jne 1f \n\t"
		__ex(ASM_VMX_VMLAUNCH) "\n\t"
		"jmp 2f \n\t"
		"1: " __ex(ASM_VMX_VMRESUME) "\n\t"
		"2: "

		/* Save guest's RCX to the stack placeholder (see above) */
		"mov %%" _ASM_CX ", %c[wordsize](%%" _ASM_SP ") \n\t"

		/* Load host's RCX, i.e. the vmx_vcpu pointer */
		"pop %%" _ASM_CX " \n\t"

		/* Set vmx->fail based on EFLAGS.{CF,ZF} */
		"setbe %c[fail](%%" _ASM_CX ")\n\t"

		/* Save all guest registers, including RCX from the stack */
		"mov %%" _ASM_AX ", %c[rax](%%" _ASM_CX ") \n\t"
		"mov %%" _ASM_BX ", %c[rbx](%%" _ASM_CX ") \n\t"
		__ASM_SIZE(pop) " %c[rcx](%%" _ASM_CX ") \n\t"
		"mov %%" _ASM_DX ", %c[rdx](%%" _ASM_CX ") \n\t"
		"mov %%" _ASM_SI ", %c[rsi](%%" _ASM_CX ") \n\t"
		"mov %%" _ASM_DI ", %c[rdi](%%" _ASM_CX ") \n\t"
		"mov %%" _ASM_BP ", %c[rbp](%%" _ASM_CX ") \n\t"
#ifdef CONFIG_X86_64
		"mov %%r8,  %c[r8](%%" _ASM_CX ") \n\t"
		"mov %%r9,  %c[r9](%%" _ASM_CX ") \n\t"
		"mov %%r10, %c[r10](%%" _ASM_CX ") \n\t"
		"mov %%r11, %c[r11](%%" _ASM_CX ") \n\t"
		"mov %%r12, %c[r12](%%" _ASM_CX ") \n\t"
		"mov %%r13, %c[r13](%%" _ASM_CX ") \n\t"
		"mov %%r14, %c[r14](%%" _ASM_CX ") \n\t"
		"mov %%r15, %c[r15](%%" _ASM_CX ") \n\t"

		/*
		 * Clear all general purpose registers (except RSP, which is loaded by
		 * the CPU during VM-Exit) to prevent speculative use of the guest's
		 * values, even those that are saved/loaded via the stack.  In theory,
		 * an L1 cache miss when restoring registers could lead to speculative
		 * execution with the guest's values.  Zeroing XORs are dirt cheap,
		 * i.e. the extra paranoia is essentially free.
		 */
		"xor %%r8d,  %%r8d \n\t"
		"xor %%r9d,  %%r9d \n\t"
		"xor %%r10d, %%r10d \n\t"
		"xor %%r11d, %%r11d \n\t"
		"xor %%r12d, %%r12d \n\t"
		"xor %%r13d, %%r13d \n\t"
		"xor %%r14d, %%r14d \n\t"
		"xor %%r15d, %%r15d \n\t"
#endif
		"mov %%cr2, %%" _ASM_AX "   \n\t"
		"mov %%" _ASM_AX ", %c[cr2](%%" _ASM_CX ") \n\t"

		"xor %%eax, %%eax \n\t"
		"xor %%ebx, %%ebx \n\t"
		"xor %%ecx, %%ecx \n\t"
		"xor %%edx, %%edx \n\t"
		"xor %%esi, %%esi \n\t"
		"xor %%edi, %%edi \n\t"
		"xor %%ebp, %%ebp \n\t"
		"pop  %%" _ASM_BP "; pop  %%" _ASM_DX " \n\t"
		".pushsection .rodata \n\t"
		".global vmx_return \n\t"
		"vmx_return: " _ASM_PTR " 2b \n\t"
		".popsection"
	      : "=c"((int){0}), "=d"((int){0}), "=S"((int){0})
	      : "c"(vmx), "d"((unsigned long)HOST_RSP), "S"(evmcs_rsp),
		[launched]"i"(offsetof(struct vcpu_vmx, __launched)),
		[fail]"i"(offsetof(struct vcpu_vmx, fail)),
		[host_rsp]"i"(offsetof(struct vcpu_vmx, host_rsp)),
		[rax]"i"(offsetof(struct vcpu_vmx, vcpu.arch.regs[VCPU_REGS_RAX])),
		[rbx]"i"(offsetof(struct vcpu_vmx, vcpu.arch.regs[VCPU_REGS_RBX])),
		[rcx]"i"(offsetof(struct vcpu_vmx, vcpu.arch.regs[VCPU_REGS_RCX])),
		[rdx]"i"(offsetof(struct vcpu_vmx, vcpu.arch.regs[VCPU_REGS_RDX])),
		[rsi]"i"(offsetof(struct vcpu_vmx, vcpu.arch.regs[VCPU_REGS_RSI])),
		[rdi]"i"(offsetof(struct vcpu_vmx, vcpu.arch.regs[VCPU_REGS_RDI])),
		[rbp]"i"(offsetof(struct vcpu_vmx, vcpu.arch.regs[VCPU_REGS_RBP])),
#ifdef CONFIG_X86_64
		[r8]"i"(offsetof(struct vcpu_vmx, vcpu.arch.regs[VCPU_REGS_R8])),
		[r9]"i"(offsetof(struct vcpu_vmx, vcpu.arch.regs[VCPU_REGS_R9])),
		[r10]"i"(offsetof(struct vcpu_vmx, vcpu.arch.regs[VCPU_REGS_R10])),
		[r11]"i"(offsetof(struct vcpu_vmx, vcpu.arch.regs[VCPU_REGS_R11])),
		[r12]"i"(offsetof(struct vcpu_vmx, vcpu.arch.regs[VCPU_REGS_R12])),
		[r13]"i"(offsetof(struct vcpu_vmx, vcpu.arch.regs[VCPU_REGS_R13])),
		[r14]"i"(offsetof(struct vcpu_vmx, vcpu.arch.regs[VCPU_REGS_R14])),
		[r15]"i"(offsetof(struct vcpu_vmx, vcpu.arch.regs[VCPU_REGS_R15])),
#endif
		[cr2]"i"(offsetof(struct vcpu_vmx, vcpu.arch.cr2)),
		[wordsize]"i"(sizeof(ulong))
	      : "cc", "memory"
#ifdef CONFIG_X86_64
		, "rax", "rbx", "rdi"
		, "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"
#else
		, "eax", "ebx", "edi"
#endif
	      );

	/*
	 * IMPORTANT: RSB filling and SPEC_CTRL handling must be done before
	 * the first unbalanced RET after vmexit!
	 *
	 * For retpoline or IBRS, RSB filling is needed to prevent poisoned RSB
	 * entries and (in some cases) RSB underflow.
	 *
	 * eIBRS has its own protection against poisoned RSB, so it doesn't
	 * need the RSB filling sequence.  But it does need to be enabled, and a
	 * single call to retire, before the first unbalanced RET.
	 *
	 * So no RETs before vmx_spec_ctrl_restore_host() below.
	 */
	vmexit_fill_RSB();

	/* Save this for below */
	spec_ctrl = vmx_spec_ctrl_restore_host(vmx);

	vmx_enable_fb_clear(vmx);

	/*
	 * We do not use IBRS in the kernel. If this vCPU has used the
	 * SPEC_CTRL MSR it may have left it on; save the value and
	 * turn it off. This is much more efficient than blindly adding
	 * it to the atomic save/restore list. Especially as the former
	 * (Saving guest MSRs on vmexit) doesn't even exist in KVM.
	 *
	 * For non-nested case:
	 * If the L01 MSR bitmap does not intercept the MSR, then we need to
	 * save it.
	 *
	 * For nested case:
	 * If the L02 MSR bitmap does not intercept the MSR, then we need to
	 * save it.
	 */
	if (unlikely(!msr_write_intercepted(vcpu, MSR_IA32_SPEC_CTRL)))
		vmx->spec_ctrl = spec_ctrl;

	/* All fields are clean at this point */
	if (static_branch_unlikely(&enable_evmcs))
		current_evmcs->hv_clean_fields |=
			HV_VMX_ENLIGHTENED_CLEAN_FIELD_ALL;

	/* MSR_IA32_DEBUGCTLMSR is zeroed on vmexit. Restore it if needed */
	if (vmx->host_debugctlmsr)
		update_debugctlmsr(vmx->host_debugctlmsr);

#ifndef CONFIG_X86_64
	/*
	 * The sysexit path does not restore ds/es, so we must set them to
	 * a reasonable value ourselves.
	 *
	 * We can't defer this to vmx_prepare_switch_to_host() since that
	 * function may be executed in interrupt context, which saves and
	 * restore segments around it, nullifying its effect.
	 */
	loadsegment(ds, __USER_DS);
	loadsegment(es, __USER_DS);
#endif

	vcpu->arch.regs_avail = ~((1 << VCPU_REGS_RIP) | (1 << VCPU_REGS_RSP)
				  | (1 << VCPU_EXREG_RFLAGS)
				  | (1 << VCPU_EXREG_PDPTR)
				  | (1 << VCPU_EXREG_SEGMENTS)
				  | (1 << VCPU_EXREG_CR3));
	vcpu->arch.regs_dirty = 0;

	/*
	 * eager fpu is enabled if PKEY is supported and CR4 is switched
	 * back on host, so it is safe to read guest PKRU from current
	 * XSAVE.
	 */
	if (static_cpu_has(X86_FEATURE_PKU) &&
	    kvm_read_cr4_bits(vcpu, X86_CR4_PKE)) {
		vcpu->arch.pkru = __read_pkru();
		if (vcpu->arch.pkru != vmx->host_pkru)
			__write_pkru(vmx->host_pkru);
	}

	kvm_put_guest_xcr0(vcpu);

	vmx->nested.nested_run_pending = 0;
	vmx->idt_vectoring_info = 0;

	vmx->exit_reason = vmx->fail ? 0xdead : vmcs_read32(VM_EXIT_REASON);
	if ((u16)vmx->exit_reason == EXIT_REASON_MCE_DURING_VMENTRY)
		kvm_machine_check();

	if (vmx->fail || (vmx->exit_reason & VMX_EXIT_REASONS_FAILED_VMENTRY))
		return;

	vmx->loaded_vmcs->launched = 1;
	vmx->idt_vectoring_info = vmcs_read32(IDT_VECTORING_INFO_FIELD);

	vmx_complete_atomic_exit(vmx);
	vmx_recover_nmi_blocking(vmx);
	vmx_complete_interrupts(vmx);
}
STACK_FRAME_NON_STANDARD(vmx_vcpu_run);

static struct kvm *vmx_vm_alloc(void)
{
	struct kvm_vmx *kvm_vmx = vzalloc(sizeof(struct kvm_vmx));

	if (!kvm_vmx)
		return NULL;

	return &kvm_vmx->kvm;
}

static void vmx_vm_free(struct kvm *kvm)
{
	vfree(to_kvm_vmx(kvm));
}

static void vmx_switch_vmcs(struct kvm_vcpu *vcpu, struct loaded_vmcs *vmcs)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	int cpu;

	if (vmx->loaded_vmcs == vmcs)
		return;

	cpu = get_cpu();
	vmx_vcpu_put(vcpu);
	vmx->loaded_vmcs = vmcs;
	vmx_vcpu_load(vcpu, cpu);
	put_cpu();
}

/*
 * Ensure that the current vmcs of the logical processor is the
 * vmcs01 of the vcpu before calling free_nested().
 */
static void vmx_free_vcpu_nested(struct kvm_vcpu *vcpu)
{
       struct vcpu_vmx *vmx = to_vmx(vcpu);

       vcpu_load(vcpu);
       vmx_switch_vmcs(vcpu, &vmx->vmcs01);
       free_nested(vmx);
       vcpu_put(vcpu);
}

static void vmx_free_vcpu(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);

	if (enable_pml)
		vmx_destroy_pml_buffer(vmx);
	free_vpid(vmx->vpid);
	leave_guest_mode(vcpu);
	vmx_free_vcpu_nested(vcpu);
	free_loaded_vmcs(vmx->loaded_vmcs);
	kfree(vmx->guest_msrs);
	kvm_vcpu_uninit(vcpu);
	kmem_cache_free(kvm_vcpu_cache, vmx);
}

static struct kvm_vcpu *vmx_create_vcpu(struct kvm *kvm, unsigned int id)
{
	int err;
	struct vcpu_vmx *vmx = kmem_cache_zalloc(kvm_vcpu_cache, GFP_KERNEL);
	unsigned long *msr_bitmap;
	int cpu;

	if (!vmx)
		return ERR_PTR(-ENOMEM);

	vmx->vpid = allocate_vpid();

	err = kvm_vcpu_init(&vmx->vcpu, kvm, id);
	if (err)
		goto free_vcpu;

	err = -ENOMEM;

	/*
	 * If PML is turned on, failure on enabling PML just results in failure
	 * of creating the vcpu, therefore we can simplify PML logic (by
	 * avoiding dealing with cases, such as enabling PML partially on vcpus
	 * for the guest, etc.
	 */
	if (enable_pml) {
		vmx->pml_pg = alloc_page(GFP_KERNEL | __GFP_ZERO);
		if (!vmx->pml_pg)
			goto uninit_vcpu;
	}

	vmx->guest_msrs = kmalloc(PAGE_SIZE, GFP_KERNEL);
	BUILD_BUG_ON(ARRAY_SIZE(vmx_msr_index) * sizeof(vmx->guest_msrs[0])
		     > PAGE_SIZE);

	if (!vmx->guest_msrs)
		goto free_pml;

	err = alloc_loaded_vmcs(&vmx->vmcs01);
	if (err < 0)
		goto free_msrs;

	msr_bitmap = vmx->vmcs01.msr_bitmap;
	vmx_disable_intercept_for_msr(msr_bitmap, MSR_FS_BASE, MSR_TYPE_RW);
	vmx_disable_intercept_for_msr(msr_bitmap, MSR_GS_BASE, MSR_TYPE_RW);
	vmx_disable_intercept_for_msr(msr_bitmap, MSR_KERNEL_GS_BASE, MSR_TYPE_RW);
	vmx_disable_intercept_for_msr(msr_bitmap, MSR_IA32_SYSENTER_CS, MSR_TYPE_RW);
	vmx_disable_intercept_for_msr(msr_bitmap, MSR_IA32_SYSENTER_ESP, MSR_TYPE_RW);
	vmx_disable_intercept_for_msr(msr_bitmap, MSR_IA32_SYSENTER_EIP, MSR_TYPE_RW);
	vmx->msr_bitmap_mode = 0;

	vmx->loaded_vmcs = &vmx->vmcs01;
	cpu = get_cpu();
	vmx_vcpu_load(&vmx->vcpu, cpu);
	vmx->vcpu.cpu = cpu;
	vmx_vcpu_setup(vmx);
	vmx_vcpu_put(&vmx->vcpu);
	put_cpu();
	if (cpu_need_virtualize_apic_accesses(&vmx->vcpu)) {
		err = alloc_apic_access_page(kvm);
		if (err)
			goto free_vmcs;
	}

	if (enable_ept && !enable_unrestricted_guest) {
		err = init_rmode_identity_map(kvm);
		if (err)
			goto free_vmcs;
	}

	if (nested)
		nested_vmx_setup_ctls_msrs(&vmx->nested.msrs,
					   kvm_vcpu_apicv_active(&vmx->vcpu));

	vmx->nested.posted_intr_nv = -1;
	vmx->nested.current_vmptr = -1ull;

	vmx->msr_ia32_feature_control_valid_bits = FEATURE_CONTROL_LOCKED;

	/*
	 * Enforce invariant: pi_desc.nv is always either POSTED_INTR_VECTOR
	 * or POSTED_INTR_WAKEUP_VECTOR.
	 */
	vmx->pi_desc.nv = POSTED_INTR_VECTOR;
	vmx->pi_desc.sn = 1;

	return &vmx->vcpu;

free_vmcs:
	free_loaded_vmcs(vmx->loaded_vmcs);
free_msrs:
	kfree(vmx->guest_msrs);
free_pml:
	vmx_destroy_pml_buffer(vmx);
uninit_vcpu:
	kvm_vcpu_uninit(&vmx->vcpu);
free_vcpu:
	free_vpid(vmx->vpid);
	kmem_cache_free(kvm_vcpu_cache, vmx);
	return ERR_PTR(err);
}

#define L1TF_MSG_SMT "L1TF CPU bug present and SMT on, data leak possible. See CVE-2018-3646 and https://www.kernel.org/doc/html/latest/admin-guide/hw-vuln/l1tf.html for details.\n"
#define L1TF_MSG_L1D "L1TF CPU bug present and virtualization mitigation disabled, data leak possible. See CVE-2018-3646 and https://www.kernel.org/doc/html/latest/admin-guide/hw-vuln/l1tf.html for details.\n"

static int vmx_vm_init(struct kvm *kvm)
{
	spin_lock_init(&to_kvm_vmx(kvm)->ept_pointer_lock);

	if (!ple_gap)
		kvm->arch.pause_in_guest = true;

	if (boot_cpu_has(X86_BUG_L1TF) && enable_ept) {
		switch (l1tf_mitigation) {
		case L1TF_MITIGATION_OFF:
		case L1TF_MITIGATION_FLUSH_NOWARN:
			/* 'I explicitly don't care' is set */
			break;
		case L1TF_MITIGATION_FLUSH:
		case L1TF_MITIGATION_FLUSH_NOSMT:
		case L1TF_MITIGATION_FULL:
			/*
			 * Warn upon starting the first VM in a potentially
			 * insecure environment.
			 */
			if (sched_smt_active())
				pr_warn_once(L1TF_MSG_SMT);
			if (l1tf_vmx_mitigation == VMENTER_L1D_FLUSH_NEVER)
				pr_warn_once(L1TF_MSG_L1D);
			break;
		case L1TF_MITIGATION_FULL_FORCE:
			/* Flush is enforced */
			break;
		}
	}
	return 0;
}

static void __init vmx_check_processor_compat(void *rtn)
{
	struct vmcs_config vmcs_conf;

	*(int *)rtn = 0;
	if (setup_vmcs_config(&vmcs_conf) < 0)
		*(int *)rtn = -EIO;
	nested_vmx_setup_ctls_msrs(&vmcs_conf.nested, enable_apicv);
	if (memcmp(&vmcs_config, &vmcs_conf, sizeof(struct vmcs_config)) != 0) {
		printk(KERN_ERR "kvm: CPU %d feature inconsistency!\n",
				smp_processor_id());
		*(int *)rtn = -EIO;
	}
}

static u64 vmx_get_mt_mask(struct kvm_vcpu *vcpu, gfn_t gfn, bool is_mmio)
{
	u8 cache;
	u64 ipat = 0;

	/* For VT-d and EPT combination
	 * 1. MMIO: always map as UC
	 * 2. EPT with VT-d:
	 *   a. VT-d without snooping control feature: can't guarantee the
	 *	result, try to trust guest.
	 *   b. VT-d with snooping control feature: snooping control feature of
	 *	VT-d engine can guarantee the cache correctness. Just set it
	 *	to WB to keep consistent with host. So the same as item 3.
	 * 3. EPT without VT-d: always map as WB and set IPAT=1 to keep
	 *    consistent with host MTRR
	 */
	if (is_mmio) {
		cache = MTRR_TYPE_UNCACHABLE;
		goto exit;
	}

	if (!kvm_arch_has_noncoherent_dma(vcpu->kvm)) {
		ipat = VMX_EPT_IPAT_BIT;
		cache = MTRR_TYPE_WRBACK;
		goto exit;
	}

	if (kvm_read_cr0(vcpu) & X86_CR0_CD) {
		ipat = VMX_EPT_IPAT_BIT;
		if (kvm_check_has_quirk(vcpu->kvm, KVM_X86_QUIRK_CD_NW_CLEARED))
			cache = MTRR_TYPE_WRBACK;
		else
			cache = MTRR_TYPE_UNCACHABLE;
		goto exit;
	}

	cache = kvm_mtrr_get_guest_memory_type(vcpu, gfn);

exit:
	return (cache << VMX_EPT_MT_EPTE_SHIFT) | ipat;
}

static int vmx_get_lpage_level(void)
{
	if (enable_ept && !cpu_has_vmx_ept_1g_page())
		return PT_DIRECTORY_LEVEL;
	else
		/* For shadow and EPT supported 1GB page */
		return PT_PDPE_LEVEL;
}

static void vmcs_set_secondary_exec_control(u32 new_ctl)
{
	/*
	 * These bits in the secondary execution controls field
	 * are dynamic, the others are mostly based on the hypervisor
	 * architecture and the guest's CPUID.  Do not touch the
	 * dynamic bits.
	 */
	u32 mask =
		SECONDARY_EXEC_SHADOW_VMCS |
		SECONDARY_EXEC_VIRTUALIZE_X2APIC_MODE |
		SECONDARY_EXEC_VIRTUALIZE_APIC_ACCESSES |
		SECONDARY_EXEC_DESC;

	u32 cur_ctl = vmcs_read32(SECONDARY_VM_EXEC_CONTROL);

	vmcs_write32(SECONDARY_VM_EXEC_CONTROL,
		     (new_ctl & ~mask) | (cur_ctl & mask));
}

/*
 * Generate MSR_IA32_VMX_CR{0,4}_FIXED1 according to CPUID. Only set bits
 * (indicating "allowed-1") if they are supported in the guest's CPUID.
 */
static void nested_vmx_cr_fixed1_bits_update(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	struct kvm_cpuid_entry2 *entry;

	vmx->nested.msrs.cr0_fixed1 = 0xffffffff;
	vmx->nested.msrs.cr4_fixed1 = X86_CR4_PCE;

#define cr4_fixed1_update(_cr4_mask, _reg, _cpuid_mask) do {		\
	if (entry && (entry->_reg & (_cpuid_mask)))			\
		vmx->nested.msrs.cr4_fixed1 |= (_cr4_mask);	\
} while (0)

	entry = kvm_find_cpuid_entry(vcpu, 0x1, 0);
	cr4_fixed1_update(X86_CR4_VME,        edx, bit(X86_FEATURE_VME));
	cr4_fixed1_update(X86_CR4_PVI,        edx, bit(X86_FEATURE_VME));
	cr4_fixed1_update(X86_CR4_TSD,        edx, bit(X86_FEATURE_TSC));
	cr4_fixed1_update(X86_CR4_DE,         edx, bit(X86_FEATURE_DE));
	cr4_fixed1_update(X86_CR4_PSE,        edx, bit(X86_FEATURE_PSE));
	cr4_fixed1_update(X86_CR4_PAE,        edx, bit(X86_FEATURE_PAE));
	cr4_fixed1_update(X86_CR4_MCE,        edx, bit(X86_FEATURE_MCE));
	cr4_fixed1_update(X86_CR4_PGE,        edx, bit(X86_FEATURE_PGE));
	cr4_fixed1_update(X86_CR4_OSFXSR,     edx, bit(X86_FEATURE_FXSR));
	cr4_fixed1_update(X86_CR4_OSXMMEXCPT, edx, bit(X86_FEATURE_XMM));
	cr4_fixed1_update(X86_CR4_VMXE,       ecx, bit(X86_FEATURE_VMX));
	cr4_fixed1_update(X86_CR4_SMXE,       ecx, bit(X86_FEATURE_SMX));
	cr4_fixed1_update(X86_CR4_PCIDE,      ecx, bit(X86_FEATURE_PCID));
	cr4_fixed1_update(X86_CR4_OSXSAVE,    ecx, bit(X86_FEATURE_XSAVE));

	entry = kvm_find_cpuid_entry(vcpu, 0x7, 0);
	cr4_fixed1_update(X86_CR4_FSGSBASE,   ebx, bit(X86_FEATURE_FSGSBASE));
	cr4_fixed1_update(X86_CR4_SMEP,       ebx, bit(X86_FEATURE_SMEP));
	cr4_fixed1_update(X86_CR4_SMAP,       ebx, bit(X86_FEATURE_SMAP));
	cr4_fixed1_update(X86_CR4_PKE,        ecx, bit(X86_FEATURE_PKU));
	cr4_fixed1_update(X86_CR4_UMIP,       ecx, bit(X86_FEATURE_UMIP));

#undef cr4_fixed1_update
}

static void nested_vmx_entry_exit_ctls_update(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);

	if (kvm_mpx_supported()) {
		bool mpx_enabled = guest_cpuid_has(vcpu, X86_FEATURE_MPX);

		if (mpx_enabled) {
			vmx->nested.msrs.entry_ctls_high |= VM_ENTRY_LOAD_BNDCFGS;
			vmx->nested.msrs.exit_ctls_high |= VM_EXIT_CLEAR_BNDCFGS;
		} else {
			vmx->nested.msrs.entry_ctls_high &= ~VM_ENTRY_LOAD_BNDCFGS;
			vmx->nested.msrs.exit_ctls_high &= ~VM_EXIT_CLEAR_BNDCFGS;
		}
	}
}

static void vmx_cpuid_update(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);

	if (cpu_has_secondary_exec_ctrls()) {
		vmx_compute_secondary_exec_control(vmx);
		vmcs_set_secondary_exec_control(vmx->secondary_exec_control);
	}

	if (nested_vmx_allowed(vcpu))
		to_vmx(vcpu)->msr_ia32_feature_control_valid_bits |=
			FEATURE_CONTROL_VMXON_ENABLED_OUTSIDE_SMX;
	else
		to_vmx(vcpu)->msr_ia32_feature_control_valid_bits &=
			~FEATURE_CONTROL_VMXON_ENABLED_OUTSIDE_SMX;

	if (nested_vmx_allowed(vcpu)) {
		nested_vmx_cr_fixed1_bits_update(vcpu);
		nested_vmx_entry_exit_ctls_update(vcpu);
	}
}

static void vmx_set_supported_cpuid(u32 func, struct kvm_cpuid_entry2 *entry)
{
	if (func == 1 && nested)
		entry->ecx |= bit(X86_FEATURE_VMX);
}

static void nested_ept_inject_page_fault(struct kvm_vcpu *vcpu,
		struct x86_exception *fault)
{
	struct vmcs12 *vmcs12 = get_vmcs12(vcpu);
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	u32 exit_reason;
	unsigned long exit_qualification = vcpu->arch.exit_qualification;

	if (vmx->nested.pml_full) {
		exit_reason = EXIT_REASON_PML_FULL;
		vmx->nested.pml_full = false;
		exit_qualification &= INTR_INFO_UNBLOCK_NMI;
	} else if (fault->error_code & PFERR_RSVD_MASK)
		exit_reason = EXIT_REASON_EPT_MISCONFIG;
	else
		exit_reason = EXIT_REASON_EPT_VIOLATION;

	nested_vmx_vmexit(vcpu, exit_reason, 0, exit_qualification);
	vmcs12->guest_physical_address = fault->address;
}

static bool nested_ept_ad_enabled(struct kvm_vcpu *vcpu)
{
	return nested_ept_get_cr3(vcpu) & VMX_EPTP_AD_ENABLE_BIT;
}

/* Callbacks for nested_ept_init_mmu_context: */

static unsigned long nested_ept_get_cr3(struct kvm_vcpu *vcpu)
{
	/* return the page table to be shadowed - in our case, EPT12 */
	return get_vmcs12(vcpu)->ept_pointer;
}

static int nested_ept_init_mmu_context(struct kvm_vcpu *vcpu)
{
	WARN_ON(mmu_is_nested(vcpu));
	if (!valid_ept_address(vcpu, nested_ept_get_cr3(vcpu)))
		return 1;

	kvm_init_shadow_ept_mmu(vcpu,
			to_vmx(vcpu)->nested.msrs.ept_caps &
			VMX_EPT_EXECUTE_ONLY_BIT,
			nested_ept_ad_enabled(vcpu),
			nested_ept_get_cr3(vcpu));
	vcpu->arch.mmu.set_cr3           = vmx_set_cr3;
	vcpu->arch.mmu.get_cr3           = nested_ept_get_cr3;
	vcpu->arch.mmu.inject_page_fault = nested_ept_inject_page_fault;

	vcpu->arch.walk_mmu              = &vcpu->arch.nested_mmu;
	return 0;
}

static void nested_ept_uninit_mmu_context(struct kvm_vcpu *vcpu)
{
	vcpu->arch.walk_mmu = &vcpu->arch.mmu;
}

static bool nested_vmx_is_page_fault_vmexit(struct vmcs12 *vmcs12,
					    u16 error_code)
{
	bool inequality, bit;

	bit = (vmcs12->exception_bitmap & (1u << PF_VECTOR)) != 0;
	inequality =
		(error_code & vmcs12->page_fault_error_code_mask) !=
		 vmcs12->page_fault_error_code_match;
	return inequality ^ bit;
}

static void vmx_inject_page_fault_nested(struct kvm_vcpu *vcpu,
		struct x86_exception *fault)
{
	struct vmcs12 *vmcs12 = get_vmcs12(vcpu);

	WARN_ON(!is_guest_mode(vcpu));

	if (nested_vmx_is_page_fault_vmexit(vmcs12, fault->error_code) &&
		!to_vmx(vcpu)->nested.nested_run_pending) {
		vmcs12->vm_exit_intr_error_code = fault->error_code;
		nested_vmx_vmexit(vcpu, EXIT_REASON_EXCEPTION_NMI,
				  PF_VECTOR | INTR_TYPE_HARD_EXCEPTION |
				  INTR_INFO_DELIVER_CODE_MASK | INTR_INFO_VALID_MASK,
				  fault->address);
	} else {
		kvm_inject_page_fault(vcpu, fault);
	}
}

static inline bool nested_vmx_prepare_msr_bitmap(struct kvm_vcpu *vcpu,
						 struct vmcs12 *vmcs12);

static void nested_get_vmcs12_pages(struct kvm_vcpu *vcpu)
{
	struct vmcs12 *vmcs12 = get_vmcs12(vcpu);
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	struct page *page;
	u64 hpa;

	if (nested_cpu_has2(vmcs12, SECONDARY_EXEC_VIRTUALIZE_APIC_ACCESSES)) {
		/*
		 * Translate L1 physical address to host physical
		 * address for vmcs02. Keep the page pinned, so this
		 * physical address remains valid. We keep a reference
		 * to it so we can release it later.
		 */
		if (vmx->nested.apic_access_page) { /* shouldn't happen */
			kvm_release_page_dirty(vmx->nested.apic_access_page);
			vmx->nested.apic_access_page = NULL;
		}
		page = kvm_vcpu_gpa_to_page(vcpu, vmcs12->apic_access_addr);
		/*
		 * If translation failed, no matter: This feature asks
		 * to exit when accessing the given address, and if it
		 * can never be accessed, this feature won't do
		 * anything anyway.
		 */
		if (!is_error_page(page)) {
			vmx->nested.apic_access_page = page;
			hpa = page_to_phys(vmx->nested.apic_access_page);
			vmcs_write64(APIC_ACCESS_ADDR, hpa);
		} else {
			vmcs_clear_bits(SECONDARY_VM_EXEC_CONTROL,
					SECONDARY_EXEC_VIRTUALIZE_APIC_ACCESSES);
		}
	}

	if (nested_cpu_has(vmcs12, CPU_BASED_TPR_SHADOW)) {
		if (vmx->nested.virtual_apic_page) { /* shouldn't happen */
			kvm_release_page_dirty(vmx->nested.virtual_apic_page);
			vmx->nested.virtual_apic_page = NULL;
		}
		page = kvm_vcpu_gpa_to_page(vcpu, vmcs12->virtual_apic_page_addr);

		/*
		 * If translation failed, VM entry will fail because
		 * prepare_vmcs02 set VIRTUAL_APIC_PAGE_ADDR to -1ull.
		 * Failing the vm entry is _not_ what the processor
		 * does but it's basically the only possibility we
		 * have.  We could still enter the guest if CR8 load
		 * exits are enabled, CR8 store exits are enabled, and
		 * virtualize APIC access is disabled; in this case
		 * the processor would never use the TPR shadow and we
		 * could simply clear the bit from the execution
		 * control.  But such a configuration is useless, so
		 * let's keep the code simple.
		 */
		if (!is_error_page(page)) {
			vmx->nested.virtual_apic_page = page;
			hpa = page_to_phys(vmx->nested.virtual_apic_page);
			vmcs_write64(VIRTUAL_APIC_PAGE_ADDR, hpa);
		}
	}

	if (nested_cpu_has_posted_intr(vmcs12)) {
		if (vmx->nested.pi_desc_page) { /* shouldn't happen */
			kunmap(vmx->nested.pi_desc_page);
			kvm_release_page_dirty(vmx->nested.pi_desc_page);
			vmx->nested.pi_desc_page = NULL;
			vmx->nested.pi_desc = NULL;
			vmcs_write64(POSTED_INTR_DESC_ADDR, -1ull);
		}
		page = kvm_vcpu_gpa_to_page(vcpu, vmcs12->posted_intr_desc_addr);
		if (is_error_page(page))
			return;
		vmx->nested.pi_desc_page = page;
		vmx->nested.pi_desc = kmap(vmx->nested.pi_desc_page);
		vmx->nested.pi_desc =
			(struct pi_desc *)((void *)vmx->nested.pi_desc +
			(unsigned long)(vmcs12->posted_intr_desc_addr &
			(PAGE_SIZE - 1)));
		vmcs_write64(POSTED_INTR_DESC_ADDR,
			page_to_phys(vmx->nested.pi_desc_page) +
			(unsigned long)(vmcs12->posted_intr_desc_addr &
			(PAGE_SIZE - 1)));
	}
	if (nested_vmx_prepare_msr_bitmap(vcpu, vmcs12))
		vmcs_set_bits(CPU_BASED_VM_EXEC_CONTROL,
			      CPU_BASED_USE_MSR_BITMAPS);
	else
		vmcs_clear_bits(CPU_BASED_VM_EXEC_CONTROL,
				CPU_BASED_USE_MSR_BITMAPS);
}

static void vmx_start_preemption_timer(struct kvm_vcpu *vcpu)
{
	u64 preemption_timeout = get_vmcs12(vcpu)->vmx_preemption_timer_value;
	struct vcpu_vmx *vmx = to_vmx(vcpu);

	/*
	 * A timer value of zero is architecturally guaranteed to cause
	 * a VMExit prior to executing any instructions in the guest.
	 */
	if (preemption_timeout == 0) {
		vmx_preemption_timer_fn(&vmx->nested.preemption_timer);
		return;
	}

	if (vcpu->arch.virtual_tsc_khz == 0)
		return;

	preemption_timeout <<= VMX_MISC_EMULATED_PREEMPTION_TIMER_RATE;
	preemption_timeout *= 1000000;
	do_div(preemption_timeout, vcpu->arch.virtual_tsc_khz);
	hrtimer_start(&vmx->nested.preemption_timer,
		      ns_to_ktime(preemption_timeout), HRTIMER_MODE_REL);
}

static int nested_vmx_check_io_bitmap_controls(struct kvm_vcpu *vcpu,
					       struct vmcs12 *vmcs12)
{
	if (!nested_cpu_has(vmcs12, CPU_BASED_USE_IO_BITMAPS))
		return 0;

	if (!page_address_valid(vcpu, vmcs12->io_bitmap_a) ||
	    !page_address_valid(vcpu, vmcs12->io_bitmap_b))
		return -EINVAL;

	return 0;
}

static int nested_vmx_check_msr_bitmap_controls(struct kvm_vcpu *vcpu,
						struct vmcs12 *vmcs12)
{
	if (!nested_cpu_has(vmcs12, CPU_BASED_USE_MSR_BITMAPS))
		return 0;

	if (!page_address_valid(vcpu, vmcs12->msr_bitmap))
		return -EINVAL;

	return 0;
}

static int nested_vmx_check_tpr_shadow_controls(struct kvm_vcpu *vcpu,
						struct vmcs12 *vmcs12)
{
	if (!nested_cpu_has(vmcs12, CPU_BASED_TPR_SHADOW))
		return 0;

	if (!page_address_valid(vcpu, vmcs12->virtual_apic_page_addr))
		return -EINVAL;

	return 0;
}

static inline void enable_x2apic_msr_intercepts(unsigned long *msr_bitmap) {
	int msr;

	for (msr = 0x800; msr <= 0x8ff; msr += BITS_PER_LONG) {
		unsigned word = msr / BITS_PER_LONG;

		msr_bitmap[word] = ~0;
		msr_bitmap[word + (0x800 / sizeof(long))] = ~0;
	}
}

/*
 * Merge L0's and L1's MSR bitmap, return false to indicate that
 * we do not use the hardware.
 */
static inline bool nested_vmx_prepare_msr_bitmap(struct kvm_vcpu *vcpu,
						 struct vmcs12 *vmcs12)
{
	int msr;
	struct page *page;
	unsigned long *msr_bitmap_l1;
	unsigned long *msr_bitmap_l0 = to_vmx(vcpu)->nested.vmcs02.msr_bitmap;
	/*
	 * pred_cmd & spec_ctrl are trying to verify two things:
	 *
	 * 1. L0 gave a permission to L1 to actually passthrough the MSR. This
	 *    ensures that we do not accidentally generate an L02 MSR bitmap
	 *    from the L12 MSR bitmap that is too permissive.
	 * 2. That L1 or L2s have actually used the MSR. This avoids
	 *    unnecessarily merging of the bitmap if the MSR is unused. This
	 *    works properly because we only update the L01 MSR bitmap lazily.
	 *    So even if L0 should pass L1 these MSRs, the L01 bitmap is only
	 *    updated to reflect this when L1 (or its L2s) actually write to
	 *    the MSR.
	 */
	bool pred_cmd = !msr_write_intercepted_l01(vcpu, MSR_IA32_PRED_CMD);
	bool spec_ctrl = !msr_write_intercepted_l01(vcpu, MSR_IA32_SPEC_CTRL);

	/* Nothing to do if the MSR bitmap is not in use.  */
	if (!cpu_has_vmx_msr_bitmap() ||
	    !nested_cpu_has(vmcs12, CPU_BASED_USE_MSR_BITMAPS))
		return false;

	if (!nested_cpu_has_virt_x2apic_mode(vmcs12) &&
	    !pred_cmd && !spec_ctrl)
		return false;

	page = kvm_vcpu_gpa_to_page(vcpu, vmcs12->msr_bitmap);
	if (is_error_page(page))
		return false;

	msr_bitmap_l1 = (unsigned long *)kmap(page);

	/*
	 * To keep the control flow simple, pay eight 8-byte writes (sixteen
	 * 4-byte writes on 32-bit systems) up front to enable intercepts for
	 * the x2APIC MSR range and selectively disable them below.
	 */
	enable_x2apic_msr_intercepts(msr_bitmap_l0);

	if (nested_cpu_has_virt_x2apic_mode(vmcs12)) {
		if (nested_cpu_has_apic_reg_virt(vmcs12)) {
			/*
			 * L0 need not intercept reads for MSRs between 0x800
			 * and 0x8ff, it just lets the processor take the value
			 * from the virtual-APIC page; take those 256 bits
			 * directly from the L1 bitmap.
			 */
			for (msr = 0x800; msr <= 0x8ff; msr += BITS_PER_LONG) {
				unsigned word = msr / BITS_PER_LONG;

				msr_bitmap_l0[word] = msr_bitmap_l1[word];
			}
		}

		nested_vmx_disable_intercept_for_msr(
			msr_bitmap_l1, msr_bitmap_l0,
			X2APIC_MSR(APIC_TASKPRI),
			MSR_TYPE_R | MSR_TYPE_W);

		if (nested_cpu_has_vid(vmcs12)) {
			nested_vmx_disable_intercept_for_msr(
				msr_bitmap_l1, msr_bitmap_l0,
				X2APIC_MSR(APIC_EOI),
				MSR_TYPE_W);
			nested_vmx_disable_intercept_for_msr(
				msr_bitmap_l1, msr_bitmap_l0,
				X2APIC_MSR(APIC_SELF_IPI),
				MSR_TYPE_W);
		}
	}

	if (spec_ctrl)
		nested_vmx_disable_intercept_for_msr(
					msr_bitmap_l1, msr_bitmap_l0,
					MSR_IA32_SPEC_CTRL,
					MSR_TYPE_R | MSR_TYPE_W);

	if (pred_cmd)
		nested_vmx_disable_intercept_for_msr(
					msr_bitmap_l1, msr_bitmap_l0,
					MSR_IA32_PRED_CMD,
					MSR_TYPE_W);

	kunmap(page);
	kvm_release_page_clean(page);

	return true;
}

static void nested_cache_shadow_vmcs12(struct kvm_vcpu *vcpu,
				       struct vmcs12 *vmcs12)
{
	struct vmcs12 *shadow;
	struct page *page;

	if (!nested_cpu_has_shadow_vmcs(vmcs12) ||
	    vmcs12->vmcs_link_pointer == -1ull)
		return;

	shadow = get_shadow_vmcs12(vcpu);
	page = kvm_vcpu_gpa_to_page(vcpu, vmcs12->vmcs_link_pointer);

	memcpy(shadow, kmap(page), VMCS12_SIZE);

	kunmap(page);
	kvm_release_page_clean(page);
}

static void nested_flush_cached_shadow_vmcs12(struct kvm_vcpu *vcpu,
					      struct vmcs12 *vmcs12)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);

	if (!nested_cpu_has_shadow_vmcs(vmcs12) ||
	    vmcs12->vmcs_link_pointer == -1ull)
		return;

	kvm_write_guest(vmx->vcpu.kvm, vmcs12->vmcs_link_pointer,
			get_shadow_vmcs12(vcpu), VMCS12_SIZE);
}

static int nested_vmx_check_apic_access_controls(struct kvm_vcpu *vcpu,
					  struct vmcs12 *vmcs12)
{
	if (nested_cpu_has2(vmcs12, SECONDARY_EXEC_VIRTUALIZE_APIC_ACCESSES) &&
	    !page_address_valid(vcpu, vmcs12->apic_access_addr))
		return -EINVAL;
	else
		return 0;
}

static int nested_vmx_check_apicv_controls(struct kvm_vcpu *vcpu,
					   struct vmcs12 *vmcs12)
{
	if (!nested_cpu_has_virt_x2apic_mode(vmcs12) &&
	    !nested_cpu_has_apic_reg_virt(vmcs12) &&
	    !nested_cpu_has_vid(vmcs12) &&
	    !nested_cpu_has_posted_intr(vmcs12))
		return 0;

	/*
	 * If virtualize x2apic mode is enabled,
	 * virtualize apic access must be disabled.
	 */
	if (nested_cpu_has_virt_x2apic_mode(vmcs12) &&
	    nested_cpu_has2(vmcs12, SECONDARY_EXEC_VIRTUALIZE_APIC_ACCESSES))
		return -EINVAL;

	/*
	 * If virtual interrupt delivery is enabled,
	 * we must exit on external interrupts.
	 */
	if (nested_cpu_has_vid(vmcs12) &&
	   !nested_exit_on_intr(vcpu))
		return -EINVAL;

	/*
	 * bits 15:8 should be zero in posted_intr_nv,
	 * the descriptor address has been already checked
	 * in nested_get_vmcs12_pages.
	 *
	 * bits 5:0 of posted_intr_desc_addr should be zero.
	 */
	if (nested_cpu_has_posted_intr(vmcs12) &&
	   (!nested_cpu_has_vid(vmcs12) ||
	    !nested_exit_intr_ack_set(vcpu) ||
	    (vmcs12->posted_intr_nv & 0xff00) ||
	    (vmcs12->posted_intr_desc_addr & 0x3f) ||
	    (vmcs12->posted_intr_desc_addr >> cpuid_maxphyaddr(vcpu))))
		return -EINVAL;

	/* tpr shadow is needed by all apicv features. */
	if (!nested_cpu_has(vmcs12, CPU_BASED_TPR_SHADOW))
		return -EINVAL;

	return 0;
}

static int nested_vmx_check_msr_switch(struct kvm_vcpu *vcpu,
				       unsigned long count_field,
				       unsigned long addr_field)
{
	struct vmcs12 *vmcs12 = get_vmcs12(vcpu);
	int maxphyaddr;
	u64 count, addr;

	if (vmcs12_read_any(vmcs12, count_field, &count) ||
	    vmcs12_read_any(vmcs12, addr_field, &addr)) {
		WARN_ON(1);
		return -EINVAL;
	}
	if (count == 0)
		return 0;
	maxphyaddr = cpuid_maxphyaddr(vcpu);
	if (!IS_ALIGNED(addr, 16) || addr >> maxphyaddr ||
	    (addr + count * sizeof(struct vmx_msr_entry) - 1) >> maxphyaddr) {
		pr_debug_ratelimited(
			"nVMX: invalid MSR switch (0x%lx, %d, %llu, 0x%08llx)",
			addr_field, maxphyaddr, count, addr);
		return -EINVAL;
	}
	return 0;
}

static int nested_vmx_check_msr_switch_controls(struct kvm_vcpu *vcpu,
						struct vmcs12 *vmcs12)
{
	if (vmcs12->vm_exit_msr_load_count == 0 &&
	    vmcs12->vm_exit_msr_store_count == 0 &&
	    vmcs12->vm_entry_msr_load_count == 0)
		return 0; /* Fast path */
	if (nested_vmx_check_msr_switch(vcpu, VM_EXIT_MSR_LOAD_COUNT,
					VM_EXIT_MSR_LOAD_ADDR) ||
	    nested_vmx_check_msr_switch(vcpu, VM_EXIT_MSR_STORE_COUNT,
					VM_EXIT_MSR_STORE_ADDR) ||
	    nested_vmx_check_msr_switch(vcpu, VM_ENTRY_MSR_LOAD_COUNT,
					VM_ENTRY_MSR_LOAD_ADDR))
		return -EINVAL;
	return 0;
}

static int nested_vmx_check_pml_controls(struct kvm_vcpu *vcpu,
					 struct vmcs12 *vmcs12)
{
	u64 address = vmcs12->pml_address;
	int maxphyaddr = cpuid_maxphyaddr(vcpu);

	if (nested_cpu_has2(vmcs12, SECONDARY_EXEC_ENABLE_PML)) {
		if (!nested_cpu_has_ept(vmcs12) ||
		    !IS_ALIGNED(address, 4096)  ||
		    address >> maxphyaddr)
			return -EINVAL;
	}

	return 0;
}

static int nested_vmx_check_shadow_vmcs_controls(struct kvm_vcpu *vcpu,
						 struct vmcs12 *vmcs12)
{
	if (!nested_cpu_has_shadow_vmcs(vmcs12))
		return 0;

	if (!page_address_valid(vcpu, vmcs12->vmread_bitmap) ||
	    !page_address_valid(vcpu, vmcs12->vmwrite_bitmap))
		return -EINVAL;

	return 0;
}

static int nested_vmx_msr_check_common(struct kvm_vcpu *vcpu,
				       struct vmx_msr_entry *e)
{
	/* x2APIC MSR accesses are not allowed */
	if (vcpu->arch.apic_base & X2APIC_ENABLE && e->index >> 8 == 0x8)
		return -EINVAL;
	if (e->index == MSR_IA32_UCODE_WRITE || /* SDM Table 35-2 */
	    e->index == MSR_IA32_UCODE_REV)
		return -EINVAL;
	if (e->reserved != 0)
		return -EINVAL;
	return 0;
}

static int nested_vmx_load_msr_check(struct kvm_vcpu *vcpu,
				     struct vmx_msr_entry *e)
{
	if (e->index == MSR_FS_BASE ||
	    e->index == MSR_GS_BASE ||
	    e->index == MSR_IA32_SMM_MONITOR_CTL || /* SMM is not supported */
	    nested_vmx_msr_check_common(vcpu, e))
		return -EINVAL;
	return 0;
}

static int nested_vmx_store_msr_check(struct kvm_vcpu *vcpu,
				      struct vmx_msr_entry *e)
{
	if (e->index == MSR_IA32_SMBASE || /* SMM is not supported */
	    nested_vmx_msr_check_common(vcpu, e))
		return -EINVAL;
	return 0;
}

/*
 * Load guest's/host's msr at nested entry/exit.
 * return 0 for success, entry index for failure.
 */
static u32 nested_vmx_load_msr(struct kvm_vcpu *vcpu, u64 gpa, u32 count)
{
	u32 i;
	struct vmx_msr_entry e;
	struct msr_data msr;

	msr.host_initiated = false;
	for (i = 0; i < count; i++) {
		if (kvm_vcpu_read_guest(vcpu, gpa + i * sizeof(e),
					&e, sizeof(e))) {
			pr_debug_ratelimited(
				"%s cannot read MSR entry (%u, 0x%08llx)\n",
				__func__, i, gpa + i * sizeof(e));
			goto fail;
		}
		if (nested_vmx_load_msr_check(vcpu, &e)) {
			pr_debug_ratelimited(
				"%s check failed (%u, 0x%x, 0x%x)\n",
				__func__, i, e.index, e.reserved);
			goto fail;
		}
		msr.index = e.index;
		msr.data = e.value;
		if (kvm_set_msr(vcpu, &msr)) {
			pr_debug_ratelimited(
				"%s cannot write MSR (%u, 0x%x, 0x%llx)\n",
				__func__, i, e.index, e.value);
			goto fail;
		}
	}
	return 0;
fail:
	return i + 1;
}

static int nested_vmx_store_msr(struct kvm_vcpu *vcpu, u64 gpa, u32 count)
{
	u32 i;
	struct vmx_msr_entry e;

	for (i = 0; i < count; i++) {
		struct msr_data msr_info;
		if (kvm_vcpu_read_guest(vcpu,
					gpa + i * sizeof(e),
					&e, 2 * sizeof(u32))) {
			pr_debug_ratelimited(
				"%s cannot read MSR entry (%u, 0x%08llx)\n",
				__func__, i, gpa + i * sizeof(e));
			return -EINVAL;
		}
		if (nested_vmx_store_msr_check(vcpu, &e)) {
			pr_debug_ratelimited(
				"%s check failed (%u, 0x%x, 0x%x)\n",
				__func__, i, e.index, e.reserved);
			return -EINVAL;
		}
		msr_info.host_initiated = false;
		msr_info.index = e.index;
		if (kvm_get_msr(vcpu, &msr_info)) {
			pr_debug_ratelimited(
				"%s cannot read MSR (%u, 0x%x)\n",
				__func__, i, e.index);
			return -EINVAL;
		}
		if (kvm_vcpu_write_guest(vcpu,
					 gpa + i * sizeof(e) +
					     offsetof(struct vmx_msr_entry, value),
					 &msr_info.data, sizeof(msr_info.data))) {
			pr_debug_ratelimited(
				"%s cannot write MSR (%u, 0x%x, 0x%llx)\n",
				__func__, i, e.index, msr_info.data);
			return -EINVAL;
		}
	}
	return 0;
}

static bool nested_cr3_valid(struct kvm_vcpu *vcpu, unsigned long val)
{
	unsigned long invalid_mask;

	invalid_mask = (~0ULL) << cpuid_maxphyaddr(vcpu);
	return (val & invalid_mask) == 0;
}

/*
 * Load guest's/host's cr3 at nested entry/exit. nested_ept is true if we are
 * emulating VM entry into a guest with EPT enabled.
 * Returns 0 on success, 1 on failure. Invalid state exit qualification code
 * is assigned to entry_failure_code on failure.
 */
static int nested_vmx_load_cr3(struct kvm_vcpu *vcpu, unsigned long cr3, bool nested_ept,
			       u32 *entry_failure_code)
{
	if (cr3 != kvm_read_cr3(vcpu) || (!nested_ept && pdptrs_changed(vcpu))) {
		if (!nested_cr3_valid(vcpu, cr3)) {
			*entry_failure_code = ENTRY_FAIL_DEFAULT;
			return 1;
		}

		/*
		 * If PAE paging and EPT are both on, CR3 is not used by the CPU and
		 * must not be dereferenced.
		 */
		if (is_pae_paging(vcpu) && !nested_ept) {
			if (!load_pdptrs(vcpu, vcpu->arch.walk_mmu, cr3)) {
				*entry_failure_code = ENTRY_FAIL_PDPTE;
				return 1;
			}
		}
	}

	if (!nested_ept)
		kvm_mmu_new_cr3(vcpu, cr3, false);

	vcpu->arch.cr3 = cr3;
	__set_bit(VCPU_EXREG_CR3, (ulong *)&vcpu->arch.regs_avail);

	kvm_init_mmu(vcpu, false);

	return 0;
}

static void prepare_vmcs02_full(struct kvm_vcpu *vcpu, struct vmcs12 *vmcs12)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);

	vmcs_write16(GUEST_ES_SELECTOR, vmcs12->guest_es_selector);
	vmcs_write16(GUEST_SS_SELECTOR, vmcs12->guest_ss_selector);
	vmcs_write16(GUEST_DS_SELECTOR, vmcs12->guest_ds_selector);
	vmcs_write16(GUEST_FS_SELECTOR, vmcs12->guest_fs_selector);
	vmcs_write16(GUEST_GS_SELECTOR, vmcs12->guest_gs_selector);
	vmcs_write16(GUEST_LDTR_SELECTOR, vmcs12->guest_ldtr_selector);
	vmcs_write16(GUEST_TR_SELECTOR, vmcs12->guest_tr_selector);
	vmcs_write32(GUEST_ES_LIMIT, vmcs12->guest_es_limit);
	vmcs_write32(GUEST_SS_LIMIT, vmcs12->guest_ss_limit);
	vmcs_write32(GUEST_DS_LIMIT, vmcs12->guest_ds_limit);
	vmcs_write32(GUEST_FS_LIMIT, vmcs12->guest_fs_limit);
	vmcs_write32(GUEST_GS_LIMIT, vmcs12->guest_gs_limit);
	vmcs_write32(GUEST_LDTR_LIMIT, vmcs12->guest_ldtr_limit);
	vmcs_write32(GUEST_TR_LIMIT, vmcs12->guest_tr_limit);
	vmcs_write32(GUEST_GDTR_LIMIT, vmcs12->guest_gdtr_limit);
	vmcs_write32(GUEST_IDTR_LIMIT, vmcs12->guest_idtr_limit);
	vmcs_write32(GUEST_ES_AR_BYTES, vmcs12->guest_es_ar_bytes);
	vmcs_write32(GUEST_SS_AR_BYTES, vmcs12->guest_ss_ar_bytes);
	vmcs_write32(GUEST_DS_AR_BYTES, vmcs12->guest_ds_ar_bytes);
	vmcs_write32(GUEST_FS_AR_BYTES, vmcs12->guest_fs_ar_bytes);
	vmcs_write32(GUEST_GS_AR_BYTES, vmcs12->guest_gs_ar_bytes);
	vmcs_write32(GUEST_LDTR_AR_BYTES, vmcs12->guest_ldtr_ar_bytes);
	vmcs_write32(GUEST_TR_AR_BYTES, vmcs12->guest_tr_ar_bytes);
	vmcs_writel(GUEST_SS_BASE, vmcs12->guest_ss_base);
	vmcs_writel(GUEST_DS_BASE, vmcs12->guest_ds_base);
	vmcs_writel(GUEST_FS_BASE, vmcs12->guest_fs_base);
	vmcs_writel(GUEST_GS_BASE, vmcs12->guest_gs_base);
	vmcs_writel(GUEST_LDTR_BASE, vmcs12->guest_ldtr_base);
	vmcs_writel(GUEST_TR_BASE, vmcs12->guest_tr_base);
	vmcs_writel(GUEST_GDTR_BASE, vmcs12->guest_gdtr_base);
	vmcs_writel(GUEST_IDTR_BASE, vmcs12->guest_idtr_base);

	vmcs_write32(GUEST_SYSENTER_CS, vmcs12->guest_sysenter_cs);
	vmcs_writel(GUEST_PENDING_DBG_EXCEPTIONS,
		vmcs12->guest_pending_dbg_exceptions);
	vmcs_writel(GUEST_SYSENTER_ESP, vmcs12->guest_sysenter_esp);
	vmcs_writel(GUEST_SYSENTER_EIP, vmcs12->guest_sysenter_eip);

	if (nested_cpu_has_xsaves(vmcs12))
		vmcs_write64(XSS_EXIT_BITMAP, vmcs12->xss_exit_bitmap);
	vmcs_write64(VMCS_LINK_POINTER, -1ull);

	if (cpu_has_vmx_posted_intr())
		vmcs_write16(POSTED_INTR_NV, POSTED_INTR_NESTED_VECTOR);

	/*
	 * Whether page-faults are trapped is determined by a combination of
	 * 3 settings: PFEC_MASK, PFEC_MATCH and EXCEPTION_BITMAP.PF.
	 * If enable_ept, L0 doesn't care about page faults and we should
	 * set all of these to L1's desires. However, if !enable_ept, L0 does
	 * care about (at least some) page faults, and because it is not easy
	 * (if at all possible?) to merge L0 and L1's desires, we simply ask
	 * to exit on each and every L2 page fault. This is done by setting
	 * MASK=MATCH=0 and (see below) EB.PF=1.
	 * Note that below we don't need special code to set EB.PF beyond the
	 * "or"ing of the EB of vmcs01 and vmcs12, because when enable_ept,
	 * vmcs01's EB.PF is 0 so the "or" will take vmcs12's value, and when
	 * !enable_ept, EB.PF is 1, so the "or" will always be 1.
	 */
	vmcs_write32(PAGE_FAULT_ERROR_CODE_MASK,
		enable_ept ? vmcs12->page_fault_error_code_mask : 0);
	vmcs_write32(PAGE_FAULT_ERROR_CODE_MATCH,
		enable_ept ? vmcs12->page_fault_error_code_match : 0);

	/* All VMFUNCs are currently emulated through L0 vmexits.  */
	if (cpu_has_vmx_vmfunc())
		vmcs_write64(VM_FUNCTION_CONTROL, 0);

	if (cpu_has_vmx_apicv()) {
		vmcs_write64(EOI_EXIT_BITMAP0, vmcs12->eoi_exit_bitmap0);
		vmcs_write64(EOI_EXIT_BITMAP1, vmcs12->eoi_exit_bitmap1);
		vmcs_write64(EOI_EXIT_BITMAP2, vmcs12->eoi_exit_bitmap2);
		vmcs_write64(EOI_EXIT_BITMAP3, vmcs12->eoi_exit_bitmap3);
	}

	/*
	 * Set host-state according to L0's settings (vmcs12 is irrelevant here)
	 * Some constant fields are set here by vmx_set_constant_host_state().
	 * Other fields are different per CPU, and will be set later when
	 * vmx_vcpu_load() is called, and when vmx_prepare_switch_to_guest()
	 * is called.
	 */
	vmx_set_constant_host_state(vmx);

	/*
	 * Set the MSR load/store lists to match L0's settings.
	 */
	vmcs_write32(VM_EXIT_MSR_STORE_COUNT, 0);
	vmcs_write32(VM_EXIT_MSR_LOAD_COUNT, vmx->msr_autoload.host.nr);
	vmcs_write64(VM_EXIT_MSR_LOAD_ADDR, __pa(vmx->msr_autoload.host.val));
	vmcs_write32(VM_ENTRY_MSR_LOAD_COUNT, vmx->msr_autoload.guest.nr);
	vmcs_write64(VM_ENTRY_MSR_LOAD_ADDR, __pa(vmx->msr_autoload.guest.val));

	set_cr4_guest_host_mask(vmx);

	if (kvm_mpx_supported() && vmx->nested.nested_run_pending &&
	    (vmcs12->vm_entry_controls & VM_ENTRY_LOAD_BNDCFGS))
		vmcs_write64(GUEST_BNDCFGS, vmcs12->guest_bndcfgs);

	if (enable_vpid) {
		if (nested_cpu_has_vpid(vmcs12) && vmx->nested.vpid02)
			vmcs_write16(VIRTUAL_PROCESSOR_ID, vmx->nested.vpid02);
		else
			vmcs_write16(VIRTUAL_PROCESSOR_ID, vmx->vpid);
	}

	/*
	 * L1 may access the L2's PDPTR, so save them to construct vmcs12
	 */
	if (enable_ept) {
		vmcs_write64(GUEST_PDPTR0, vmcs12->guest_pdptr0);
		vmcs_write64(GUEST_PDPTR1, vmcs12->guest_pdptr1);
		vmcs_write64(GUEST_PDPTR2, vmcs12->guest_pdptr2);
		vmcs_write64(GUEST_PDPTR3, vmcs12->guest_pdptr3);
	}

	if (cpu_has_vmx_msr_bitmap())
		vmcs_write64(MSR_BITMAP, __pa(vmx->nested.vmcs02.msr_bitmap));
}

/*
 * prepare_vmcs02 is called when the L1 guest hypervisor runs its nested
 * L2 guest. L1 has a vmcs for L2 (vmcs12), and this function "merges" it
 * with L0's requirements for its guest (a.k.a. vmcs01), so we can run the L2
 * guest in a way that will both be appropriate to L1's requests, and our
 * needs. In addition to modifying the active vmcs (which is vmcs02), this
 * function also has additional necessary side-effects, like setting various
 * vcpu->arch fields.
 * Returns 0 on success, 1 on failure. Invalid state exit qualification code
 * is assigned to entry_failure_code on failure.
 */
static int prepare_vmcs02(struct kvm_vcpu *vcpu, struct vmcs12 *vmcs12,
			  u32 *entry_failure_code)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	u32 exec_control, vmcs12_exec_ctrl;

	if (vmx->nested.dirty_vmcs12) {
		prepare_vmcs02_full(vcpu, vmcs12);
		vmx->nested.dirty_vmcs12 = false;
	}

	/*
	 * First, the fields that are shadowed.  This must be kept in sync
	 * with vmx_shadow_fields.h.
	 */

	vmcs_write16(GUEST_CS_SELECTOR, vmcs12->guest_cs_selector);
	vmcs_write32(GUEST_CS_LIMIT, vmcs12->guest_cs_limit);
	vmcs_write32(GUEST_CS_AR_BYTES, vmcs12->guest_cs_ar_bytes);
	vmcs_writel(GUEST_ES_BASE, vmcs12->guest_es_base);
	vmcs_writel(GUEST_CS_BASE, vmcs12->guest_cs_base);

	if (vmx->nested.nested_run_pending &&
	    (vmcs12->vm_entry_controls & VM_ENTRY_LOAD_DEBUG_CONTROLS)) {
		kvm_set_dr(vcpu, 7, vmcs12->guest_dr7);
		vmcs_write64(GUEST_IA32_DEBUGCTL, vmcs12->guest_ia32_debugctl);
	} else {
		kvm_set_dr(vcpu, 7, vcpu->arch.dr7);
		vmcs_write64(GUEST_IA32_DEBUGCTL, vmx->nested.vmcs01_debugctl);
	}
	if (kvm_mpx_supported() && (!vmx->nested.nested_run_pending ||
	    !(vmcs12->vm_entry_controls & VM_ENTRY_LOAD_BNDCFGS)))
		vmcs_write64(GUEST_BNDCFGS, vmx->nested.vmcs01_guest_bndcfgs);
	if (vmx->nested.nested_run_pending) {
		vmcs_write32(VM_ENTRY_INTR_INFO_FIELD,
			     vmcs12->vm_entry_intr_info_field);
		vmcs_write32(VM_ENTRY_EXCEPTION_ERROR_CODE,
			     vmcs12->vm_entry_exception_error_code);
		vmcs_write32(VM_ENTRY_INSTRUCTION_LEN,
			     vmcs12->vm_entry_instruction_len);
		vmcs_write32(GUEST_INTERRUPTIBILITY_INFO,
			     vmcs12->guest_interruptibility_info);
		vmx->loaded_vmcs->nmi_known_unmasked =
			!(vmcs12->guest_interruptibility_info & GUEST_INTR_STATE_NMI);
	} else {
		vmcs_write32(VM_ENTRY_INTR_INFO_FIELD, 0);
	}
	vmx_set_rflags(vcpu, vmcs12->guest_rflags);

	exec_control = vmcs12->pin_based_vm_exec_control;

	/* Preemption timer setting is computed directly in vmx_vcpu_run.  */
	exec_control |= vmcs_config.pin_based_exec_ctrl;
	exec_control &= ~PIN_BASED_VMX_PREEMPTION_TIMER;
	vmx->loaded_vmcs->hv_timer_armed = false;

	/* Posted interrupts setting is only taken from vmcs12.  */
	if (nested_cpu_has_posted_intr(vmcs12)) {
		vmx->nested.posted_intr_nv = vmcs12->posted_intr_nv;
		vmx->nested.pi_pending = false;
	} else {
		exec_control &= ~PIN_BASED_POSTED_INTR;
	}

	vmcs_write32(PIN_BASED_VM_EXEC_CONTROL, exec_control);

	vmx->nested.preemption_timer_expired = false;
	if (nested_cpu_has_preemption_timer(vmcs12))
		vmx_start_preemption_timer(vcpu);

	if (cpu_has_secondary_exec_ctrls()) {
		exec_control = vmx->secondary_exec_control;

		/* Take the following fields only from vmcs12 */
		exec_control &= ~(SECONDARY_EXEC_VIRTUALIZE_APIC_ACCESSES |
				  SECONDARY_EXEC_ENABLE_INVPCID |
				  SECONDARY_EXEC_RDTSCP |
				  SECONDARY_EXEC_XSAVES |
				  SECONDARY_EXEC_VIRTUAL_INTR_DELIVERY |
				  SECONDARY_EXEC_APIC_REGISTER_VIRT |
				  SECONDARY_EXEC_ENABLE_VMFUNC);
		if (nested_cpu_has(vmcs12,
				   CPU_BASED_ACTIVATE_SECONDARY_CONTROLS)) {
			vmcs12_exec_ctrl = vmcs12->secondary_vm_exec_control &
				~SECONDARY_EXEC_ENABLE_PML;
			exec_control |= vmcs12_exec_ctrl;
		}

		/* VMCS shadowing for L2 is emulated for now */
		exec_control &= ~SECONDARY_EXEC_SHADOW_VMCS;

		if (exec_control & SECONDARY_EXEC_VIRTUAL_INTR_DELIVERY)
			vmcs_write16(GUEST_INTR_STATUS,
				vmcs12->guest_intr_status);

		/*
		 * Write an illegal value to APIC_ACCESS_ADDR. Later,
		 * nested_get_vmcs12_pages will either fix it up or
		 * remove the VM execution control.
		 */
		if (exec_control & SECONDARY_EXEC_VIRTUALIZE_APIC_ACCESSES)
			vmcs_write64(APIC_ACCESS_ADDR, -1ull);

		if (exec_control & SECONDARY_EXEC_ENCLS_EXITING)
			vmcs_write64(ENCLS_EXITING_BITMAP, -1ull);

		vmcs_write32(SECONDARY_VM_EXEC_CONTROL, exec_control);
	}

	/*
	 * HOST_RSP is normally set correctly in vmx_vcpu_run() just before
	 * entry, but only if the current (host) sp changed from the value
	 * we wrote last (vmx->host_rsp). This cache is no longer relevant
	 * if we switch vmcs, and rather than hold a separate cache per vmcs,
	 * here we just force the write to happen on entry.
	 */
	vmx->host_rsp = 0;

	exec_control = vmx_exec_control(vmx); /* L0's desires */
	exec_control &= ~CPU_BASED_VIRTUAL_INTR_PENDING;
	exec_control &= ~CPU_BASED_VIRTUAL_NMI_PENDING;
	exec_control &= ~CPU_BASED_TPR_SHADOW;
	exec_control |= vmcs12->cpu_based_vm_exec_control;

	/*
	 * Write an illegal value to VIRTUAL_APIC_PAGE_ADDR. Later, if
	 * nested_get_vmcs12_pages can't fix it up, the illegal value
	 * will result in a VM entry failure.
	 */
	if (exec_control & CPU_BASED_TPR_SHADOW) {
		vmcs_write64(VIRTUAL_APIC_PAGE_ADDR, -1ull);
		vmcs_write32(TPR_THRESHOLD, vmcs12->tpr_threshold);
	} else {
#ifdef CONFIG_X86_64
		exec_control |= CPU_BASED_CR8_LOAD_EXITING |
				CPU_BASED_CR8_STORE_EXITING;
#endif
	}

	/*
	 * A vmexit (to either L1 hypervisor or L0 userspace) is always needed
	 * for I/O port accesses.
	 */
	exec_control &= ~CPU_BASED_USE_IO_BITMAPS;
	exec_control |= CPU_BASED_UNCOND_IO_EXITING;

	vmcs_write32(CPU_BASED_VM_EXEC_CONTROL, exec_control);

	/* EXCEPTION_BITMAP and CR0_GUEST_HOST_MASK should basically be the
	 * bitwise-or of what L1 wants to trap for L2, and what we want to
	 * trap. Note that CR0.TS also needs updating - we do this later.
	 */
	update_exception_bitmap(vcpu);
	vcpu->arch.cr0_guest_owned_bits &= ~vmcs12->cr0_guest_host_mask;
	vmcs_writel(CR0_GUEST_HOST_MASK, ~vcpu->arch.cr0_guest_owned_bits);

	/* L2->L1 exit controls are emulated - the hardware exit is to L0 so
	 * we should use its exit controls. Note that VM_EXIT_LOAD_IA32_EFER
	 * bits are further modified by vmx_set_efer() below.
	 */
	vmcs_write32(VM_EXIT_CONTROLS, vmcs_config.vmexit_ctrl);

	/* vmcs12's VM_ENTRY_LOAD_IA32_EFER and VM_ENTRY_IA32E_MODE are
	 * emulated by vmx_set_efer(), below.
	 */
	vm_entry_controls_init(vmx, 
		(vmcs12->vm_entry_controls & ~VM_ENTRY_LOAD_IA32_EFER &
			~VM_ENTRY_IA32E_MODE) |
		(vmcs_config.vmentry_ctrl & ~VM_ENTRY_IA32E_MODE));

	if (vmx->nested.nested_run_pending &&
	    (vmcs12->vm_entry_controls & VM_ENTRY_LOAD_IA32_PAT)) {
		vmcs_write64(GUEST_IA32_PAT, vmcs12->guest_ia32_pat);
		vcpu->arch.pat = vmcs12->guest_ia32_pat;
	} else if (vmcs_config.vmentry_ctrl & VM_ENTRY_LOAD_IA32_PAT) {
		vmcs_write64(GUEST_IA32_PAT, vmx->vcpu.arch.pat);
	}

	vmcs_write64(TSC_OFFSET, vcpu->arch.tsc_offset);

	if (kvm_has_tsc_control)
		decache_tsc_multiplier(vmx);

	if (enable_vpid) {
		/*
		 * There is no direct mapping between vpid02 and vpid12, the
		 * vpid02 is per-vCPU for L0 and reused while the value of
		 * vpid12 is changed w/ one invvpid during nested vmentry.
		 * The vpid12 is allocated by L1 for L2, so it will not
		 * influence global bitmap(for vpid01 and vpid02 allocation)
		 * even if spawn a lot of nested vCPUs.
		 */
		if (nested_cpu_has_vpid(vmcs12) && vmx->nested.vpid02) {
			if (vmcs12->virtual_processor_id != vmx->nested.last_vpid) {
				vmx->nested.last_vpid = vmcs12->virtual_processor_id;
				__vmx_flush_tlb(vcpu, vmx->nested.vpid02, true);
			}
		} else {
			vmx_flush_tlb(vcpu, true);
		}
	}

	if (enable_pml) {
		/*
		 * Conceptually we want to copy the PML address and index from
		 * vmcs01 here, and then back to vmcs01 on nested vmexit. But,
		 * since we always flush the log on each vmexit, this happens
		 * to be equivalent to simply resetting the fields in vmcs02.
		 */
		ASSERT(vmx->pml_pg);
		vmcs_write64(PML_ADDRESS, page_to_phys(vmx->pml_pg));
		vmcs_write16(GUEST_PML_INDEX, PML_ENTITY_NUM - 1);
	}

	if (nested_cpu_has_ept(vmcs12)) {
		if (nested_ept_init_mmu_context(vcpu)) {
			*entry_failure_code = ENTRY_FAIL_DEFAULT;
			return 1;
		}
	} else if (nested_cpu_has2(vmcs12,
				   SECONDARY_EXEC_VIRTUALIZE_APIC_ACCESSES)) {
		vmx_flush_tlb(vcpu, true);
	}

	/*
	 * This sets GUEST_CR0 to vmcs12->guest_cr0, possibly modifying those
	 * bits which we consider mandatory enabled.
	 * The CR0_READ_SHADOW is what L2 should have expected to read given
	 * the specifications by L1; It's not enough to take
	 * vmcs12->cr0_read_shadow because on our cr0_guest_host_mask we we
	 * have more bits than L1 expected.
	 */
	vmx_set_cr0(vcpu, vmcs12->guest_cr0);
	vmcs_writel(CR0_READ_SHADOW, nested_read_cr0(vmcs12));

	vmx_set_cr4(vcpu, vmcs12->guest_cr4);
	vmcs_writel(CR4_READ_SHADOW, nested_read_cr4(vmcs12));

	if (vmx->nested.nested_run_pending &&
	    (vmcs12->vm_entry_controls & VM_ENTRY_LOAD_IA32_EFER))
		vcpu->arch.efer = vmcs12->guest_ia32_efer;
	else if (vmcs12->vm_entry_controls & VM_ENTRY_IA32E_MODE)
		vcpu->arch.efer |= (EFER_LMA | EFER_LME);
	else
		vcpu->arch.efer &= ~(EFER_LMA | EFER_LME);
	/* Note: modifies VM_ENTRY/EXIT_CONTROLS and GUEST/HOST_IA32_EFER */
	vmx_set_efer(vcpu, vcpu->arch.efer);

	/*
	 * Guest state is invalid and unrestricted guest is disabled,
	 * which means L1 attempted VMEntry to L2 with invalid state.
	 * Fail the VMEntry.
	 */
	if (vmx->emulation_required) {
		*entry_failure_code = ENTRY_FAIL_DEFAULT;
		return 1;
	}

	/* Shadow page tables on either EPT or shadow page tables. */
	if (nested_vmx_load_cr3(vcpu, vmcs12->guest_cr3, nested_cpu_has_ept(vmcs12),
				entry_failure_code))
		return 1;

	if (!enable_ept)
		vcpu->arch.walk_mmu->inject_page_fault = vmx_inject_page_fault_nested;

	kvm_register_write(vcpu, VCPU_REGS_RSP, vmcs12->guest_rsp);
	kvm_register_write(vcpu, VCPU_REGS_RIP, vmcs12->guest_rip);
	return 0;
}

static int nested_vmx_check_nmi_controls(struct vmcs12 *vmcs12)
{
	if (!nested_cpu_has_nmi_exiting(vmcs12) &&
	    nested_cpu_has_virtual_nmis(vmcs12))
		return -EINVAL;

	if (!nested_cpu_has_virtual_nmis(vmcs12) &&
	    nested_cpu_has(vmcs12, CPU_BASED_VIRTUAL_NMI_PENDING))
		return -EINVAL;

	return 0;
}

static int check_vmentry_prereqs(struct kvm_vcpu *vcpu, struct vmcs12 *vmcs12)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);

	if (vmcs12->guest_activity_state != GUEST_ACTIVITY_ACTIVE &&
	    vmcs12->guest_activity_state != GUEST_ACTIVITY_HLT)
		return VMXERR_ENTRY_INVALID_CONTROL_FIELD;

	if (nested_cpu_has_vpid(vmcs12) && !vmcs12->virtual_processor_id)
		return VMXERR_ENTRY_INVALID_CONTROL_FIELD;

	if (nested_vmx_check_io_bitmap_controls(vcpu, vmcs12))
		return VMXERR_ENTRY_INVALID_CONTROL_FIELD;

	if (nested_vmx_check_msr_bitmap_controls(vcpu, vmcs12))
		return VMXERR_ENTRY_INVALID_CONTROL_FIELD;

	if (nested_vmx_check_apic_access_controls(vcpu, vmcs12))
		return VMXERR_ENTRY_INVALID_CONTROL_FIELD;

	if (nested_vmx_check_tpr_shadow_controls(vcpu, vmcs12))
		return VMXERR_ENTRY_INVALID_CONTROL_FIELD;

	if (nested_vmx_check_apicv_controls(vcpu, vmcs12))
		return VMXERR_ENTRY_INVALID_CONTROL_FIELD;

	if (nested_vmx_check_msr_switch_controls(vcpu, vmcs12))
		return VMXERR_ENTRY_INVALID_CONTROL_FIELD;

	if (!nested_cpu_has_preemption_timer(vmcs12) &&
	    nested_cpu_has_save_preemption_timer(vmcs12))
		return VMXERR_ENTRY_INVALID_CONTROL_FIELD;

	if (nested_vmx_check_pml_controls(vcpu, vmcs12))
		return VMXERR_ENTRY_INVALID_CONTROL_FIELD;

	if (nested_vmx_check_shadow_vmcs_controls(vcpu, vmcs12))
		return VMXERR_ENTRY_INVALID_CONTROL_FIELD;

	if (!vmx_control_verify(vmcs12->cpu_based_vm_exec_control,
				vmx->nested.msrs.procbased_ctls_low,
				vmx->nested.msrs.procbased_ctls_high) ||
	    (nested_cpu_has(vmcs12, CPU_BASED_ACTIVATE_SECONDARY_CONTROLS) &&
	     !vmx_control_verify(vmcs12->secondary_vm_exec_control,
				 vmx->nested.msrs.secondary_ctls_low,
				 vmx->nested.msrs.secondary_ctls_high)) ||
	    !vmx_control_verify(vmcs12->pin_based_vm_exec_control,
				vmx->nested.msrs.pinbased_ctls_low,
				vmx->nested.msrs.pinbased_ctls_high) ||
	    !vmx_control_verify(vmcs12->vm_exit_controls,
				vmx->nested.msrs.exit_ctls_low,
				vmx->nested.msrs.exit_ctls_high) ||
	    !vmx_control_verify(vmcs12->vm_entry_controls,
				vmx->nested.msrs.entry_ctls_low,
				vmx->nested.msrs.entry_ctls_high))
		return VMXERR_ENTRY_INVALID_CONTROL_FIELD;

	if (nested_vmx_check_nmi_controls(vmcs12))
		return VMXERR_ENTRY_INVALID_CONTROL_FIELD;

	if (nested_cpu_has_vmfunc(vmcs12)) {
		if (vmcs12->vm_function_control &
		    ~vmx->nested.msrs.vmfunc_controls)
			return VMXERR_ENTRY_INVALID_CONTROL_FIELD;

		if (nested_cpu_has_eptp_switching(vmcs12)) {
			if (!nested_cpu_has_ept(vmcs12) ||
			    !page_address_valid(vcpu, vmcs12->eptp_list_address))
				return VMXERR_ENTRY_INVALID_CONTROL_FIELD;
		}
	}

	if (vmcs12->cr3_target_count > nested_cpu_vmx_misc_cr3_count(vcpu))
		return VMXERR_ENTRY_INVALID_CONTROL_FIELD;

	if (!nested_host_cr0_valid(vcpu, vmcs12->host_cr0) ||
	    !nested_host_cr4_valid(vcpu, vmcs12->host_cr4) ||
	    !nested_cr3_valid(vcpu, vmcs12->host_cr3))
		return VMXERR_ENTRY_INVALID_HOST_STATE_FIELD;

	/*
	 * From the Intel SDM, volume 3:
	 * Fields relevant to VM-entry event injection must be set properly.
	 * These fields are the VM-entry interruption-information field, the
	 * VM-entry exception error code, and the VM-entry instruction length.
	 */
	if (vmcs12->vm_entry_intr_info_field & INTR_INFO_VALID_MASK) {
		u32 intr_info = vmcs12->vm_entry_intr_info_field;
		u8 vector = intr_info & INTR_INFO_VECTOR_MASK;
		u32 intr_type = intr_info & INTR_INFO_INTR_TYPE_MASK;
		bool has_error_code = intr_info & INTR_INFO_DELIVER_CODE_MASK;
		bool should_have_error_code;
		bool urg = nested_cpu_has2(vmcs12,
					   SECONDARY_EXEC_UNRESTRICTED_GUEST);
		bool prot_mode = !urg || vmcs12->guest_cr0 & X86_CR0_PE;

		/* VM-entry interruption-info field: interruption type */
		if (intr_type == INTR_TYPE_RESERVED ||
		    (intr_type == INTR_TYPE_OTHER_EVENT &&
		     !nested_cpu_supports_monitor_trap_flag(vcpu)))
			return VMXERR_ENTRY_INVALID_CONTROL_FIELD;

		/* VM-entry interruption-info field: vector */
		if ((intr_type == INTR_TYPE_NMI_INTR && vector != NMI_VECTOR) ||
		    (intr_type == INTR_TYPE_HARD_EXCEPTION && vector > 31) ||
		    (intr_type == INTR_TYPE_OTHER_EVENT && vector != 0))
			return VMXERR_ENTRY_INVALID_CONTROL_FIELD;

		/* VM-entry interruption-info field: deliver error code */
		should_have_error_code =
			intr_type == INTR_TYPE_HARD_EXCEPTION && prot_mode &&
			x86_exception_has_error_code(vector);
		if (has_error_code != should_have_error_code)
			return VMXERR_ENTRY_INVALID_CONTROL_FIELD;

		/* VM-entry exception error code */
		if (has_error_code &&
		    vmcs12->vm_entry_exception_error_code & GENMASK(31, 16))
			return VMXERR_ENTRY_INVALID_CONTROL_FIELD;

		/* VM-entry interruption-info field: reserved bits */
		if (intr_info & INTR_INFO_RESVD_BITS_MASK)
			return VMXERR_ENTRY_INVALID_CONTROL_FIELD;

		/* VM-entry instruction length */
		switch (intr_type) {
		case INTR_TYPE_SOFT_EXCEPTION:
		case INTR_TYPE_SOFT_INTR:
		case INTR_TYPE_PRIV_SW_EXCEPTION:
			if ((vmcs12->vm_entry_instruction_len > 15) ||
			    (vmcs12->vm_entry_instruction_len == 0 &&
			     !nested_cpu_has_zero_length_injection(vcpu)))
				return VMXERR_ENTRY_INVALID_CONTROL_FIELD;
		}
	}

	return 0;
}

static int nested_vmx_check_vmcs_link_ptr(struct kvm_vcpu *vcpu,
					  struct vmcs12 *vmcs12)
{
	int r;
	struct page *page;
	struct vmcs12 *shadow;

	if (vmcs12->vmcs_link_pointer == -1ull)
		return 0;

	if (!page_address_valid(vcpu, vmcs12->vmcs_link_pointer))
		return -EINVAL;

	page = kvm_vcpu_gpa_to_page(vcpu, vmcs12->vmcs_link_pointer);
	if (is_error_page(page))
		return -EINVAL;

	r = 0;
	shadow = kmap(page);
	if (shadow->hdr.revision_id != VMCS12_REVISION ||
	    shadow->hdr.shadow_vmcs != nested_cpu_has_shadow_vmcs(vmcs12))
		r = -EINVAL;
	kunmap(page);
	kvm_release_page_clean(page);
	return r;
}

static int check_vmentry_postreqs(struct kvm_vcpu *vcpu, struct vmcs12 *vmcs12,
				  u32 *exit_qual)
{
	bool ia32e = !!(vmcs12->vm_entry_controls & VM_ENTRY_IA32E_MODE);

	*exit_qual = ENTRY_FAIL_DEFAULT;

	if (!nested_guest_cr0_valid(vcpu, vmcs12->guest_cr0) ||
	    !nested_guest_cr4_valid(vcpu, vmcs12->guest_cr4))
		return 1;

	if (nested_vmx_check_vmcs_link_ptr(vcpu, vmcs12)) {
		*exit_qual = ENTRY_FAIL_VMCS_LINK_PTR;
		return 1;
	}

	if ((vmcs12->guest_cr0 & (X86_CR0_PG | X86_CR0_PE)) == X86_CR0_PG)
		return 1;

	if ((ia32e && !(vmcs12->guest_cr4 & X86_CR4_PAE)) ||
	    (ia32e && !(vmcs12->guest_cr0 & X86_CR0_PG)))
		return 1;

	/*
	 * If the load IA32_EFER VM-entry control is 1, the following checks
	 * are performed on the field for the IA32_EFER MSR:
	 * - Bits reserved in the IA32_EFER MSR must be 0.
	 * - Bit 10 (corresponding to IA32_EFER.LMA) must equal the value of
	 *   the IA-32e mode guest VM-exit control. It must also be identical
	 *   to bit 8 (LME) if bit 31 in the CR0 field (corresponding to
	 *   CR0.PG) is 1.
	 */
	if (to_vmx(vcpu)->nested.nested_run_pending &&
	    (vmcs12->vm_entry_controls & VM_ENTRY_LOAD_IA32_EFER)) {
		if (!kvm_valid_efer(vcpu, vmcs12->guest_ia32_efer) ||
		    ia32e != !!(vmcs12->guest_ia32_efer & EFER_LMA) ||
		    ((vmcs12->guest_cr0 & X86_CR0_PG) &&
		     ia32e != !!(vmcs12->guest_ia32_efer & EFER_LME)))
			return 1;
	}

	/*
	 * If the load IA32_EFER VM-exit control is 1, bits reserved in the
	 * IA32_EFER MSR must be 0 in the field for that register. In addition,
	 * the values of the LMA and LME bits in the field must each be that of
	 * the host address-space size VM-exit control.
	 */
	if (vmcs12->vm_exit_controls & VM_EXIT_LOAD_IA32_EFER) {
		ia32e = (vmcs12->vm_exit_controls &
			 VM_EXIT_HOST_ADDR_SPACE_SIZE) != 0;
		if (!kvm_valid_efer(vcpu, vmcs12->host_ia32_efer) ||
		    ia32e != !!(vmcs12->host_ia32_efer & EFER_LMA) ||
		    ia32e != !!(vmcs12->host_ia32_efer & EFER_LME))
			return 1;
	}

	if ((vmcs12->vm_entry_controls & VM_ENTRY_LOAD_BNDCFGS) &&
		(is_noncanonical_address(vmcs12->guest_bndcfgs & PAGE_MASK, vcpu) ||
		(vmcs12->guest_bndcfgs & MSR_IA32_BNDCFGS_RSVD)))
			return 1;

	return 0;
}

/*
 * If exit_qual is NULL, this is being called from state restore (either RSM
 * or KVM_SET_NESTED_STATE).  Otherwise it's called from vmlaunch/vmresume.
 */
static int enter_vmx_non_root_mode(struct kvm_vcpu *vcpu, u32 *exit_qual)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	struct vmcs12 *vmcs12 = get_vmcs12(vcpu);
	bool from_vmentry = !!exit_qual;
	u32 dummy_exit_qual;
	bool evaluate_pending_interrupts;
	int r = 0;

	evaluate_pending_interrupts = vmcs_read32(CPU_BASED_VM_EXEC_CONTROL) &
		(CPU_BASED_VIRTUAL_INTR_PENDING | CPU_BASED_VIRTUAL_NMI_PENDING);
	if (likely(!evaluate_pending_interrupts) && kvm_vcpu_apicv_active(vcpu))
		evaluate_pending_interrupts |= vmx_has_apicv_interrupt(vcpu);

	enter_guest_mode(vcpu);

	if (!(vmcs12->vm_entry_controls & VM_ENTRY_LOAD_DEBUG_CONTROLS))
		vmx->nested.vmcs01_debugctl = vmcs_read64(GUEST_IA32_DEBUGCTL);
	if (kvm_mpx_supported() &&
		!(vmcs12->vm_entry_controls & VM_ENTRY_LOAD_BNDCFGS))
		vmx->nested.vmcs01_guest_bndcfgs = vmcs_read64(GUEST_BNDCFGS);

	vmx_switch_vmcs(vcpu, &vmx->nested.vmcs02);
	vmx_segment_cache_clear(vmx);

	if (vmcs12->cpu_based_vm_exec_control & CPU_BASED_USE_TSC_OFFSETING)
		vcpu->arch.tsc_offset += vmcs12->tsc_offset;

	r = EXIT_REASON_INVALID_STATE;
	if (prepare_vmcs02(vcpu, vmcs12, from_vmentry ? exit_qual : &dummy_exit_qual))
		goto fail;

	if (from_vmentry) {
		nested_get_vmcs12_pages(vcpu);

		r = EXIT_REASON_MSR_LOAD_FAIL;
		*exit_qual = nested_vmx_load_msr(vcpu,
	     					 vmcs12->vm_entry_msr_load_addr,
					      	 vmcs12->vm_entry_msr_load_count);
		if (*exit_qual)
			goto fail;
	} else {
		/*
		 * The MMU is not initialized to point at the right entities yet and
		 * "get pages" would need to read data from the guest (i.e. we will
		 * need to perform gpa to hpa translation). Request a call
		 * to nested_get_vmcs12_pages before the next VM-entry.  The MSRs
		 * have already been set at vmentry time and should not be reset.
		 */
		kvm_make_request(KVM_REQ_GET_VMCS12_PAGES, vcpu);
	}

	/*
	 * If L1 had a pending IRQ/NMI until it executed
	 * VMLAUNCH/VMRESUME which wasn't delivered because it was
	 * disallowed (e.g. interrupts disabled), L0 needs to
	 * evaluate if this pending event should cause an exit from L2
	 * to L1 or delivered directly to L2 (e.g. In case L1 don't
	 * intercept EXTERNAL_INTERRUPT).
	 *
	 * Usually this would be handled by the processor noticing an
	 * IRQ/NMI window request, or checking RVI during evaluation of
	 * pending virtual interrupts.  However, this setting was done
	 * on VMCS01 and now VMCS02 is active instead. Thus, we force L0
	 * to perform pending event evaluation by requesting a KVM_REQ_EVENT.
	 */
	if (unlikely(evaluate_pending_interrupts))
		kvm_make_request(KVM_REQ_EVENT, vcpu);

	/*
	 * Note no nested_vmx_succeed or nested_vmx_fail here. At this point
	 * we are no longer running L1, and VMLAUNCH/VMRESUME has not yet
	 * returned as far as L1 is concerned. It will only return (and set
	 * the success flag) when L2 exits (see nested_vmx_vmexit()).
	 */
	return 0;

fail:
	if (vmcs12->cpu_based_vm_exec_control & CPU_BASED_USE_TSC_OFFSETING)
		vcpu->arch.tsc_offset -= vmcs12->tsc_offset;
	leave_guest_mode(vcpu);
	vmx_switch_vmcs(vcpu, &vmx->vmcs01);
	return r;
}

/*
 * nested_vmx_run() handles a nested entry, i.e., a VMLAUNCH or VMRESUME on L1
 * for running an L2 nested guest.
 */
static int nested_vmx_run(struct kvm_vcpu *vcpu, bool launch)
{
	struct vmcs12 *vmcs12;
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	u32 interrupt_shadow = vmx_get_interrupt_shadow(vcpu);
	u32 exit_qual;
	int ret;

	if (!nested_vmx_check_permission(vcpu))
		return 1;

	if (!nested_vmx_check_vmcs12(vcpu))
		goto out;

	vmcs12 = get_vmcs12(vcpu);

	/*
	 * Can't VMLAUNCH or VMRESUME a shadow VMCS. Despite the fact
	 * that there *is* a valid VMCS pointer, RFLAGS.CF is set
	 * rather than RFLAGS.ZF, and no error number is stored to the
	 * VM-instruction error field.
	 */
	if (vmcs12->hdr.shadow_vmcs) {
		nested_vmx_failInvalid(vcpu);
		goto out;
	}

	if (enable_shadow_vmcs)
		copy_shadow_to_vmcs12(vmx);

	/*
	 * The nested entry process starts with enforcing various prerequisites
	 * on vmcs12 as required by the Intel SDM, and act appropriately when
	 * they fail: As the SDM explains, some conditions should cause the
	 * instruction to fail, while others will cause the instruction to seem
	 * to succeed, but return an EXIT_REASON_INVALID_STATE.
	 * To speed up the normal (success) code path, we should avoid checking
	 * for misconfigurations which will anyway be caught by the processor
	 * when using the merged vmcs02.
	 */
	if (interrupt_shadow & KVM_X86_SHADOW_INT_MOV_SS) {
		nested_vmx_failValid(vcpu,
				     VMXERR_ENTRY_EVENTS_BLOCKED_BY_MOV_SS);
		goto out;
	}

	if (vmcs12->launch_state == launch) {
		nested_vmx_failValid(vcpu,
			launch ? VMXERR_VMLAUNCH_NONCLEAR_VMCS
			       : VMXERR_VMRESUME_NONLAUNCHED_VMCS);
		goto out;
	}

	ret = check_vmentry_prereqs(vcpu, vmcs12);
	if (ret) {
		nested_vmx_failValid(vcpu, ret);
		goto out;
	}

	/*
	 * After this point, the trap flag no longer triggers a singlestep trap
	 * on the vm entry instructions; don't call kvm_skip_emulated_instruction.
	 * This is not 100% correct; for performance reasons, we delegate most
	 * of the checks on host state to the processor.  If those fail,
	 * the singlestep trap is missed.
	 */
	skip_emulated_instruction(vcpu);

	ret = check_vmentry_postreqs(vcpu, vmcs12, &exit_qual);
	if (ret) {
		nested_vmx_entry_failure(vcpu, vmcs12,
					 EXIT_REASON_INVALID_STATE, exit_qual);
		return 1;
	}

	/*
	 * We're finally done with prerequisite checking, and can start with
	 * the nested entry.
	 */

	vmx->nested.nested_run_pending = 1;
	ret = enter_vmx_non_root_mode(vcpu, &exit_qual);
	if (ret) {
		nested_vmx_entry_failure(vcpu, vmcs12, ret, exit_qual);
		vmx->nested.nested_run_pending = 0;
		return 1;
	}

	/* Hide L1D cache contents from the nested guest.  */
	vmx->vcpu.arch.l1tf_flush_l1d = true;

	/*
	 * Must happen outside of enter_vmx_non_root_mode() as it will
	 * also be used as part of restoring nVMX state for
	 * snapshot restore (migration).
	 *
	 * In this flow, it is assumed that vmcs12 cache was
	 * trasferred as part of captured nVMX state and should
	 * therefore not be read from guest memory (which may not
	 * exist on destination host yet).
	 */
	nested_cache_shadow_vmcs12(vcpu, vmcs12);

	/*
	 * If we're entering a halted L2 vcpu and the L2 vcpu won't be
	 * awakened by event injection or by an NMI-window VM-exit or
	 * by an interrupt-window VM-exit, halt the vcpu.
	 */
	if ((vmcs12->guest_activity_state == GUEST_ACTIVITY_HLT) &&
	    !(vmcs12->vm_entry_intr_info_field & INTR_INFO_VALID_MASK) &&
	    !(vmcs12->cpu_based_vm_exec_control & CPU_BASED_VIRTUAL_NMI_PENDING) &&
	    !((vmcs12->cpu_based_vm_exec_control & CPU_BASED_VIRTUAL_INTR_PENDING) &&
	      (vmcs12->guest_rflags & X86_EFLAGS_IF))) {
		vmx->nested.nested_run_pending = 0;
		return kvm_vcpu_halt(vcpu);
	}
	return 1;

out:
	return kvm_skip_emulated_instruction(vcpu);
}

/*
 * On a nested exit from L2 to L1, vmcs12.guest_cr0 might not be up-to-date
 * because L2 may have changed some cr0 bits directly (CRO_GUEST_HOST_MASK).
 * This function returns the new value we should put in vmcs12.guest_cr0.
 * It's not enough to just return the vmcs02 GUEST_CR0. Rather,
 *  1. Bits that neither L0 nor L1 trapped, were set directly by L2 and are now
 *     available in vmcs02 GUEST_CR0. (Note: It's enough to check that L0
 *     didn't trap the bit, because if L1 did, so would L0).
 *  2. Bits that L1 asked to trap (and therefore L0 also did) could not have
 *     been modified by L2, and L1 knows it. So just leave the old value of
 *     the bit from vmcs12.guest_cr0. Note that the bit from vmcs02 GUEST_CR0
 *     isn't relevant, because if L0 traps this bit it can set it to anything.
 *  3. Bits that L1 didn't trap, but L0 did. L1 believes the guest could have
 *     changed these bits, and therefore they need to be updated, but L0
 *     didn't necessarily allow them to be changed in GUEST_CR0 - and rather
 *     put them in vmcs02 CR0_READ_SHADOW. So take these bits from there.
 */
static inline unsigned long
vmcs12_guest_cr0(struct kvm_vcpu *vcpu, struct vmcs12 *vmcs12)
{
	return
	/*1*/	(vmcs_readl(GUEST_CR0) & vcpu->arch.cr0_guest_owned_bits) |
	/*2*/	(vmcs12->guest_cr0 & vmcs12->cr0_guest_host_mask) |
	/*3*/	(vmcs_readl(CR0_READ_SHADOW) & ~(vmcs12->cr0_guest_host_mask |
			vcpu->arch.cr0_guest_owned_bits));
}

static inline unsigned long
vmcs12_guest_cr4(struct kvm_vcpu *vcpu, struct vmcs12 *vmcs12)
{
	return
	/*1*/	(vmcs_readl(GUEST_CR4) & vcpu->arch.cr4_guest_owned_bits) |
	/*2*/	(vmcs12->guest_cr4 & vmcs12->cr4_guest_host_mask) |
	/*3*/	(vmcs_readl(CR4_READ_SHADOW) & ~(vmcs12->cr4_guest_host_mask |
			vcpu->arch.cr4_guest_owned_bits));
}

static void vmcs12_save_pending_event(struct kvm_vcpu *vcpu,
				       struct vmcs12 *vmcs12)
{
	u32 idt_vectoring;
	unsigned int nr;

	if (vcpu->arch.exception.injected) {
		nr = vcpu->arch.exception.nr;
		idt_vectoring = nr | VECTORING_INFO_VALID_MASK;

		if (kvm_exception_is_soft(nr)) {
			vmcs12->vm_exit_instruction_len =
				vcpu->arch.event_exit_inst_len;
			idt_vectoring |= INTR_TYPE_SOFT_EXCEPTION;
		} else
			idt_vectoring |= INTR_TYPE_HARD_EXCEPTION;

		if (vcpu->arch.exception.has_error_code) {
			idt_vectoring |= VECTORING_INFO_DELIVER_CODE_MASK;
			vmcs12->idt_vectoring_error_code =
				vcpu->arch.exception.error_code;
		}

		vmcs12->idt_vectoring_info_field = idt_vectoring;
	} else if (vcpu->arch.nmi_injected) {
		vmcs12->idt_vectoring_info_field =
			INTR_TYPE_NMI_INTR | INTR_INFO_VALID_MASK | NMI_VECTOR;
	} else if (vcpu->arch.interrupt.injected) {
		nr = vcpu->arch.interrupt.nr;
		idt_vectoring = nr | VECTORING_INFO_VALID_MASK;

		if (vcpu->arch.interrupt.soft) {
			idt_vectoring |= INTR_TYPE_SOFT_INTR;
			vmcs12->vm_entry_instruction_len =
				vcpu->arch.event_exit_inst_len;
		} else
			idt_vectoring |= INTR_TYPE_EXT_INTR;

		vmcs12->idt_vectoring_info_field = idt_vectoring;
	}
}

static int vmx_check_nested_events(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	unsigned long exit_qual;
	bool block_nested_events =
	    vmx->nested.nested_run_pending || kvm_event_needs_reinjection(vcpu);

	if (vcpu->arch.exception.pending &&
		nested_vmx_check_exception(vcpu, &exit_qual)) {
		if (block_nested_events)
			return -EBUSY;
		nested_vmx_inject_exception_vmexit(vcpu, exit_qual);
		return 0;
	}

	if (nested_cpu_has_preemption_timer(get_vmcs12(vcpu)) &&
	    vmx->nested.preemption_timer_expired) {
		if (block_nested_events)
			return -EBUSY;
		nested_vmx_vmexit(vcpu, EXIT_REASON_PREEMPTION_TIMER, 0, 0);
		return 0;
	}

	if (vcpu->arch.nmi_pending && nested_exit_on_nmi(vcpu)) {
		if (block_nested_events)
			return -EBUSY;
		nested_vmx_vmexit(vcpu, EXIT_REASON_EXCEPTION_NMI,
				  NMI_VECTOR | INTR_TYPE_NMI_INTR |
				  INTR_INFO_VALID_MASK, 0);
		/*
		 * The NMI-triggered VM exit counts as injection:
		 * clear this one and block further NMIs.
		 */
		vcpu->arch.nmi_pending = 0;
		vmx_set_nmi_mask(vcpu, true);
		return 0;
	}

	if (kvm_cpu_has_interrupt(vcpu) && nested_exit_on_intr(vcpu)) {
		if (block_nested_events)
			return -EBUSY;
		nested_vmx_vmexit(vcpu, EXIT_REASON_EXTERNAL_INTERRUPT, 0, 0);
		return 0;
	}

	vmx_complete_nested_posted_interrupt(vcpu);
	return 0;
}

static void vmx_request_immediate_exit(struct kvm_vcpu *vcpu)
{
	to_vmx(vcpu)->req_immediate_exit = true;
}

static u32 vmx_get_preemption_timer_value(struct kvm_vcpu *vcpu)
{
	ktime_t remaining =
		hrtimer_get_remaining(&to_vmx(vcpu)->nested.preemption_timer);
	u64 value;

	if (ktime_to_ns(remaining) <= 0)
		return 0;

	value = ktime_to_ns(remaining) * vcpu->arch.virtual_tsc_khz;
	do_div(value, 1000000);
	return value >> VMX_MISC_EMULATED_PREEMPTION_TIMER_RATE;
}

/*
 * Update the guest state fields of vmcs12 to reflect changes that
 * occurred while L2 was running. (The "IA-32e mode guest" bit of the
 * VM-entry controls is also updated, since this is really a guest
 * state bit.)
 */
static void sync_vmcs12(struct kvm_vcpu *vcpu, struct vmcs12 *vmcs12)
{
	vmcs12->guest_cr0 = vmcs12_guest_cr0(vcpu, vmcs12);
	vmcs12->guest_cr4 = vmcs12_guest_cr4(vcpu, vmcs12);

	vmcs12->guest_rsp = kvm_register_read(vcpu, VCPU_REGS_RSP);
	vmcs12->guest_rip = kvm_register_read(vcpu, VCPU_REGS_RIP);
	vmcs12->guest_rflags = vmcs_readl(GUEST_RFLAGS);

	vmcs12->guest_es_selector = vmcs_read16(GUEST_ES_SELECTOR);
	vmcs12->guest_cs_selector = vmcs_read16(GUEST_CS_SELECTOR);
	vmcs12->guest_ss_selector = vmcs_read16(GUEST_SS_SELECTOR);
	vmcs12->guest_ds_selector = vmcs_read16(GUEST_DS_SELECTOR);
	vmcs12->guest_fs_selector = vmcs_read16(GUEST_FS_SELECTOR);
	vmcs12->guest_gs_selector = vmcs_read16(GUEST_GS_SELECTOR);
	vmcs12->guest_ldtr_selector = vmcs_read16(GUEST_LDTR_SELECTOR);
	vmcs12->guest_tr_selector = vmcs_read16(GUEST_TR_SELECTOR);
	vmcs12->guest_es_limit = vmcs_read32(GUEST_ES_LIMIT);
	vmcs12->guest_cs_limit = vmcs_read32(GUEST_CS_LIMIT);
	vmcs12->guest_ss_limit = vmcs_read32(GUEST_SS_LIMIT);
	vmcs12->guest_ds_limit = vmcs_read32(GUEST_DS_LIMIT);
	vmcs12->guest_fs_limit = vmcs_read32(GUEST_FS_LIMIT);
	vmcs12->guest_gs_limit = vmcs_read32(GUEST_GS_LIMIT);
	vmcs12->guest_ldtr_limit = vmcs_read32(GUEST_LDTR_LIMIT);
	vmcs12->guest_tr_limit = vmcs_read32(GUEST_TR_LIMIT);
	vmcs12->guest_gdtr_limit = vmcs_read32(GUEST_GDTR_LIMIT);
	vmcs12->guest_idtr_limit = vmcs_read32(GUEST_IDTR_LIMIT);
	vmcs12->guest_es_ar_bytes = vmcs_read32(GUEST_ES_AR_BYTES);
	vmcs12->guest_cs_ar_bytes = vmcs_read32(GUEST_CS_AR_BYTES);
	vmcs12->guest_ss_ar_bytes = vmcs_read32(GUEST_SS_AR_BYTES);
	vmcs12->guest_ds_ar_bytes = vmcs_read32(GUEST_DS_AR_BYTES);
	vmcs12->guest_fs_ar_bytes = vmcs_read32(GUEST_FS_AR_BYTES);
	vmcs12->guest_gs_ar_bytes = vmcs_read32(GUEST_GS_AR_BYTES);
	vmcs12->guest_ldtr_ar_bytes = vmcs_read32(GUEST_LDTR_AR_BYTES);
	vmcs12->guest_tr_ar_bytes = vmcs_read32(GUEST_TR_AR_BYTES);
	vmcs12->guest_es_base = vmcs_readl(GUEST_ES_BASE);
	vmcs12->guest_cs_base = vmcs_readl(GUEST_CS_BASE);
	vmcs12->guest_ss_base = vmcs_readl(GUEST_SS_BASE);
	vmcs12->guest_ds_base = vmcs_readl(GUEST_DS_BASE);
	vmcs12->guest_fs_base = vmcs_readl(GUEST_FS_BASE);
	vmcs12->guest_gs_base = vmcs_readl(GUEST_GS_BASE);
	vmcs12->guest_ldtr_base = vmcs_readl(GUEST_LDTR_BASE);
	vmcs12->guest_tr_base = vmcs_readl(GUEST_TR_BASE);
	vmcs12->guest_gdtr_base = vmcs_readl(GUEST_GDTR_BASE);
	vmcs12->guest_idtr_base = vmcs_readl(GUEST_IDTR_BASE);

	vmcs12->guest_interruptibility_info =
		vmcs_read32(GUEST_INTERRUPTIBILITY_INFO);
	vmcs12->guest_pending_dbg_exceptions =
		vmcs_readl(GUEST_PENDING_DBG_EXCEPTIONS);
	if (vcpu->arch.mp_state == KVM_MP_STATE_HALTED)
		vmcs12->guest_activity_state = GUEST_ACTIVITY_HLT;
	else
		vmcs12->guest_activity_state = GUEST_ACTIVITY_ACTIVE;

	if (nested_cpu_has_preemption_timer(vmcs12)) {
		if (vmcs12->vm_exit_controls &
		    VM_EXIT_SAVE_VMX_PREEMPTION_TIMER)
			vmcs12->vmx_preemption_timer_value =
				vmx_get_preemption_timer_value(vcpu);
		hrtimer_cancel(&to_vmx(vcpu)->nested.preemption_timer);
	}

	/*
	 * In some cases (usually, nested EPT), L2 is allowed to change its
	 * own CR3 without exiting. If it has changed it, we must keep it.
	 * Of course, if L0 is using shadow page tables, GUEST_CR3 was defined
	 * by L0, not L1 or L2, so we mustn't unconditionally copy it to vmcs12.
	 *
	 * Additionally, restore L2's PDPTR to vmcs12.
	 */
	if (enable_ept) {
		vmcs12->guest_cr3 = vmcs_readl(GUEST_CR3);
		vmcs12->guest_pdptr0 = vmcs_read64(GUEST_PDPTR0);
		vmcs12->guest_pdptr1 = vmcs_read64(GUEST_PDPTR1);
		vmcs12->guest_pdptr2 = vmcs_read64(GUEST_PDPTR2);
		vmcs12->guest_pdptr3 = vmcs_read64(GUEST_PDPTR3);
	}

	vmcs12->guest_linear_address = vmcs_readl(GUEST_LINEAR_ADDRESS);

	if (nested_cpu_has_vid(vmcs12))
		vmcs12->guest_intr_status = vmcs_read16(GUEST_INTR_STATUS);

	vmcs12->vm_entry_controls =
		(vmcs12->vm_entry_controls & ~VM_ENTRY_IA32E_MODE) |
		(vm_entry_controls_get(to_vmx(vcpu)) & VM_ENTRY_IA32E_MODE);

	if (vmcs12->vm_exit_controls & VM_EXIT_SAVE_DEBUG_CONTROLS) {
		kvm_get_dr(vcpu, 7, (unsigned long *)&vmcs12->guest_dr7);
		vmcs12->guest_ia32_debugctl = vmcs_read64(GUEST_IA32_DEBUGCTL);
	}

	/* TODO: These cannot have changed unless we have MSR bitmaps and
	 * the relevant bit asks not to trap the change */
	if (vmcs12->vm_exit_controls & VM_EXIT_SAVE_IA32_PAT)
		vmcs12->guest_ia32_pat = vmcs_read64(GUEST_IA32_PAT);
	if (vmcs12->vm_exit_controls & VM_EXIT_SAVE_IA32_EFER)
		vmcs12->guest_ia32_efer = vcpu->arch.efer;
	vmcs12->guest_sysenter_cs = vmcs_read32(GUEST_SYSENTER_CS);
	vmcs12->guest_sysenter_esp = vmcs_readl(GUEST_SYSENTER_ESP);
	vmcs12->guest_sysenter_eip = vmcs_readl(GUEST_SYSENTER_EIP);
	if (kvm_mpx_supported())
		vmcs12->guest_bndcfgs = vmcs_read64(GUEST_BNDCFGS);
}

/*
 * prepare_vmcs12 is part of what we need to do when the nested L2 guest exits
 * and we want to prepare to run its L1 parent. L1 keeps a vmcs for L2 (vmcs12),
 * and this function updates it to reflect the changes to the guest state while
 * L2 was running (and perhaps made some exits which were handled directly by L0
 * without going back to L1), and to reflect the exit reason.
 * Note that we do not have to copy here all VMCS fields, just those that
 * could have changed by the L2 guest or the exit - i.e., the guest-state and
 * exit-information fields only. Other fields are modified by L1 with VMWRITE,
 * which already writes to vmcs12 directly.
 */
static void prepare_vmcs12(struct kvm_vcpu *vcpu, struct vmcs12 *vmcs12,
			   u32 exit_reason, u32 exit_intr_info,
			   unsigned long exit_qualification)
{
	/* update guest state fields: */
	sync_vmcs12(vcpu, vmcs12);

	/* update exit information fields: */

	vmcs12->vm_exit_reason = exit_reason;
	vmcs12->exit_qualification = exit_qualification;
	vmcs12->vm_exit_intr_info = exit_intr_info;

	vmcs12->idt_vectoring_info_field = 0;
	vmcs12->vm_exit_instruction_len = vmcs_read32(VM_EXIT_INSTRUCTION_LEN);
	vmcs12->vmx_instruction_info = vmcs_read32(VMX_INSTRUCTION_INFO);

	if (!(vmcs12->vm_exit_reason & VMX_EXIT_REASONS_FAILED_VMENTRY)) {
		vmcs12->launch_state = 1;

		/* vm_entry_intr_info_field is cleared on exit. Emulate this
		 * instead of reading the real value. */
		vmcs12->vm_entry_intr_info_field &= ~INTR_INFO_VALID_MASK;

		/*
		 * Transfer the event that L0 or L1 may wanted to inject into
		 * L2 to IDT_VECTORING_INFO_FIELD.
		 */
		vmcs12_save_pending_event(vcpu, vmcs12);
	}
}

/*
 * A part of what we need to when the nested L2 guest exits and we want to
 * run its L1 parent, is to reset L1's guest state to the host state specified
 * in vmcs12.
 * This function is to be called not only on normal nested exit, but also on
 * a nested entry failure, as explained in Intel's spec, 3B.23.7 ("VM-Entry
 * Failures During or After Loading Guest State").
 * This function should be called when the active VMCS is L1's (vmcs01).
 */
static void load_vmcs12_host_state(struct kvm_vcpu *vcpu,
				   struct vmcs12 *vmcs12)
{
	struct kvm_segment seg;
	u32 entry_failure_code;

	if (vmcs12->vm_exit_controls & VM_EXIT_LOAD_IA32_EFER)
		vcpu->arch.efer = vmcs12->host_ia32_efer;
	else if (vmcs12->vm_exit_controls & VM_EXIT_HOST_ADDR_SPACE_SIZE)
		vcpu->arch.efer |= (EFER_LMA | EFER_LME);
	else
		vcpu->arch.efer &= ~(EFER_LMA | EFER_LME);
	vmx_set_efer(vcpu, vcpu->arch.efer);

	kvm_register_write(vcpu, VCPU_REGS_RSP, vmcs12->host_rsp);
	kvm_register_write(vcpu, VCPU_REGS_RIP, vmcs12->host_rip);
	vmx_set_rflags(vcpu, X86_EFLAGS_FIXED);
	/*
	 * Note that calling vmx_set_cr0 is important, even if cr0 hasn't
	 * actually changed, because vmx_set_cr0 refers to efer set above.
	 *
	 * CR0_GUEST_HOST_MASK is already set in the original vmcs01
	 * (KVM doesn't change it);
	 */
	vcpu->arch.cr0_guest_owned_bits = X86_CR0_TS;
	vmx_set_cr0(vcpu, vmcs12->host_cr0);

	/* Same as above - no reason to call set_cr4_guest_host_mask().  */
	vcpu->arch.cr4_guest_owned_bits = ~vmcs_readl(CR4_GUEST_HOST_MASK);
	vmx_set_cr4(vcpu, vmcs12->host_cr4);

	nested_ept_uninit_mmu_context(vcpu);

	/*
	 * Only PDPTE load can fail as the value of cr3 was checked on entry and
	 * couldn't have changed.
	 */
	if (nested_vmx_load_cr3(vcpu, vmcs12->host_cr3, false, &entry_failure_code))
		nested_vmx_abort(vcpu, VMX_ABORT_LOAD_HOST_PDPTE_FAIL);

	if (!enable_ept)
		vcpu->arch.walk_mmu->inject_page_fault = kvm_inject_page_fault;

	/*
	 * If vmcs01 don't use VPID, CPU flushes TLB on every
	 * VMEntry/VMExit. Thus, no need to flush TLB.
	 *
	 * If vmcs12 uses VPID, TLB entries populated by L2 are
	 * tagged with vmx->nested.vpid02 while L1 entries are tagged
	 * with vmx->vpid. Thus, no need to flush TLB.
	 *
	 * Therefore, flush TLB only in case vmcs01 uses VPID and
	 * vmcs12 don't use VPID as in this case L1 & L2 TLB entries
	 * are both tagged with vmx->vpid.
	 */
	if (enable_vpid &&
	    !(nested_cpu_has_vpid(vmcs12) && to_vmx(vcpu)->nested.vpid02)) {
		vmx_flush_tlb(vcpu, true);
	}

	vmcs_write32(GUEST_SYSENTER_CS, vmcs12->host_ia32_sysenter_cs);
	vmcs_writel(GUEST_SYSENTER_ESP, vmcs12->host_ia32_sysenter_esp);
	vmcs_writel(GUEST_SYSENTER_EIP, vmcs12->host_ia32_sysenter_eip);
	vmcs_writel(GUEST_IDTR_BASE, vmcs12->host_idtr_base);
	vmcs_writel(GUEST_GDTR_BASE, vmcs12->host_gdtr_base);
	vmcs_write32(GUEST_IDTR_LIMIT, 0xFFFF);
	vmcs_write32(GUEST_GDTR_LIMIT, 0xFFFF);

	/* If not VM_EXIT_CLEAR_BNDCFGS, the L2 value propagates to L1.  */
	if (vmcs12->vm_exit_controls & VM_EXIT_CLEAR_BNDCFGS)
		vmcs_write64(GUEST_BNDCFGS, 0);

	if (vmcs12->vm_exit_controls & VM_EXIT_LOAD_IA32_PAT) {
		vmcs_write64(GUEST_IA32_PAT, vmcs12->host_ia32_pat);
		vcpu->arch.pat = vmcs12->host_ia32_pat;
	}
	if (vmcs12->vm_exit_controls & VM_EXIT_LOAD_IA32_PERF_GLOBAL_CTRL)
		vmcs_write64(GUEST_IA32_PERF_GLOBAL_CTRL,
			vmcs12->host_ia32_perf_global_ctrl);

	/* Set L1 segment info according to Intel SDM
	    27.5.2 Loading Host Segment and Descriptor-Table Registers */
	seg = (struct kvm_segment) {
		.base = 0,
		.limit = 0xFFFFFFFF,
		.selector = vmcs12->host_cs_selector,
		.type = 11,
		.present = 1,
		.s = 1,
		.g = 1
	};
	if (vmcs12->vm_exit_controls & VM_EXIT_HOST_ADDR_SPACE_SIZE)
		seg.l = 1;
	else
		seg.db = 1;
	vmx_set_segment(vcpu, &seg, VCPU_SREG_CS);
	seg = (struct kvm_segment) {
		.base = 0,
		.limit = 0xFFFFFFFF,
		.type = 3,
		.present = 1,
		.s = 1,
		.db = 1,
		.g = 1
	};
	seg.selector = vmcs12->host_ds_selector;
	vmx_set_segment(vcpu, &seg, VCPU_SREG_DS);
	seg.selector = vmcs12->host_es_selector;
	vmx_set_segment(vcpu, &seg, VCPU_SREG_ES);
	seg.selector = vmcs12->host_ss_selector;
	vmx_set_segment(vcpu, &seg, VCPU_SREG_SS);
	seg.selector = vmcs12->host_fs_selector;
	seg.base = vmcs12->host_fs_base;
	vmx_set_segment(vcpu, &seg, VCPU_SREG_FS);
	seg.selector = vmcs12->host_gs_selector;
	seg.base = vmcs12->host_gs_base;
	vmx_set_segment(vcpu, &seg, VCPU_SREG_GS);
	seg = (struct kvm_segment) {
		.base = vmcs12->host_tr_base,
		.limit = 0x67,
		.selector = vmcs12->host_tr_selector,
		.type = 11,
		.present = 1
	};
	vmx_set_segment(vcpu, &seg, VCPU_SREG_TR);

	kvm_set_dr(vcpu, 7, 0x400);
	vmcs_write64(GUEST_IA32_DEBUGCTL, 0);

	if (cpu_has_vmx_msr_bitmap())
		vmx_update_msr_bitmap(vcpu);

	if (nested_vmx_load_msr(vcpu, vmcs12->vm_exit_msr_load_addr,
				vmcs12->vm_exit_msr_load_count))
		nested_vmx_abort(vcpu, VMX_ABORT_LOAD_HOST_MSR_FAIL);
}

static inline u64 nested_vmx_get_vmcs01_guest_efer(struct vcpu_vmx *vmx)
{
	struct shared_msr_entry *efer_msr;
	unsigned int i;

	if (vm_entry_controls_get(vmx) & VM_ENTRY_LOAD_IA32_EFER)
		return vmcs_read64(GUEST_IA32_EFER);

	if (cpu_has_load_ia32_efer)
		return host_efer;

	for (i = 0; i < vmx->msr_autoload.guest.nr; ++i) {
		if (vmx->msr_autoload.guest.val[i].index == MSR_EFER)
			return vmx->msr_autoload.guest.val[i].value;
	}

	efer_msr = find_msr_entry(vmx, MSR_EFER);
	if (efer_msr)
		return efer_msr->data;

	return host_efer;
}

static void nested_vmx_restore_host_state(struct kvm_vcpu *vcpu)
{
	struct vmcs12 *vmcs12 = get_vmcs12(vcpu);
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	struct vmx_msr_entry g, h;
	struct msr_data msr;
	gpa_t gpa;
	u32 i, j;

	vcpu->arch.pat = vmcs_read64(GUEST_IA32_PAT);

	if (vmcs12->vm_entry_controls & VM_ENTRY_LOAD_DEBUG_CONTROLS) {
		/*
		 * L1's host DR7 is lost if KVM_GUESTDBG_USE_HW_BP is set
		 * as vmcs01.GUEST_DR7 contains a userspace defined value
		 * and vcpu->arch.dr7 is not squirreled away before the
		 * nested VMENTER (not worth adding a variable in nested_vmx).
		 */
		if (vcpu->guest_debug & KVM_GUESTDBG_USE_HW_BP)
			kvm_set_dr(vcpu, 7, DR7_FIXED_1);
		else
			WARN_ON(kvm_set_dr(vcpu, 7, vmcs_readl(GUEST_DR7)));
	}

	/*
	 * Note that calling vmx_set_{efer,cr0,cr4} is important as they
	 * handle a variety of side effects to KVM's software model.
	 */
	vmx_set_efer(vcpu, nested_vmx_get_vmcs01_guest_efer(vmx));

	vcpu->arch.cr0_guest_owned_bits = X86_CR0_TS;
	vmx_set_cr0(vcpu, vmcs_readl(CR0_READ_SHADOW));

	vcpu->arch.cr4_guest_owned_bits = ~vmcs_readl(CR4_GUEST_HOST_MASK);
	vmx_set_cr4(vcpu, vmcs_readl(CR4_READ_SHADOW));

	nested_ept_uninit_mmu_context(vcpu);
	vcpu->arch.cr3 = vmcs_readl(GUEST_CR3);
	__set_bit(VCPU_EXREG_CR3, (ulong *)&vcpu->arch.regs_avail);

	/*
	 * Use ept_save_pdptrs(vcpu) to load the MMU's cached PDPTRs
	 * from vmcs01 (if necessary).  The PDPTRs are not loaded on
	 * VMFail, like everything else we just need to ensure our
	 * software model is up-to-date.
	 */
	ept_save_pdptrs(vcpu);

	kvm_mmu_reset_context(vcpu);

	if (cpu_has_vmx_msr_bitmap())
		vmx_update_msr_bitmap(vcpu);

	/*
	 * This nasty bit of open coding is a compromise between blindly
	 * loading L1's MSRs using the exit load lists (incorrect emulation
	 * of VMFail), leaving the nested VM's MSRs in the software model
	 * (incorrect behavior) and snapshotting the modified MSRs (too
	 * expensive since the lists are unbound by hardware).  For each
	 * MSR that was (prematurely) loaded from the nested VMEntry load
	 * list, reload it from the exit load list if it exists and differs
	 * from the guest value.  The intent is to stuff host state as
	 * silently as possible, not to fully process the exit load list.
	 */
	msr.host_initiated = false;
	for (i = 0; i < vmcs12->vm_entry_msr_load_count; i++) {
		gpa = vmcs12->vm_entry_msr_load_addr + (i * sizeof(g));
		if (kvm_vcpu_read_guest(vcpu, gpa, &g, sizeof(g))) {
			pr_debug_ratelimited(
				"%s read MSR index failed (%u, 0x%08llx)\n",
				__func__, i, gpa);
			goto vmabort;
		}

		for (j = 0; j < vmcs12->vm_exit_msr_load_count; j++) {
			gpa = vmcs12->vm_exit_msr_load_addr + (j * sizeof(h));
			if (kvm_vcpu_read_guest(vcpu, gpa, &h, sizeof(h))) {
				pr_debug_ratelimited(
					"%s read MSR failed (%u, 0x%08llx)\n",
					__func__, j, gpa);
				goto vmabort;
			}
			if (h.index != g.index)
				continue;
			if (h.value == g.value)
				break;

			if (nested_vmx_load_msr_check(vcpu, &h)) {
				pr_debug_ratelimited(
					"%s check failed (%u, 0x%x, 0x%x)\n",
					__func__, j, h.index, h.reserved);
				goto vmabort;
			}

			msr.index = h.index;
			msr.data = h.value;
			if (kvm_set_msr(vcpu, &msr)) {
				pr_debug_ratelimited(
					"%s WRMSR failed (%u, 0x%x, 0x%llx)\n",
					__func__, j, h.index, h.value);
				goto vmabort;
			}
		}
	}

	return;

vmabort:
	nested_vmx_abort(vcpu, VMX_ABORT_LOAD_HOST_MSR_FAIL);
}

/*
 * Emulate an exit from nested guest (L2) to L1, i.e., prepare to run L1
 * and modify vmcs12 to make it see what it would expect to see there if
 * L2 was its real guest. Must only be called when in L2 (is_guest_mode())
 */
static void nested_vmx_vmexit(struct kvm_vcpu *vcpu, u32 exit_reason,
			      u32 exit_intr_info,
			      unsigned long exit_qualification)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	struct vmcs12 *vmcs12 = get_vmcs12(vcpu);

	/* trying to cancel vmlaunch/vmresume is a bug */
	WARN_ON_ONCE(vmx->nested.nested_run_pending);

	/*
	 * The only expected VM-instruction error is "VM entry with
	 * invalid control field(s)." Anything else indicates a
	 * problem with L0.
	 */
	WARN_ON_ONCE(vmx->fail && (vmcs_read32(VM_INSTRUCTION_ERROR) !=
				   VMXERR_ENTRY_INVALID_CONTROL_FIELD));

	leave_guest_mode(vcpu);

	if (vmcs12->cpu_based_vm_exec_control & CPU_BASED_USE_TSC_OFFSETING)
		vcpu->arch.tsc_offset -= vmcs12->tsc_offset;

	if (likely(!vmx->fail)) {
		if (exit_reason == -1)
			sync_vmcs12(vcpu, vmcs12);
		else
			prepare_vmcs12(vcpu, vmcs12, exit_reason, exit_intr_info,
				       exit_qualification);

		/*
		 * Must happen outside of sync_vmcs12() as it will
		 * also be used to capture vmcs12 cache as part of
		 * capturing nVMX state for snapshot (migration).
		 *
		 * Otherwise, this flush will dirty guest memory at a
		 * point it is already assumed by user-space to be
		 * immutable.
		 */
		nested_flush_cached_shadow_vmcs12(vcpu, vmcs12);

		if (nested_vmx_store_msr(vcpu, vmcs12->vm_exit_msr_store_addr,
					 vmcs12->vm_exit_msr_store_count))
			nested_vmx_abort(vcpu, VMX_ABORT_SAVE_GUEST_MSR_FAIL);
	}

	/*
	 * Drop events/exceptions that were queued for re-injection to L2
	 * (picked up via vmx_complete_interrupts()), as well as exceptions
	 * that were pending for L2.  Note, this must NOT be hoisted above
	 * prepare_vmcs12(), events/exceptions queued for re-injection need to
	 * be captured in vmcs12 (see vmcs12_save_pending_event()).
	 */
	vcpu->arch.nmi_injected = false;
	kvm_clear_exception_queue(vcpu);
	kvm_clear_interrupt_queue(vcpu);

	vmx_switch_vmcs(vcpu, &vmx->vmcs01);
	vm_entry_controls_reset_shadow(vmx);
	vm_exit_controls_reset_shadow(vmx);
	vmx_segment_cache_clear(vmx);

	/* Update any VMCS fields that might have changed while L2 ran */
	vmcs_write32(VM_EXIT_MSR_LOAD_COUNT, vmx->msr_autoload.host.nr);
	vmcs_write32(VM_ENTRY_MSR_LOAD_COUNT, vmx->msr_autoload.guest.nr);
	vmcs_write64(TSC_OFFSET, vcpu->arch.tsc_offset);

	if (kvm_has_tsc_control)
		decache_tsc_multiplier(vmx);

	if (vmx->nested.change_vmcs01_virtual_apic_mode) {
		vmx->nested.change_vmcs01_virtual_apic_mode = false;
		vmx_set_virtual_apic_mode(vcpu);
	} else if (!nested_cpu_has_ept(vmcs12) &&
		   nested_cpu_has2(vmcs12,
				   SECONDARY_EXEC_VIRTUALIZE_APIC_ACCESSES)) {
		vmx_flush_tlb(vcpu, true);
	}

	/* This is needed for same reason as it was needed in prepare_vmcs02 */
	vmx->host_rsp = 0;

	/* Unpin physical memory we referred to in vmcs02 */
	if (vmx->nested.apic_access_page) {
		kvm_release_page_dirty(vmx->nested.apic_access_page);
		vmx->nested.apic_access_page = NULL;
	}
	if (vmx->nested.virtual_apic_page) {
		kvm_release_page_dirty(vmx->nested.virtual_apic_page);
		vmx->nested.virtual_apic_page = NULL;
	}
	if (vmx->nested.pi_desc_page) {
		kunmap(vmx->nested.pi_desc_page);
		kvm_release_page_dirty(vmx->nested.pi_desc_page);
		vmx->nested.pi_desc_page = NULL;
		vmx->nested.pi_desc = NULL;
	}

	/*
	 * We are now running in L2, mmu_notifier will force to reload the
	 * page's hpa for L2 vmcs. Need to reload it for L1 before entering L1.
	 */
	kvm_make_request(KVM_REQ_APIC_PAGE_RELOAD, vcpu);

	if (enable_shadow_vmcs && exit_reason != -1)
		vmx->nested.sync_shadow_vmcs = true;

	/* in case we halted in L2 */
	vcpu->arch.mp_state = KVM_MP_STATE_RUNNABLE;

	if (likely(!vmx->fail)) {
		if (exit_reason == EXIT_REASON_EXTERNAL_INTERRUPT &&
		    nested_exit_intr_ack_set(vcpu)) {
			int irq = kvm_cpu_get_interrupt(vcpu);
			WARN_ON(irq < 0);
			vmcs12->vm_exit_intr_info = irq |
				INTR_INFO_VALID_MASK | INTR_TYPE_EXT_INTR;
		}

		if (exit_reason != -1)
			trace_kvm_nested_vmexit_inject(vmcs12->vm_exit_reason,
						       vmcs12->exit_qualification,
						       vmcs12->idt_vectoring_info_field,
						       vmcs12->vm_exit_intr_info,
						       vmcs12->vm_exit_intr_error_code,
						       KVM_ISA_VMX);

		load_vmcs12_host_state(vcpu, vmcs12);

		return;
	}
	
	/*
	 * After an early L2 VM-entry failure, we're now back
	 * in L1 which thinks it just finished a VMLAUNCH or
	 * VMRESUME instruction, so we need to set the failure
	 * flag and the VM-instruction error field of the VMCS
	 * accordingly.
	 */
	nested_vmx_failValid(vcpu, VMXERR_ENTRY_INVALID_CONTROL_FIELD);

	/*
	 * Restore L1's host state to KVM's software model.  We're here
	 * because a consistency check was caught by hardware, which
	 * means some amount of guest state has been propagated to KVM's
	 * model and needs to be unwound to the host's state.
	 */
	nested_vmx_restore_host_state(vcpu);

	/*
	 * The emulated instruction was already skipped in
	 * nested_vmx_run, but the updated RIP was never
	 * written back to the vmcs01.
	 */
	skip_emulated_instruction(vcpu);
	vmx->fail = 0;
}

/*
 * Forcibly leave nested mode in order to be able to reset the VCPU later on.
 */
static void vmx_leave_nested(struct kvm_vcpu *vcpu)
{
	if (is_guest_mode(vcpu)) {
		to_vmx(vcpu)->nested.nested_run_pending = 0;
		nested_vmx_vmexit(vcpu, -1, 0, 0);
	}
	free_nested(to_vmx(vcpu));
}

/*
 * L1's failure to enter L2 is a subset of a normal exit, as explained in
 * 23.7 "VM-entry failures during or after loading guest state" (this also
 * lists the acceptable exit-reason and exit-qualification parameters).
 * It should only be called before L2 actually succeeded to run, and when
 * vmcs01 is current (it doesn't leave_guest_mode() or switch vmcss).
 */
static void nested_vmx_entry_failure(struct kvm_vcpu *vcpu,
			struct vmcs12 *vmcs12,
			u32 reason, unsigned long qualification)
{
	load_vmcs12_host_state(vcpu, vmcs12);
	vmcs12->vm_exit_reason = reason | VMX_EXIT_REASONS_FAILED_VMENTRY;
	vmcs12->exit_qualification = qualification;
	nested_vmx_succeed(vcpu);
	if (enable_shadow_vmcs)
		to_vmx(vcpu)->nested.sync_shadow_vmcs = true;
}

static int vmx_check_intercept_io(struct kvm_vcpu *vcpu,
				  struct x86_instruction_info *info)
{
	struct vmcs12 *vmcs12 = get_vmcs12(vcpu);
	unsigned short port;
	bool intercept;
	int size;

	if (info->intercept == x86_intercept_in ||
	    info->intercept == x86_intercept_ins) {
		port = info->src_val;
		size = info->dst_bytes;
	} else {
		port = info->dst_val;
		size = info->src_bytes;
	}

	/*
	 * If the 'use IO bitmaps' VM-execution control is 0, IO instruction
	 * VM-exits depend on the 'unconditional IO exiting' VM-execution
	 * control.
	 *
	 * Otherwise, IO instruction VM-exits are controlled by the IO bitmaps.
	 */
	if (!nested_cpu_has(vmcs12, CPU_BASED_USE_IO_BITMAPS))
		intercept = nested_cpu_has(vmcs12,
					   CPU_BASED_UNCOND_IO_EXITING);
	else
		intercept = nested_vmx_check_io_bitmaps(vcpu, port, size);

	/* FIXME: produce nested vmexit and return X86EMUL_INTERCEPTED.  */
	return intercept ? X86EMUL_UNHANDLEABLE : X86EMUL_CONTINUE;
}

static int vmx_check_intercept(struct kvm_vcpu *vcpu,
			       struct x86_instruction_info *info,
			       enum x86_intercept_stage stage)
{
	struct vmcs12 *vmcs12 = get_vmcs12(vcpu);
	struct x86_emulate_ctxt *ctxt = &vcpu->arch.emulate_ctxt;

	switch (info->intercept) {
	/*
	 * RDPID causes #UD if disabled through secondary execution controls.
	 * Because it is marked as EmulateOnUD, we need to intercept it here.
	 */
	case x86_intercept_rdtscp:
		if (!nested_cpu_has2(vmcs12, SECONDARY_EXEC_RDTSCP)) {
			ctxt->exception.vector = UD_VECTOR;
			ctxt->exception.error_code_valid = false;
			return X86EMUL_PROPAGATE_FAULT;
		}
		break;

	case x86_intercept_in:
	case x86_intercept_ins:
	case x86_intercept_out:
	case x86_intercept_outs:
		return vmx_check_intercept_io(vcpu, info);

	case x86_intercept_lgdt:
	case x86_intercept_lidt:
	case x86_intercept_lldt:
	case x86_intercept_ltr:
	case x86_intercept_sgdt:
	case x86_intercept_sidt:
	case x86_intercept_sldt:
	case x86_intercept_str:
		if (!nested_cpu_has2(vmcs12, SECONDARY_EXEC_DESC))
			return X86EMUL_CONTINUE;

		/* FIXME: produce nested vmexit and return X86EMUL_INTERCEPTED.  */
		break;

	case x86_intercept_pause:
		/*
		 * PAUSE is a single-byte NOP with a REPE prefix, i.e. collides
		 * with vanilla NOPs in the emulator.  Apply the interception
		 * check only to actual PAUSE instructions.  Don't check
		 * PAUSE-loop-exiting, software can't expect a given PAUSE to
		 * exit, i.e. KVM is within its rights to allow L2 to execute
		 * the PAUSE.
		 */
		if ((info->rep_prefix != REPE_PREFIX) ||
		    !nested_cpu_has2(vmcs12, CPU_BASED_PAUSE_EXITING))
			return X86EMUL_CONTINUE;

		break;

	/* TODO: check more intercepts... */
	default:
		break;
	}

	return X86EMUL_UNHANDLEABLE;
}

#ifdef CONFIG_X86_64
/* (a << shift) / divisor, return 1 if overflow otherwise 0 */
static inline int u64_shl_div_u64(u64 a, unsigned int shift,
				  u64 divisor, u64 *result)
{
	u64 low = a << shift, high = a >> (64 - shift);

	/* To avoid the overflow on divq */
	if (high >= divisor)
		return 1;

	/* Low hold the result, high hold rem which is discarded */
	asm("divq %2\n\t" : "=a" (low), "=d" (high) :
	    "rm" (divisor), "0" (low), "1" (high));
	*result = low;

	return 0;
}

static int vmx_set_hv_timer(struct kvm_vcpu *vcpu, u64 guest_deadline_tsc)
{
	struct vcpu_vmx *vmx;
	u64 tscl, guest_tscl, delta_tsc, lapic_timer_advance_cycles;

	if (kvm_mwait_in_guest(vcpu->kvm))
		return -EOPNOTSUPP;

	vmx = to_vmx(vcpu);
	tscl = rdtsc();
	guest_tscl = kvm_read_l1_tsc(vcpu, tscl);
	delta_tsc = max(guest_deadline_tsc, guest_tscl) - guest_tscl;
	lapic_timer_advance_cycles = nsec_to_cycles(vcpu, lapic_timer_advance_ns);

	if (delta_tsc > lapic_timer_advance_cycles)
		delta_tsc -= lapic_timer_advance_cycles;
	else
		delta_tsc = 0;

	/* Convert to host delta tsc if tsc scaling is enabled */
	if (vcpu->arch.tsc_scaling_ratio != kvm_default_tsc_scaling_ratio &&
			u64_shl_div_u64(delta_tsc,
				kvm_tsc_scaling_ratio_frac_bits,
				vcpu->arch.tsc_scaling_ratio,
				&delta_tsc))
		return -ERANGE;

	/*
	 * If the delta tsc can't fit in the 32 bit after the multi shift,
	 * we can't use the preemption timer.
	 * It's possible that it fits on later vmentries, but checking
	 * on every vmentry is costly so we just use an hrtimer.
	 */
	if (delta_tsc >> (cpu_preemption_timer_multi + 32))
		return -ERANGE;

	vmx->hv_deadline_tsc = tscl + delta_tsc;
	return delta_tsc == 0;
}

static void vmx_cancel_hv_timer(struct kvm_vcpu *vcpu)
{
	to_vmx(vcpu)->hv_deadline_tsc = -1;
}
#endif

static void vmx_sched_in(struct kvm_vcpu *vcpu, int cpu)
{
	if (!kvm_pause_in_guest(vcpu->kvm))
		shrink_ple_window(vcpu);
}

static void vmx_slot_enable_log_dirty(struct kvm *kvm,
				     struct kvm_memory_slot *slot)
{
	kvm_mmu_slot_leaf_clear_dirty(kvm, slot);
	kvm_mmu_slot_largepage_remove_write_access(kvm, slot);
}

static void vmx_slot_disable_log_dirty(struct kvm *kvm,
				       struct kvm_memory_slot *slot)
{
	kvm_mmu_slot_set_dirty(kvm, slot);
}

static void vmx_flush_log_dirty(struct kvm *kvm)
{
	kvm_flush_pml_buffers(kvm);
}

static int vmx_write_pml_buffer(struct kvm_vcpu *vcpu, gpa_t gpa)
{
	struct vmcs12 *vmcs12;
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	struct page *page = NULL;
	u64 *pml_address;

	if (is_guest_mode(vcpu)) {
		WARN_ON_ONCE(vmx->nested.pml_full);

		/*
		 * Check if PML is enabled for the nested guest.
		 * Whether eptp bit 6 is set is already checked
		 * as part of A/D emulation.
		 */
		vmcs12 = get_vmcs12(vcpu);
		if (!nested_cpu_has_pml(vmcs12))
			return 0;

		if (vmcs12->guest_pml_index >= PML_ENTITY_NUM) {
			vmx->nested.pml_full = true;
			return 1;
		}

		gpa &= ~0xFFFull;

		page = kvm_vcpu_gpa_to_page(vcpu, vmcs12->pml_address);
		if (is_error_page(page))
			return 0;

		pml_address = kmap(page);
		pml_address[vmcs12->guest_pml_index--] = gpa;
		kunmap(page);
		kvm_release_page_clean(page);
	}

	return 0;
}

static void vmx_enable_log_dirty_pt_masked(struct kvm *kvm,
					   struct kvm_memory_slot *memslot,
					   gfn_t offset, unsigned long mask)
{
	kvm_mmu_clear_dirty_pt_masked(kvm, memslot, offset, mask);
}

static void __pi_post_block(struct kvm_vcpu *vcpu)
{
	struct pi_desc *pi_desc = vcpu_to_pi_desc(vcpu);
	struct pi_desc old, new;
	unsigned int dest;

	do {
		old.control = new.control = pi_desc->control;
		WARN(old.nv != POSTED_INTR_WAKEUP_VECTOR,
		     "Wakeup handler not enabled while the VCPU is blocked\n");

		dest = cpu_physical_id(vcpu->cpu);

		if (x2apic_enabled())
			new.ndst = dest;
		else
			new.ndst = (dest << 8) & 0xFF00;

		/* set 'NV' to 'notification vector' */
		new.nv = POSTED_INTR_VECTOR;
	} while (cmpxchg64(&pi_desc->control, old.control,
			   new.control) != old.control);

	if (!WARN_ON_ONCE(vcpu->pre_pcpu == -1)) {
		spin_lock(&per_cpu(blocked_vcpu_on_cpu_lock, vcpu->pre_pcpu));
		list_del(&vcpu->blocked_vcpu_list);
		spin_unlock(&per_cpu(blocked_vcpu_on_cpu_lock, vcpu->pre_pcpu));
		vcpu->pre_pcpu = -1;
	}
}

/*
 * This routine does the following things for vCPU which is going
 * to be blocked if VT-d PI is enabled.
 * - Store the vCPU to the wakeup list, so when interrupts happen
 *   we can find the right vCPU to wake up.
 * - Change the Posted-interrupt descriptor as below:
 *      'NDST' <-- vcpu->pre_pcpu
 *      'NV' <-- POSTED_INTR_WAKEUP_VECTOR
 * - If 'ON' is set during this process, which means at least one
 *   interrupt is posted for this vCPU, we cannot block it, in
 *   this case, return 1, otherwise, return 0.
 *
 */
static int pi_pre_block(struct kvm_vcpu *vcpu)
{
	unsigned int dest;
	struct pi_desc old, new;
	struct pi_desc *pi_desc = vcpu_to_pi_desc(vcpu);

	if (!kvm_arch_has_assigned_device(vcpu->kvm) ||
		!irq_remapping_cap(IRQ_POSTING_CAP)  ||
		!kvm_vcpu_apicv_active(vcpu))
		return 0;

	WARN_ON(irqs_disabled());
	local_irq_disable();
	if (!WARN_ON_ONCE(vcpu->pre_pcpu != -1)) {
		vcpu->pre_pcpu = vcpu->cpu;
		spin_lock(&per_cpu(blocked_vcpu_on_cpu_lock, vcpu->pre_pcpu));
		list_add_tail(&vcpu->blocked_vcpu_list,
			      &per_cpu(blocked_vcpu_on_cpu,
				       vcpu->pre_pcpu));
		spin_unlock(&per_cpu(blocked_vcpu_on_cpu_lock, vcpu->pre_pcpu));
	}

	do {
		old.control = new.control = pi_desc->control;

		WARN((pi_desc->sn == 1),
		     "Warning: SN field of posted-interrupts "
		     "is set before blocking\n");

		/*
		 * Since vCPU can be preempted during this process,
		 * vcpu->cpu could be different with pre_pcpu, we
		 * need to set pre_pcpu as the destination of wakeup
		 * notification event, then we can find the right vCPU
		 * to wakeup in wakeup handler if interrupts happen
		 * when the vCPU is in blocked state.
		 */
		dest = cpu_physical_id(vcpu->pre_pcpu);

		if (x2apic_enabled())
			new.ndst = dest;
		else
			new.ndst = (dest << 8) & 0xFF00;

		/* set 'NV' to 'wakeup vector' */
		new.nv = POSTED_INTR_WAKEUP_VECTOR;
	} while (cmpxchg64(&pi_desc->control, old.control,
			   new.control) != old.control);

	/* We should not block the vCPU if an interrupt is posted for it.  */
	if (pi_test_on(pi_desc) == 1)
		__pi_post_block(vcpu);

	local_irq_enable();
	return (vcpu->pre_pcpu == -1);
}

static int vmx_pre_block(struct kvm_vcpu *vcpu)
{
	if (pi_pre_block(vcpu))
		return 1;

	if (kvm_lapic_hv_timer_in_use(vcpu))
		kvm_lapic_switch_to_sw_timer(vcpu);

	return 0;
}

static void pi_post_block(struct kvm_vcpu *vcpu)
{
	if (vcpu->pre_pcpu == -1)
		return;

	WARN_ON(irqs_disabled());
	local_irq_disable();
	__pi_post_block(vcpu);
	local_irq_enable();
}

static void vmx_post_block(struct kvm_vcpu *vcpu)
{
	if (kvm_x86_ops->set_hv_timer)
		kvm_lapic_switch_to_hv_timer(vcpu);

	pi_post_block(vcpu);
}

/*
 * vmx_update_pi_irte - set IRTE for Posted-Interrupts
 *
 * @kvm: kvm
 * @host_irq: host irq of the interrupt
 * @guest_irq: gsi of the interrupt
 * @set: set or unset PI
 * returns 0 on success, < 0 on failure
 */
static int vmx_update_pi_irte(struct kvm *kvm, unsigned int host_irq,
			      uint32_t guest_irq, bool set)
{
	struct kvm_kernel_irq_routing_entry *e;
	struct kvm_irq_routing_table *irq_rt;
	struct kvm_lapic_irq irq;
	struct kvm_vcpu *vcpu;
	struct vcpu_data vcpu_info;
	int idx, ret = 0;

	if (!kvm_arch_has_assigned_device(kvm) ||
		!irq_remapping_cap(IRQ_POSTING_CAP) ||
		!kvm_vcpu_apicv_active(kvm->vcpus[0]))
		return 0;

	idx = srcu_read_lock(&kvm->irq_srcu);
	irq_rt = srcu_dereference(kvm->irq_routing, &kvm->irq_srcu);
	if (guest_irq >= irq_rt->nr_rt_entries ||
	    hlist_empty(&irq_rt->map[guest_irq])) {
		pr_warn_once("no route for guest_irq %u/%u (broken user space?)\n",
			     guest_irq, irq_rt->nr_rt_entries);
		goto out;
	}

	hlist_for_each_entry(e, &irq_rt->map[guest_irq], link) {
		if (e->type != KVM_IRQ_ROUTING_MSI)
			continue;
		/*
		 * VT-d PI cannot support posting multicast/broadcast
		 * interrupts to a vCPU, we still use interrupt remapping
		 * for these kind of interrupts.
		 *
		 * For lowest-priority interrupts, we only support
		 * those with single CPU as the destination, e.g. user
		 * configures the interrupts via /proc/irq or uses
		 * irqbalance to make the interrupts single-CPU.
		 *
		 * We will support full lowest-priority interrupt later.
		 */

		kvm_set_msi_irq(kvm, e, &irq);
		if (!kvm_intr_is_single_vcpu(kvm, &irq, &vcpu)) {
			/*
			 * Make sure the IRTE is in remapped mode if
			 * we don't handle it in posted mode.
			 */
			ret = irq_set_vcpu_affinity(host_irq, NULL);
			if (ret < 0) {
				printk(KERN_INFO
				   "failed to back to remapped mode, irq: %u\n",
				   host_irq);
				goto out;
			}

			continue;
		}

		vcpu_info.pi_desc_addr = __pa(vcpu_to_pi_desc(vcpu));
		vcpu_info.vector = irq.vector;

		trace_kvm_pi_irte_update(host_irq, vcpu->vcpu_id, e->gsi,
				vcpu_info.vector, vcpu_info.pi_desc_addr, set);

		if (set)
			ret = irq_set_vcpu_affinity(host_irq, &vcpu_info);
		else
			ret = irq_set_vcpu_affinity(host_irq, NULL);

		if (ret < 0) {
			printk(KERN_INFO "%s: failed to update PI IRTE\n",
					__func__);
			goto out;
		}
	}

	ret = 0;
out:
	srcu_read_unlock(&kvm->irq_srcu, idx);
	return ret;
}

static void vmx_setup_mce(struct kvm_vcpu *vcpu)
{
	if (vcpu->arch.mcg_cap & MCG_LMCE_P)
		to_vmx(vcpu)->msr_ia32_feature_control_valid_bits |=
			FEATURE_CONTROL_LMCE;
	else
		to_vmx(vcpu)->msr_ia32_feature_control_valid_bits &=
			~FEATURE_CONTROL_LMCE;
}

static int vmx_smi_allowed(struct kvm_vcpu *vcpu)
{
	/* we need a nested vmexit to enter SMM, postpone if run is pending */
	if (to_vmx(vcpu)->nested.nested_run_pending)
		return 0;
	return 1;
}

static int vmx_pre_enter_smm(struct kvm_vcpu *vcpu, char *smstate)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);

	vmx->nested.smm.guest_mode = is_guest_mode(vcpu);
	if (vmx->nested.smm.guest_mode)
		nested_vmx_vmexit(vcpu, -1, 0, 0);

	vmx->nested.smm.vmxon = vmx->nested.vmxon;
	vmx->nested.vmxon = false;
	vmx_clear_hlt(vcpu);
	return 0;
}

static int vmx_pre_leave_smm(struct kvm_vcpu *vcpu, u64 smbase)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	int ret;

	if (vmx->nested.smm.vmxon) {
		vmx->nested.vmxon = true;
		vmx->nested.smm.vmxon = false;
	}

	if (vmx->nested.smm.guest_mode) {
		vcpu->arch.hflags &= ~HF_SMM_MASK;
		ret = enter_vmx_non_root_mode(vcpu, NULL);
		vcpu->arch.hflags |= HF_SMM_MASK;
		if (ret)
			return ret;

		vmx->nested.smm.guest_mode = false;
	}
	return 0;
}

static int enable_smi_window(struct kvm_vcpu *vcpu)
{
	return 0;
}

static int vmx_get_nested_state(struct kvm_vcpu *vcpu,
				struct kvm_nested_state __user *user_kvm_nested_state,
				u32 user_data_size)
{
	struct vcpu_vmx *vmx;
	struct vmcs12 *vmcs12;
	struct kvm_nested_state kvm_state = {
		.flags = 0,
		.format = 0,
		.size = sizeof(kvm_state),
		.vmx.vmxon_pa = -1ull,
		.vmx.vmcs_pa = -1ull,
	};

	if (!vcpu)
		return kvm_state.size + 2 * VMCS12_SIZE;

	vmx = to_vmx(vcpu);
	vmcs12 = get_vmcs12(vcpu);
	if (nested_vmx_allowed(vcpu) &&
	    (vmx->nested.vmxon || vmx->nested.smm.vmxon)) {
		kvm_state.vmx.vmxon_pa = vmx->nested.vmxon_ptr;
		kvm_state.vmx.vmcs_pa = vmx->nested.current_vmptr;

		if (vmx->nested.current_vmptr != -1ull) {
			kvm_state.size += VMCS12_SIZE;

			if (is_guest_mode(vcpu) &&
			    nested_cpu_has_shadow_vmcs(vmcs12) &&
			    vmcs12->vmcs_link_pointer != -1ull)
				kvm_state.size += VMCS12_SIZE;
		}

		if (vmx->nested.smm.vmxon)
			kvm_state.vmx.smm.flags |= KVM_STATE_NESTED_SMM_VMXON;

		if (vmx->nested.smm.guest_mode)
			kvm_state.vmx.smm.flags |= KVM_STATE_NESTED_SMM_GUEST_MODE;

		if (is_guest_mode(vcpu)) {
			kvm_state.flags |= KVM_STATE_NESTED_GUEST_MODE;

			if (vmx->nested.nested_run_pending)
				kvm_state.flags |= KVM_STATE_NESTED_RUN_PENDING;
		}
	}

	if (user_data_size < kvm_state.size)
		goto out;

	if (copy_to_user(user_kvm_nested_state, &kvm_state, sizeof(kvm_state)))
		return -EFAULT;

	if (vmx->nested.current_vmptr == -1ull)
		goto out;

	/*
	 * When running L2, the authoritative vmcs12 state is in the
	 * vmcs02. When running L1, the authoritative vmcs12 state is
	 * in the shadow vmcs linked to vmcs01, unless
	 * sync_shadow_vmcs is set, in which case, the authoritative
	 * vmcs12 state is in the vmcs12 already.
	 */
	if (is_guest_mode(vcpu))
		sync_vmcs12(vcpu, vmcs12);
	else if (enable_shadow_vmcs && !vmx->nested.sync_shadow_vmcs)
		copy_shadow_to_vmcs12(vmx);

	/*
	 * Copy over the full allocated size of vmcs12 rather than just the size
	 * of the struct.
	 */
	if (copy_to_user(user_kvm_nested_state->data, vmcs12, VMCS12_SIZE))
		return -EFAULT;

	if (nested_cpu_has_shadow_vmcs(vmcs12) &&
	    vmcs12->vmcs_link_pointer != -1ull) {
		if (copy_to_user(user_kvm_nested_state->data + VMCS12_SIZE,
				 get_shadow_vmcs12(vcpu), VMCS12_SIZE))
			return -EFAULT;
	}

out:
	return kvm_state.size;
}

static int vmx_set_nested_state(struct kvm_vcpu *vcpu,
				struct kvm_nested_state __user *user_kvm_nested_state,
				struct kvm_nested_state *kvm_state)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	struct vmcs12 *vmcs12;
	u32 exit_qual;
	int ret;

	if (kvm_state->format != 0)
		return -EINVAL;

	if (!nested_vmx_allowed(vcpu))
		return kvm_state->vmx.vmxon_pa == -1ull ? 0 : -EINVAL;

	if (kvm_state->vmx.vmxon_pa == -1ull) {
		if (kvm_state->vmx.smm.flags)
			return -EINVAL;

		if (kvm_state->vmx.vmcs_pa != -1ull)
			return -EINVAL;

		vmx_leave_nested(vcpu);
		return 0;
	}

	if (!page_address_valid(vcpu, kvm_state->vmx.vmxon_pa))
		return -EINVAL;

	if ((kvm_state->vmx.smm.flags & KVM_STATE_NESTED_SMM_GUEST_MODE) &&
	    (kvm_state->flags & KVM_STATE_NESTED_GUEST_MODE))
		return -EINVAL;

	if (kvm_state->vmx.smm.flags &
	    ~(KVM_STATE_NESTED_SMM_GUEST_MODE | KVM_STATE_NESTED_SMM_VMXON))
		return -EINVAL;

	/*
	 * SMM temporarily disables VMX, so we cannot be in guest mode,
	 * nor can VMLAUNCH/VMRESUME be pending.  Outside SMM, SMM flags
	 * must be zero.
	 */
	if (is_smm(vcpu) ? kvm_state->flags : kvm_state->vmx.smm.flags)
		return -EINVAL;

	if ((kvm_state->vmx.smm.flags & KVM_STATE_NESTED_SMM_GUEST_MODE) &&
	    !(kvm_state->vmx.smm.flags & KVM_STATE_NESTED_SMM_VMXON))
		return -EINVAL;

	vmx_leave_nested(vcpu);
	if (kvm_state->vmx.vmxon_pa == -1ull)
		return 0;

	vmx->nested.vmxon_ptr = kvm_state->vmx.vmxon_pa;
	ret = enter_vmx_operation(vcpu);
	if (ret)
		return ret;

	/* Empty 'VMXON' state is permitted */
	if (kvm_state->size < sizeof(*kvm_state) + sizeof(*vmcs12))
		return 0;

	if (kvm_state->vmx.vmcs_pa == kvm_state->vmx.vmxon_pa ||
	    !page_address_valid(vcpu, kvm_state->vmx.vmcs_pa))
		return -EINVAL;

	set_current_vmptr(vmx, kvm_state->vmx.vmcs_pa);

	if (kvm_state->vmx.smm.flags & KVM_STATE_NESTED_SMM_VMXON) {
		vmx->nested.smm.vmxon = true;
		vmx->nested.vmxon = false;

		if (kvm_state->vmx.smm.flags & KVM_STATE_NESTED_SMM_GUEST_MODE)
			vmx->nested.smm.guest_mode = true;
	}

	vmcs12 = get_vmcs12(vcpu);
	if (copy_from_user(vmcs12, user_kvm_nested_state->data, sizeof(*vmcs12)))
		return -EFAULT;

	if (vmcs12->hdr.revision_id != VMCS12_REVISION)
		return -EINVAL;

	if (!(kvm_state->flags & KVM_STATE_NESTED_GUEST_MODE))
		return 0;

	vmx->nested.nested_run_pending =
		!!(kvm_state->flags & KVM_STATE_NESTED_RUN_PENDING);

	if (nested_cpu_has_shadow_vmcs(vmcs12) &&
	    vmcs12->vmcs_link_pointer != -1ull) {
		struct vmcs12 *shadow_vmcs12 = get_shadow_vmcs12(vcpu);
		if (kvm_state->size < sizeof(*kvm_state) + 2 * sizeof(*vmcs12))
			return -EINVAL;

		if (copy_from_user(shadow_vmcs12,
				   user_kvm_nested_state->data + VMCS12_SIZE,
				   sizeof(*vmcs12)))
			return -EFAULT;

		if (shadow_vmcs12->hdr.revision_id != VMCS12_REVISION ||
		    !shadow_vmcs12->hdr.shadow_vmcs)
			return -EINVAL;
	}

	if (check_vmentry_prereqs(vcpu, vmcs12) ||
	    check_vmentry_postreqs(vcpu, vmcs12, &exit_qual))
		return -EINVAL;

	vmx->nested.dirty_vmcs12 = true;
	ret = enter_vmx_non_root_mode(vcpu, NULL);
	if (ret)
		return -EINVAL;

	return 0;
}

static struct kvm_x86_ops vmx_x86_ops __ro_after_init = {
	.cpu_has_kvm_support = cpu_has_kvm_support,
	.disabled_by_bios = vmx_disabled_by_bios,
	.hardware_setup = hardware_setup,
	.hardware_unsetup = hardware_unsetup,
	.check_processor_compatibility = vmx_check_processor_compat,
	.hardware_enable = hardware_enable,
	.hardware_disable = hardware_disable,
	.cpu_has_accelerated_tpr = report_flexpriority,
	.has_emulated_msr = vmx_has_emulated_msr,

	.vm_init = vmx_vm_init,
	.vm_alloc = vmx_vm_alloc,
	.vm_free = vmx_vm_free,

	.vcpu_create = vmx_create_vcpu,
	.vcpu_free = vmx_free_vcpu,
	.vcpu_reset = vmx_vcpu_reset,

	.prepare_guest_switch = vmx_prepare_switch_to_guest,
	.vcpu_load = vmx_vcpu_load,
	.vcpu_put = vmx_vcpu_put,

	.update_bp_intercept = update_exception_bitmap,
	.get_msr_feature = vmx_get_msr_feature,
	.get_msr = vmx_get_msr,
	.set_msr = vmx_set_msr,
	.get_segment_base = vmx_get_segment_base,
	.get_segment = vmx_get_segment,
	.set_segment = vmx_set_segment,
	.get_cpl = vmx_get_cpl,
	.get_cs_db_l_bits = vmx_get_cs_db_l_bits,
	.decache_cr0_guest_bits = vmx_decache_cr0_guest_bits,
	.decache_cr3 = vmx_decache_cr3,
	.decache_cr4_guest_bits = vmx_decache_cr4_guest_bits,
	.set_cr0 = vmx_set_cr0,
	.set_cr3 = vmx_set_cr3,
	.set_cr4 = vmx_set_cr4,
	.set_efer = vmx_set_efer,
	.get_idt = vmx_get_idt,
	.set_idt = vmx_set_idt,
	.get_gdt = vmx_get_gdt,
	.set_gdt = vmx_set_gdt,
	.get_dr6 = vmx_get_dr6,
	.set_dr6 = vmx_set_dr6,
	.set_dr7 = vmx_set_dr7,
	.sync_dirty_debug_regs = vmx_sync_dirty_debug_regs,
	.cache_reg = vmx_cache_reg,
	.get_rflags = vmx_get_rflags,
	.set_rflags = vmx_set_rflags,

	.tlb_flush = vmx_flush_tlb,
	.tlb_flush_gva = vmx_flush_tlb_gva,

	.run = vmx_vcpu_run,
	.handle_exit = vmx_handle_exit,
	.skip_emulated_instruction = skip_emulated_instruction,
	.set_interrupt_shadow = vmx_set_interrupt_shadow,
	.get_interrupt_shadow = vmx_get_interrupt_shadow,
	.patch_hypercall = vmx_patch_hypercall,
	.set_irq = vmx_inject_irq,
	.set_nmi = vmx_inject_nmi,
	.queue_exception = vmx_queue_exception,
	.cancel_injection = vmx_cancel_injection,
	.interrupt_allowed = vmx_interrupt_allowed,
	.nmi_allowed = vmx_nmi_allowed,
	.get_nmi_mask = vmx_get_nmi_mask,
	.set_nmi_mask = vmx_set_nmi_mask,
	.enable_nmi_window = enable_nmi_window,
	.enable_irq_window = enable_irq_window,
	.update_cr8_intercept = update_cr8_intercept,
	.set_virtual_apic_mode = vmx_set_virtual_apic_mode,
	.set_apic_access_page_addr = vmx_set_apic_access_page_addr,
	.get_enable_apicv = vmx_get_enable_apicv,
	.refresh_apicv_exec_ctrl = vmx_refresh_apicv_exec_ctrl,
	.load_eoi_exitmap = vmx_load_eoi_exitmap,
	.apicv_post_state_restore = vmx_apicv_post_state_restore,
	.hwapic_irr_update = vmx_hwapic_irr_update,
	.hwapic_isr_update = vmx_hwapic_isr_update,
	.guest_apic_has_interrupt = vmx_guest_apic_has_interrupt,
	.sync_pir_to_irr = vmx_sync_pir_to_irr,
	.deliver_posted_interrupt = vmx_deliver_posted_interrupt,
	.dy_apicv_has_pending_interrupt = vmx_dy_apicv_has_pending_interrupt,

	.set_tss_addr = vmx_set_tss_addr,
	.set_identity_map_addr = vmx_set_identity_map_addr,
	.get_tdp_level = get_ept_level,
	.get_mt_mask = vmx_get_mt_mask,

	.get_exit_info = vmx_get_exit_info,

	.get_lpage_level = vmx_get_lpage_level,

	.cpuid_update = vmx_cpuid_update,

	.rdtscp_supported = vmx_rdtscp_supported,
	.invpcid_supported = vmx_invpcid_supported,

	.set_supported_cpuid = vmx_set_supported_cpuid,

	.has_wbinvd_exit = cpu_has_vmx_wbinvd_exit,

	.read_l1_tsc_offset = vmx_read_l1_tsc_offset,
	.write_l1_tsc_offset = vmx_write_l1_tsc_offset,

	.set_tdp_cr3 = vmx_set_cr3,

	.check_intercept = vmx_check_intercept,
	.handle_external_intr = vmx_handle_external_intr,
	.mpx_supported = vmx_mpx_supported,
	.xsaves_supported = vmx_xsaves_supported,
	.umip_emulated = vmx_umip_emulated,

	.check_nested_events = vmx_check_nested_events,
	.request_immediate_exit = vmx_request_immediate_exit,

	.sched_in = vmx_sched_in,

	.slot_enable_log_dirty = vmx_slot_enable_log_dirty,
	.slot_disable_log_dirty = vmx_slot_disable_log_dirty,
	.flush_log_dirty = vmx_flush_log_dirty,
	.enable_log_dirty_pt_masked = vmx_enable_log_dirty_pt_masked,
	.write_log_dirty = vmx_write_pml_buffer,

	.pre_block = vmx_pre_block,
	.post_block = vmx_post_block,

	.pmu_ops = &intel_pmu_ops,

	.update_pi_irte = vmx_update_pi_irte,

#ifdef CONFIG_X86_64
	.set_hv_timer = vmx_set_hv_timer,
	.cancel_hv_timer = vmx_cancel_hv_timer,
#endif

	.setup_mce = vmx_setup_mce,

	.get_nested_state = vmx_get_nested_state,
	.set_nested_state = vmx_set_nested_state,
	.get_vmcs12_pages = nested_get_vmcs12_pages,

	.smi_allowed = vmx_smi_allowed,
	.pre_enter_smm = vmx_pre_enter_smm,
	.pre_leave_smm = vmx_pre_leave_smm,
	.enable_smi_window = enable_smi_window,
};

static void vmx_cleanup_l1d_flush(void)
{
	if (vmx_l1d_flush_pages) {
		free_pages((unsigned long)vmx_l1d_flush_pages, L1D_CACHE_ORDER);
		vmx_l1d_flush_pages = NULL;
	}
	/* Restore state so sysfs ignores VMX */
	l1tf_vmx_mitigation = VMENTER_L1D_FLUSH_AUTO;
}

static void vmx_exit(void)
{
#ifdef CONFIG_KEXEC_CORE
	RCU_INIT_POINTER(crash_vmclear_loaded_vmcss, NULL);
	synchronize_rcu();
#endif

	kvm_exit();

#if IS_ENABLED(CONFIG_HYPERV)
	if (static_branch_unlikely(&enable_evmcs)) {
		int cpu;
		struct hv_vp_assist_page *vp_ap;
		/*
		 * Reset everything to support using non-enlightened VMCS
		 * access later (e.g. when we reload the module with
		 * enlightened_vmcs=0)
		 */
		for_each_online_cpu(cpu) {
			vp_ap =	hv_get_vp_assist_page(cpu);

			if (!vp_ap)
				continue;

			vp_ap->current_nested_vmcs = 0;
			vp_ap->enlighten_vmentry = 0;
		}

		static_branch_disable(&enable_evmcs);
	}
#endif
	vmx_cleanup_l1d_flush();
}
module_exit(vmx_exit);

static int __init vmx_init(void)
{
	int r, cpu;

#if IS_ENABLED(CONFIG_HYPERV)
	/*
	 * Enlightened VMCS usage should be recommended and the host needs
	 * to support eVMCS v1 or above. We can also disable eVMCS support
	 * with module parameter.
	 */
	if (enlightened_vmcs &&
	    ms_hyperv.hints & HV_X64_ENLIGHTENED_VMCS_RECOMMENDED &&
	    (ms_hyperv.nested_features & HV_X64_ENLIGHTENED_VMCS_VERSION) >=
	    KVM_EVMCS_VERSION) {
		int cpu;

		/* Check that we have assist pages on all online CPUs */
		for_each_online_cpu(cpu) {
			if (!hv_get_vp_assist_page(cpu)) {
				enlightened_vmcs = false;
				break;
			}
		}

		if (enlightened_vmcs) {
			pr_info("KVM: vmx: using Hyper-V Enlightened VMCS\n");
			static_branch_enable(&enable_evmcs);
		}
	} else {
		enlightened_vmcs = false;
	}
#endif

	r = kvm_init(&vmx_x86_ops, sizeof(struct vcpu_vmx),
		     __alignof__(struct vcpu_vmx), THIS_MODULE);
	if (r)
		return r;

	/*
	 * Must be called after kvm_init() so enable_ept is properly set
	 * up. Hand the parameter mitigation value in which was stored in
	 * the pre module init parser. If no parameter was given, it will
	 * contain 'auto' which will be turned into the default 'cond'
	 * mitigation mode.
	 */
	if (boot_cpu_has(X86_BUG_L1TF)) {
		r = vmx_setup_l1d_flush(vmentry_l1d_flush_param);
		if (r) {
			vmx_exit();
			return r;
		}
	}

	vmx_setup_fb_clear_ctrl();

	for_each_possible_cpu(cpu) {
		INIT_LIST_HEAD(&per_cpu(loaded_vmcss_on_cpu, cpu));

		INIT_LIST_HEAD(&per_cpu(blocked_vcpu_on_cpu, cpu));
		spin_lock_init(&per_cpu(blocked_vcpu_on_cpu_lock, cpu));
	}

#ifdef CONFIG_KEXEC_CORE
	rcu_assign_pointer(crash_vmclear_loaded_vmcss,
			   crash_vmclear_local_loaded_vmcss);
#endif
	vmx_check_vmcs12_offsets();

	return 0;
}
module_init(vmx_init);
