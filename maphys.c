#include <CoreFoundation/CoreFoundation.h>
#include <mach-o/loader.h>
#include <mach/mach.h>

#define PMAP_MIN_OFF (0x10)
#define PMAP_MAX_OFF (0x18)
#define PROC_TASK_OFF (0x10)
#define VM_MAP_PMAP_OFF (0x48)
#define USER_CLIENT_TRAP_OFF (0x40)
#define IPC_PORT_IP_KOBJECT_OFF (0x68)
#ifdef __arm64e__
#	define CPU_DATA_RTCLOCK_DATAP_OFF (0x190)
#else
#	define CPU_DATA_RTCLOCK_DATAP_OFF (0x198)
#endif
#define VM_KERNEL_LINK_ADDRESS (0xFFFFFFF007004000ULL)
#define kCFCoreFoundationVersionNumber_iOS_13_0_b2 (1656)
#define kCFCoreFoundationVersionNumber_iOS_13_0_b1 (1652.20)
#define TASK_MAP_OFF (kCFCoreFoundationVersionNumber >= kCFCoreFoundationVersionNumber_iOS_13_0_b1 ? 0x28 : 0x20)
#define PROC_P_PID_OFF (kCFCoreFoundationVersionNumber >= kCFCoreFoundationVersionNumber_iOS_13_0_b2 ? 0x68 : 0x60)
#define TASK_ITK_REGISTERED_OFF (kCFCoreFoundationVersionNumber >= kCFCoreFoundationVersionNumber_iOS_13_0_b1 ? 0x308 : 0x2E8)
#define VTAB_GET_EXTERNAL_TRAP_FOR_INDEX_OFF (kCFCoreFoundationVersionNumber >= kCFCoreFoundationVersionNumber_iOS_13_0_b1 ? 0x5C0 : 0x5B8)

#define KADDR_FMT "0x%" PRIX64
#define VM_KERN_MEMORY_CPU (9)
#define RD(a) extract32(a, 0, 5)
#define RN(a) extract32(a, 5, 5)
#define BCOPY_PHYS_DST_PHYS (1U)
#define BCOPY_PHYS_SRC_PHYS (2U)
#define IS_RET(a) ((a) == 0xD65F03C0U)
#define ADRP_ADDR(a) ((a) & ~0xFFFULL)
#define ADRP_IMM(a) (ADR_IMM(a) << 12U)
#define IO_OBJECT_NULL ((io_object_t)0)
#define MAX_VTAB_SZ (vm_kernel_page_size)
#define ADD_X_IMM(a) extract32(a, 10, 12)
#define FAULT_MAGIC (0xAAAAAAAAAAAAAAAAULL)
#define BL_IMM(a) (sextract64(a, 0, 26) << 2U)
#define LDR_X_IMM(a) (sextract64(a, 5, 19) << 2U)
#define IS_BL(a) (((a) & 0xFC000000U) == 0x94000000U)
#define IS_ADR(a) (((a) & 0x9F000000U) == 0x10000000U)
#define IS_ADRP(a) (((a) & 0x9F000000U) == 0x90000000U)
#define IS_ADD_X(a) (((a) & 0xFFC00000U) == 0x91000000U)
#define IS_LDR_X(a) (((a) & 0xFF000000U) == 0x58000000U)
#define IS_MOV_X(a) (((a) & 0xFFE00000U) == 0xAA000000U)
#define LDR_X_UNSIGNED_IMM(a) (extract32(a, 10, 12) << 3U)
#define IS_MOV_W_ZHW(a) (((a) & 0xFFE00000U) == 0x52800000U)
#define IS_ADD_X_ZSHIFT(a) (((a) & 0xFFE00000U) == 0x8B000000U)
#define IS_LDR_X_UNSIGNED_IMM(a) (((a) & 0xFFC00000U) == 0xF9400000U)
#define ADR_IMM(a) ((sextract64(a, 5, 19) << 2U) | extract32(a, 29, 2))

#ifndef SEG_TEXT_EXEC
#	define SEG_TEXT_EXEC "__TEXT_EXEC"
#endif

#ifndef SECT_CSTRING
#	define SECT_CSTRING "__cstring"
#endif

#ifndef MIN
#	define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

typedef uint64_t kaddr_t;
typedef mach_port_t io_object_t;
typedef io_object_t io_service_t;
typedef io_object_t io_connect_t;

typedef struct {
	struct section_64 s64;
	char *data;
} sec_64_t;

typedef struct {
	sec_64_t sec_text, sec_cstring;
} pfinder_t;

typedef struct {
	kaddr_t obj, func, delta;
} io_external_trap_t;

kern_return_t
IOServiceClose(io_connect_t);

kern_return_t
IOObjectRelease(io_object_t);

CFMutableDictionaryRef
IOServiceMatching(const char *);

io_service_t
IOServiceGetMatchingService(mach_port_t, CFDictionaryRef);

kern_return_t
mach_vm_deallocate(vm_map_t, mach_vm_address_t, mach_vm_size_t);

kern_return_t
IOServiceOpen(io_service_t, task_port_t, uint32_t, io_connect_t *);

kern_return_t
mach_vm_allocate(vm_map_t, mach_vm_address_t *, mach_vm_size_t, int);

kern_return_t
mach_vm_copy(vm_map_t, mach_vm_address_t, mach_vm_size_t, mach_vm_address_t);

kern_return_t
mach_vm_write(vm_map_t, mach_vm_address_t, vm_offset_t, mach_msg_type_number_t);

kern_return_t
IOConnectTrap6(io_connect_t, uint32_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t);

kern_return_t
mach_vm_read_overwrite(vm_map_t, mach_vm_address_t, mach_vm_size_t, mach_vm_address_t, mach_vm_size_t *);

kern_return_t
mach_vm_machine_attribute(vm_map_t, mach_vm_address_t, mach_vm_size_t, vm_machine_attribute_t, vm_machine_attribute_val_t *);

kern_return_t
mach_vm_region(vm_map_t, mach_vm_address_t *, mach_vm_size_t *, vm_region_flavor_t, vm_region_info_t, mach_msg_type_number_t *, mach_port_t *);

extern const mach_port_t kIOMasterPortDefault;

static task_t tfp0 = MACH_PORT_NULL;
static io_connect_t g_conn = IO_OBJECT_NULL;
static kaddr_t allproc, csblob_get_cdhash, pmap_find_phys, bcopy_phys, orig_vtab, fake_vtab, user_client, kernel_pmap, kernel_pmap_min, kernel_pmap_max;

static uint32_t
extract32(uint32_t val, unsigned start, unsigned len) {
	return (val >> start) & (~0U >> (32U - len));
}

static uint64_t
sextract64(uint64_t val, unsigned start, unsigned len) {
	return (uint64_t)((int64_t)(val << (64U - len - start)) >> (64U - len));
}

static kern_return_t
init_tfp0(void) {
	kern_return_t ret = task_for_pid(mach_task_self(), 0, &tfp0);
	mach_port_t host;
	pid_t pid;

	if(ret != KERN_SUCCESS) {
		host = mach_host_self();
		if(MACH_PORT_VALID(host)) {
			printf("host: 0x%" PRIX32 "\n", host);
			ret = host_get_special_port(host, HOST_LOCAL_NODE, 4, &tfp0);
			mach_port_deallocate(mach_task_self(), host);
		}
	}
	if(ret == KERN_SUCCESS && MACH_PORT_VALID(tfp0)) {
		if(pid_for_task(tfp0, &pid) == KERN_SUCCESS && pid == 0) {
			return ret;
		}
		mach_port_deallocate(mach_task_self(), tfp0);
	}
	return KERN_FAILURE;
}

static kern_return_t
kread_buf(kaddr_t addr, void *buf, mach_vm_size_t sz) {
	mach_vm_address_t p = (mach_vm_address_t)buf;
	mach_vm_size_t read_sz, out_sz = 0;

	while(sz != 0) {
		read_sz = MIN(sz, vm_kernel_page_size - (addr & vm_kernel_page_mask));
		if(mach_vm_read_overwrite(tfp0, addr, read_sz, p, &out_sz) != KERN_SUCCESS || out_sz != read_sz) {
			return KERN_FAILURE;
		}
		p += read_sz;
		sz -= read_sz;
		addr += read_sz;
	}
	return KERN_SUCCESS;
}

static kern_return_t
kread_addr(kaddr_t addr, kaddr_t *val) {
	return kread_buf(addr, val, sizeof(*val));
}

static kern_return_t
kwrite_buf(kaddr_t addr, const void *buf, mach_msg_type_number_t sz) {
	vm_machine_attribute_val_t mattr_val = MATTR_VAL_CACHE_FLUSH;
	mach_vm_address_t p = (mach_vm_address_t)buf;
	mach_msg_type_number_t write_sz;

	while(sz != 0) {
		write_sz = (mach_msg_type_number_t)MIN(sz, vm_kernel_page_size - (addr & vm_kernel_page_mask));
		if(mach_vm_write(tfp0, addr, p, write_sz) != KERN_SUCCESS || mach_vm_machine_attribute(tfp0, addr, write_sz, MATTR_CACHE, &mattr_val) != KERN_SUCCESS) {
			return KERN_FAILURE;
		}
		p += write_sz;
		sz -= write_sz;
		addr += write_sz;
	}
	return KERN_SUCCESS;
}

static kern_return_t
kwrite_addr(kaddr_t addr, kaddr_t val) {
	return kwrite_buf(addr, &val, sizeof(val));
}

static kern_return_t
kalloc(mach_vm_size_t sz, kaddr_t *addr) {
	return mach_vm_allocate(tfp0, addr, sz, VM_FLAGS_ANYWHERE);
}

static kern_return_t
kfree(kaddr_t addr, mach_vm_size_t sz) {
	return mach_vm_deallocate(tfp0, addr, sz);
}

static kaddr_t
get_kbase(kaddr_t *kslide) {
	mach_msg_type_number_t cnt = TASK_DYLD_INFO_COUNT;
	vm_region_extended_info_data_t extended_info;
	task_dyld_info_data_t dyld_info;
	kaddr_t addr, rtclock_datap;
	struct mach_header_64 mh64;
	mach_port_t obj_nm;
	mach_vm_size_t sz;

	if(task_info(tfp0, TASK_DYLD_INFO, (task_info_t)&dyld_info, &cnt) == KERN_SUCCESS && dyld_info.all_image_info_size != 0) {
		*kslide = dyld_info.all_image_info_size;
		return VM_KERNEL_LINK_ADDRESS + *kslide;
	}
	cnt = VM_REGION_EXTENDED_INFO_COUNT;
	for(addr = 0; mach_vm_region(tfp0, &addr, &sz, VM_REGION_EXTENDED_INFO, (vm_region_info_t)&extended_info, &cnt, &obj_nm) == KERN_SUCCESS; addr += sz) {
		mach_port_deallocate(mach_task_self(), obj_nm);
		if(extended_info.user_tag == VM_KERN_MEMORY_CPU && extended_info.protection == VM_PROT_DEFAULT) {
			if(kread_addr(addr + CPU_DATA_RTCLOCK_DATAP_OFF, &rtclock_datap) != KERN_SUCCESS) {
				break;
			}
			printf("rtclock_datap: " KADDR_FMT "\n", rtclock_datap);
			rtclock_datap = trunc_page_kernel(rtclock_datap);
			do {
				if(rtclock_datap <= VM_KERNEL_LINK_ADDRESS) {
					return 0;
				}
				rtclock_datap -= vm_kernel_page_size;
				if(kread_buf(rtclock_datap, &mh64, sizeof(mh64)) != KERN_SUCCESS) {
					return 0;
				}
			} while(mh64.magic != MH_MAGIC_64 || mh64.cputype != CPU_TYPE_ARM64 || mh64.filetype != MH_EXECUTE);
			*kslide = rtclock_datap - VM_KERNEL_LINK_ADDRESS;
			return rtclock_datap;
		}
	}
	return 0;
}

static kern_return_t
find_section(kaddr_t sg64_addr, struct segment_command_64 sg64, const char *sect_name, struct section_64 *sp) {
	kaddr_t s64_addr, s64_end;

	for(s64_addr = sg64_addr + sizeof(sg64), s64_end = s64_addr + (sg64.cmdsize - sizeof(*sp)); s64_addr < s64_end; s64_addr += sizeof(*sp)) {
		if(kread_buf(s64_addr, sp, sizeof(*sp)) != KERN_SUCCESS) {
			break;
		}
		if(strncmp(sp->segname, sg64.segname, sizeof(sp->segname)) == 0 && strncmp(sp->sectname, sect_name, sizeof(sp->sectname)) == 0) {
			return KERN_SUCCESS;
		}
	}
	return KERN_FAILURE;
}

static void
sec_reset(sec_64_t *sec) {
	memset(&sec->s64, '\0', sizeof(sec->s64));
	sec->data = NULL;
}

static void
sec_term(sec_64_t *sec) {
	free(sec->data);
	sec_reset(sec);
}

static kern_return_t
sec_init(sec_64_t *sec) {
	if((sec->data = malloc(sec->s64.size)) != NULL) {
		if(kread_buf(sec->s64.addr, sec->data, sec->s64.size) == KERN_SUCCESS) {
			return KERN_SUCCESS;
		}
		sec_term(sec);
	}
	return KERN_FAILURE;
}

static void
pfinder_reset(pfinder_t *pfinder) {
	sec_reset(&pfinder->sec_text);
	sec_reset(&pfinder->sec_cstring);
}

static void
pfinder_term(pfinder_t *pfinder) {
	sec_term(&pfinder->sec_text);
	sec_term(&pfinder->sec_cstring);
	pfinder_reset(pfinder);
}

static kern_return_t
pfinder_init(pfinder_t *pfinder, kaddr_t kbase) {
	kern_return_t ret = KERN_FAILURE;
	struct segment_command_64 sg64;
	kaddr_t sg64_addr, sg64_end;
	struct mach_header_64 mh64;
	struct section_64 s64;

	pfinder_reset(pfinder);
	if(kread_buf(kbase, &mh64, sizeof(mh64)) == KERN_SUCCESS && mh64.magic == MH_MAGIC_64 && mh64.cputype == CPU_TYPE_ARM64 && mh64.filetype == MH_EXECUTE) {
		for(sg64_addr = kbase + sizeof(mh64), sg64_end = sg64_addr + (mh64.sizeofcmds - sizeof(sg64)); sg64_addr < sg64_end; sg64_addr += sg64.cmdsize) {
			if(kread_buf(sg64_addr, &sg64, sizeof(sg64)) != KERN_SUCCESS) {
				break;
			}
			if(sg64.cmd == LC_SEGMENT_64) {
				if(strncmp(sg64.segname, SEG_TEXT_EXEC, sizeof(sg64.segname)) == 0 && find_section(sg64_addr, sg64, SECT_TEXT, &s64) == KERN_SUCCESS) {
					pfinder->sec_text.s64 = s64;
					printf("sec_text_addr: " KADDR_FMT ", sec_text_sz: 0x%" PRIX64 "\n", s64.addr, s64.size);
				} else if(strncmp(sg64.segname, SEG_TEXT, sizeof(sg64.segname)) == 0 && find_section(sg64_addr, sg64, SECT_CSTRING, &s64) == KERN_SUCCESS) {
					pfinder->sec_cstring.s64 = s64;
					printf("sec_cstring_addr: " KADDR_FMT ", sec_cstring_sz: 0x%" PRIX64 "\n", s64.addr, s64.size);
				}
			}
			if(pfinder->sec_text.s64.size != 0 && pfinder->sec_cstring.s64.size != 0) {
				if(sec_init(&pfinder->sec_text) == KERN_SUCCESS) {
					ret = sec_init(&pfinder->sec_cstring);
				}
				break;
			}
		}
	}
	if(ret != KERN_SUCCESS) {
		pfinder_term(pfinder);
	}
	return ret;
}

static kaddr_t
pfinder_xref_rd(pfinder_t pfinder, uint32_t rd, kaddr_t start, kaddr_t to) {
	uint64_t x[32] = { 0 };
	uint32_t insn;

	for(; start >= pfinder.sec_text.s64.addr && start < pfinder.sec_text.s64.addr + (pfinder.sec_text.s64.size - sizeof(insn)); start += sizeof(insn)) {
		memcpy(&insn, pfinder.sec_text.data + (start - pfinder.sec_text.s64.addr), sizeof(insn));
		if(IS_LDR_X(insn)) {
			x[RD(insn)] = start + LDR_X_IMM(insn);
		} else if(IS_ADR(insn)) {
			x[RD(insn)] = start + ADR_IMM(insn);
		} else if(IS_ADRP(insn)) {
			x[RD(insn)] = ADRP_ADDR(start) + ADRP_IMM(insn);
			continue;
		} else if(IS_ADD_X(insn)) {
			x[RD(insn)] = x[RN(insn)] + ADD_X_IMM(insn);
		} else if(IS_LDR_X_UNSIGNED_IMM(insn)) {
			x[RD(insn)] = x[RN(insn)] + LDR_X_UNSIGNED_IMM(insn);
		} else if(IS_RET(insn)) {
			memset(x, '\0', sizeof(x));
		}
		if(RD(insn) == rd) {
			if(to == 0) {
				return x[rd];
			}
			if(x[rd] == to) {
				return start;
			}
		}
	}
	return 0;
}

static kaddr_t
pfinder_xref_str(pfinder_t pfinder, const char *str, uint32_t rd) {
	const char *p, *e;
	size_t len;

	for(p = pfinder.sec_cstring.data, e = p + pfinder.sec_cstring.s64.size; p < e; p += len) {
		len = strlen(p) + 1;
		if(strncmp(str, p, len) == 0) {
			return pfinder_xref_rd(pfinder, rd, pfinder.sec_text.s64.addr, pfinder.sec_cstring.s64.addr + (kaddr_t)(p - pfinder.sec_cstring.data));
		}
	}
	return 0;
}

static kaddr_t
pfinder_allproc(pfinder_t pfinder) {
	kaddr_t ref = pfinder_xref_str(pfinder, "shutdownwait", 2);

	if(ref == 0) {
		ref = pfinder_xref_str(pfinder, "shutdownwait", 3); /* msleep */
	}
	return pfinder_xref_rd(pfinder, 8, ref, 0);
}

static kaddr_t
pfinder_csblob_get_cdhash(pfinder_t pfinder) {
	uint32_t insns[2];
	kaddr_t start;

	for(start = pfinder.sec_text.s64.addr; start < pfinder.sec_text.s64.addr + (pfinder.sec_text.s64.size - sizeof(insns)); start += sizeof(*insns)) {
		memcpy(insns, pfinder.sec_text.data + (start - pfinder.sec_text.s64.addr), sizeof(insns));
		if(IS_ADD_X(insns[0]) && RD(insns[0]) == 0 && RN(insns[0]) == 0 && ADD_X_IMM(insns[0]) == USER_CLIENT_TRAP_OFF && IS_RET(insns[1])) {
			return start;
		}
	}
	return 0;
}

static kaddr_t
pfinder_pmap_find_phys(pfinder_t pfinder) {
	uint32_t insns[2];
	kaddr_t ref;

	for(ref = pfinder_xref_str(pfinder, "Kext %s - page %p is not backed by physical memory.", 2); ref >= pfinder.sec_text.s64.addr && ref < pfinder.sec_text.s64.addr + (pfinder.sec_text.s64.size - sizeof(insns)); ref -= sizeof(*insns)) {
		memcpy(insns, pfinder.sec_text.data + (ref - pfinder.sec_text.s64.addr), sizeof(insns));
		if(IS_MOV_X(insns[0]) && RD(insns[0]) == 1 && IS_BL(insns[1])) {
			return ref + sizeof(*insns) + BL_IMM(insns[1]);
		}
	}
	return 0;
}

static kaddr_t
pfinder_ml_nofault_copy(pfinder_t pfinder) {
	uint32_t insns[2];
	kaddr_t ref;

	for(ref = pfinder_xref_str(pfinder, "Kernel UUID: %s\n", 0); ref >= pfinder.sec_text.s64.addr && ref < pfinder.sec_text.s64.addr + (pfinder.sec_text.s64.size - sizeof(insns)); ref -= sizeof(*insns)) {
		memcpy(insns, pfinder.sec_text.data + (ref - pfinder.sec_text.s64.addr), sizeof(insns));
		if(IS_MOV_W_ZHW(insns[0]) && RD(insns[0]) == 2 && IS_BL(insns[1])) {
			return ref + sizeof(*insns) + BL_IMM(insns[1]);
		}
	}
	return 0;
}

static kaddr_t
pfinder_bcopy_phys(pfinder_t pfinder) {
	kaddr_t ref = pfinder_ml_nofault_copy(pfinder);
	uint32_t insns[2];

	printf("ml_nofault_copy: " KADDR_FMT "\n", ref);
	for(; ref >= pfinder.sec_text.s64.addr && ref < pfinder.sec_text.s64.addr + (pfinder.sec_text.s64.size - sizeof(insns)); ref += sizeof(*insns)) {
		memcpy(insns, pfinder.sec_text.data + (ref - pfinder.sec_text.s64.addr), sizeof(insns));
		if(IS_BL(insns[0]) && IS_ADD_X_ZSHIFT(insns[1])) {
			return ref + BL_IMM(insns[0]);
		}
	}
	return 0;
}

static kern_return_t
pfinder_init_offsets(pfinder_t pfinder) {
	if((allproc = pfinder_allproc(pfinder)) != 0) {
		printf("allproc: " KADDR_FMT "\n", allproc);
		if((csblob_get_cdhash = pfinder_csblob_get_cdhash(pfinder)) != 0) {
			printf("csblob_get_cdhash: " KADDR_FMT "\n", csblob_get_cdhash);
			if((pmap_find_phys = pfinder_pmap_find_phys(pfinder)) != 0) {
				printf("pmap_find_phys: " KADDR_FMT "\n", pmap_find_phys);
				if((bcopy_phys = pfinder_bcopy_phys(pfinder)) != 0) {
					printf("bcopy_phys: " KADDR_FMT "\n", bcopy_phys);
					return KERN_SUCCESS;
				}
			}
		}
	}
	return KERN_FAILURE;
}

static kern_return_t
find_task(pid_t pid, kaddr_t *task) {
	kaddr_t proc = allproc;
	pid_t cur_pid;

	while(kread_addr(proc, &proc) == KERN_SUCCESS && proc != 0) {
		if(kread_buf(proc + PROC_P_PID_OFF, &cur_pid, sizeof(cur_pid)) == KERN_SUCCESS && cur_pid == pid) {
			return kread_addr(proc + PROC_TASK_OFF, task);
		}
	}
	return KERN_FAILURE;
}

static io_connect_t
get_conn(const char *name) {
	io_service_t serv = IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceMatching(name));
	io_connect_t conn = IO_OBJECT_NULL;

	if(serv != IO_OBJECT_NULL) {
		printf("serv: 0x%" PRIX32 "\n", serv);
		if(IOServiceOpen(serv, mach_task_self(), 0, &conn) != KERN_SUCCESS) {
			conn = IO_OBJECT_NULL;
		}
		IOObjectRelease(serv);
	}
	return conn;
}

static kaddr_t
get_port(kaddr_t our_task, mach_port_t port) {
	kaddr_t ipc_port = 0;

	if(mach_ports_register(mach_task_self(), &port, 1) == KERN_SUCCESS) {
		if(kread_addr(our_task + TASK_ITK_REGISTERED_OFF, &ipc_port) != KERN_SUCCESS) {
			ipc_port = 0;
		}
		mach_ports_register(mach_task_self(), NULL, 0);
	}
	return ipc_port;
}

static void
kcall_term(void) {
	io_external_trap_t trap = { 0 };

	kwrite_addr(user_client, orig_vtab);
	kfree(fake_vtab, MAX_VTAB_SZ);
	kwrite_buf(user_client + USER_CLIENT_TRAP_OFF, &trap, sizeof(trap));
	IOServiceClose(g_conn);
}

static kern_return_t
kcall_init(void) {
	kaddr_t our_task, ipc_port;

	if((g_conn = get_conn("AppleKeyStore")) != IO_OBJECT_NULL) {
		printf("g_conn: 0x%" PRIX32 "\n", g_conn);
		if(find_task(getpid(), &our_task) == KERN_SUCCESS) {
			printf("our_task: " KADDR_FMT "\n", our_task);
			if((ipc_port = get_port(our_task, g_conn)) != 0) {
				printf("ipc_port: " KADDR_FMT "\n", ipc_port);
				if(kread_addr(ipc_port + IPC_PORT_IP_KOBJECT_OFF, &user_client) == KERN_SUCCESS) {
					printf("user_client: " KADDR_FMT "\n", user_client);
					if(kread_addr(user_client, &orig_vtab) == KERN_SUCCESS) {
						printf("orig_vtab: " KADDR_FMT "\n", orig_vtab);
						if(kalloc(MAX_VTAB_SZ, &fake_vtab) == KERN_SUCCESS) {
							printf("fake_vtab: " KADDR_FMT "\n", fake_vtab);
							if(mach_vm_copy(tfp0, orig_vtab, MAX_VTAB_SZ, fake_vtab) == KERN_SUCCESS && kwrite_addr(fake_vtab + VTAB_GET_EXTERNAL_TRAP_FOR_INDEX_OFF, csblob_get_cdhash) == KERN_SUCCESS && kwrite_addr(user_client, fake_vtab) == KERN_SUCCESS) {
								return KERN_SUCCESS;
							}
							kfree(fake_vtab, MAX_VTAB_SZ);
						}
					}
				}
			}
		}
		IOServiceClose(g_conn);
	}
	return KERN_FAILURE;
}

static kern_return_t
kcall(kern_return_t *ret, kaddr_t func, size_t argc, ...) {
	io_external_trap_t trap;
	kaddr_t args[7] = { 1 };
	va_list ap;
	size_t i;

	va_start(ap, argc);
	for(i = 0; i < MIN(argc, 7); ++i) {
		args[i] = va_arg(ap, kaddr_t);
	}
	va_end(ap);
	trap.obj = args[0];
	trap.func = func;
	trap.delta = 0;
	if(kwrite_buf(user_client + USER_CLIENT_TRAP_OFF, &trap, sizeof(trap)) == KERN_SUCCESS) {
		*ret = IOConnectTrap6(g_conn, 0, args[1], args[2], args[3], args[4], args[5], args[6]);
		return KERN_SUCCESS;
	}
	return KERN_FAILURE;
}

static kern_return_t
phys_init(void) {
	kaddr_t kernel_task, kernel_map;

	if(find_task(0, &kernel_task) == KERN_SUCCESS) {
		printf("kernel_task: " KADDR_FMT "\n", kernel_task);
		if(kread_addr(kernel_task + TASK_MAP_OFF, &kernel_map) == KERN_SUCCESS) {
			printf("kernel_map: " KADDR_FMT "\n", kernel_map);
			if(kread_addr(kernel_map + VM_MAP_PMAP_OFF, &kernel_pmap) == KERN_SUCCESS) {
				printf("kernel_pmap: " KADDR_FMT "\n", kernel_pmap);
				if(kread_addr(kernel_pmap + PMAP_MIN_OFF, &kernel_pmap_min) == KERN_SUCCESS) {
					printf("kernel_pmap_min: " KADDR_FMT "\n", kernel_pmap_min);
					if(kread_addr(kernel_pmap + PMAP_MAX_OFF, &kernel_pmap_max) == KERN_SUCCESS) {
						printf("kernel_pmap_max: " KADDR_FMT "\n", kernel_pmap_max);
						return KERN_SUCCESS;
					}
				}
			}
		}
	}
	return KERN_FAILURE;
}

static kern_return_t
phys_copy(kaddr_t src, kaddr_t dst, mach_vm_size_t sz) {
	vm_machine_attribute_val_t mattr_val = MATTR_VAL_CACHE_FLUSH;
	kaddr_t phys_src = src, phys_dst = dst;
	bool is_virt_src, is_virt_dst;
	mach_vm_size_t copy_sz;
	kern_return_t ret;

	while(sz != 0) {
		is_virt_src = src >= kernel_pmap_min && src < kernel_pmap_max;
		if(is_virt_src) {
			if(kcall(&ret, pmap_find_phys, 2, kernel_pmap, src) != KERN_SUCCESS || ret <= 0) {
				return KERN_FAILURE;
			}
			phys_src = ((kaddr_t)ret << vm_kernel_page_shift) | (src & vm_kernel_page_mask);
			printf("phys_src: " KADDR_FMT "\n", phys_src);
		}
		is_virt_dst = dst >= kernel_pmap_min && dst < kernel_pmap_max;
		if(is_virt_dst) {
			if(kcall(&ret, pmap_find_phys, 2, kernel_pmap, dst) != KERN_SUCCESS || ret <= 0) {
				if(kwrite_addr(dst, FAULT_MAGIC) != KERN_SUCCESS || kcall(&ret, pmap_find_phys, 2, kernel_pmap, dst) != KERN_SUCCESS || ret <= 0) {
					return KERN_FAILURE;
				}
			}
			phys_dst = ((kaddr_t)ret << vm_kernel_page_shift) | (dst & vm_kernel_page_mask);
			printf("phys_dst: " KADDR_FMT "\n", phys_dst);
		}
		copy_sz = MIN(sz, MIN(vm_kernel_page_size - (phys_src & vm_kernel_page_mask), vm_kernel_page_size - (phys_dst & vm_kernel_page_mask)));
		if(((phys_src | phys_dst | copy_sz) % sizeof(kaddr_t)) != 0 || kcall(&ret, bcopy_phys, 4, phys_src, phys_dst, copy_sz, BCOPY_PHYS_SRC_PHYS | BCOPY_PHYS_DST_PHYS) != KERN_SUCCESS) {
			return KERN_FAILURE;
		}
		if(is_virt_dst && mach_vm_machine_attribute(tfp0, dst, copy_sz, MATTR_CACHE, &mattr_val) != KERN_SUCCESS) {
			return KERN_FAILURE;
		}
		src += copy_sz;
		dst += copy_sz;
		sz -= copy_sz;
	}
	return KERN_SUCCESS;
}

static void
phys_test(void) {
	kaddr_t virt_src, virt_dst;

	if(kalloc(vm_kernel_page_size, &virt_src) == KERN_SUCCESS) {
		printf("virt_src: " KADDR_FMT "\n", virt_src);
		if(kwrite_addr(virt_src, FAULT_MAGIC) == KERN_SUCCESS) {
			if(kalloc(vm_kernel_page_size, &virt_dst) == KERN_SUCCESS) {
				printf("virt_dst: " KADDR_FMT "\n", virt_dst);
				if(phys_copy(virt_src, virt_dst, vm_kernel_page_size) == KERN_SUCCESS) {
					printf("Copied 0x%lx bytes from " KADDR_FMT " to " KADDR_FMT "\n", vm_kernel_page_size, virt_src, virt_dst);
				}
				kfree(virt_dst, vm_kernel_page_size);
			}
		}
		kfree(virt_src, vm_kernel_page_size);
	}
}

int
main(void) {
	kaddr_t kbase, kslide;
	kern_return_t ret;
	pfinder_t pfinder;

	if(init_tfp0() == KERN_SUCCESS) {
		printf("tfp0: 0x%" PRIX32 "\n", tfp0);
		if((kbase = get_kbase(&kslide)) != 0) {
			printf("kbase: " KADDR_FMT ", kslide: " KADDR_FMT "\n", kbase, kslide);
			if(pfinder_init(&pfinder, kbase) == KERN_SUCCESS) {
				if(pfinder_init_offsets(pfinder) == KERN_SUCCESS && kcall_init() == KERN_SUCCESS) {
					if(kcall(&ret, csblob_get_cdhash, 1, USER_CLIENT_TRAP_OFF) == KERN_SUCCESS) {
						printf("csblob_get_cdhash(USER_CLIENT_TRAP_OFF): 0x%" PRIX32 "\n", ret);
						if(phys_init() == KERN_SUCCESS) {
							phys_test();
						}
					}
					kcall_term();
				}
				pfinder_term(&pfinder);
			}
		}
		mach_port_deallocate(mach_task_self(), tfp0);
	}
}
