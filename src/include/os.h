#ifndef __OS_H_
#define __OS_H_

#include <stdint.h>
#include <sys/types.h>

#ifndef _WIN32
#include <dlfcn.h>
#include <sys/mman.h>
#else
#include <windows.h>
typedef __int64 ssize_t;
#define dlsym(a, b) NULL
#define box_strdup(a) strdup(a)

#define PROT_READ  0x1
#define PROT_WRITE 0x2
#define PROT_EXEC  0x4

#define MAP_FAILED    ((void*)-1)
#define MAP_PRIVATE   0x02
#define MAP_FIXED     0x10
#define MAP_ANONYMOUS 0x20
#define MAP_32BIT     0x40
#define MAP_NORESERVE 0

void* mmap(void* addr, size_t length, int prot, int flags, int fd, off_t offset);
int munmap(void* addr, size_t length);
int mprotect(void* addr, size_t len, int prot);

void x86Int(void* emu, int code);

void* WinMalloc(size_t size);
void* WinRealloc(void* ptr, size_t size);
void* WinCalloc(size_t nmemb, size_t size);
void WinFree(void* ptr);
#endif

void* InternalMmap(void* addr, unsigned long length, int prot, int flags, int fd, ssize_t offset);

/* [rosetta 补丁 0009] guest 分配钩子(ROSETTA_EMBED):box64 的一切
 * 映射原语(装载映像/栈/dynablock arena/簿记)进 gVisor mm——guest
 * syscall 传进来的指针必须能被 sentry copyin 解析,宿主匿名映射会触
 * EFAULT(ADR-0014 的根本差异);box64 的语义形状 = gVisor 上的普通
 * arm64 程序,零宿主内核调用(ADR-0025)。shim 供给(合成 ring
 * syscall);fd >= 0 直通 guest file-backed mmap(guest fd 语义)。
 * InternalMmap/InternalMunmap 在 os_linux.c 内已重定向到本族;
 * 直调 mmap/munmap/mprotect 的漏网点由构建侧 TU 强制包含头收口
 * (andock shim/guestheap/alloc_redirect.h)。 */
#ifdef ROSETTA_EMBED
#include <stdio.h>
void* rosetta_guest_mmap(void* addr, size_t len, int prot, int flags, int fd, ssize_t offset);
int rosetta_guest_mprotect(void* addr, size_t len, int prot);
int rosetta_guest_munmap(void* addr, size_t len);
/* [rosetta 补丁 0009] loader 文件 IO 的 guest 面:funopen 包裹 guest
 * fd(bionic 无 fopencookie);fileno 登记簿供 elfloader 的 try_mmap;
 * getrandom = AT_RANDOM 的 guest 侧正向产出源(失败即 fail loud) */
FILE* rosetta_guest_fopen(const char* path);
int rosetta_guest_fileno(FILE* f);
void rosetta_guest_getrandom(void* buf, size_t n);
/* [rosetta 补丁 0013] 零摆渡 guest 全局区(fork.md §5;用户定向
 * 2026-09-01):box64 的宿主 .bss 根变量经宏重定向(各消费点
 * 头部)落进本结构——结构住在 x64 快照页固定偏移(编译期常量
 * 寻址),guest 内存随 fork COW 自动全带,补丁 0012 的抄录/回种
 * 摆渡代码整类删除。**未来新增全局根变量 = 本结构加字段即享
 * COW**,无需任何新摆渡代码。地址与 shim fork_snap.h 对账
 * (kSnapPageAddr + kSnapGGOff,单事实源在彼)——改动必须双端
 * 同步。 */
#define ROSETTA_SNAP_PAGE_ADDR 0x6F000000UL /* fork_snap.h kSnapPageAddr */
#define ROSETTA_GG_OFF 0x400UL              /* fork_snap.h kSnapGGOff */
typedef struct box64context_s box64context_t;
typedef struct rosetta_box64_globals_s {
    void* memprot;        /* custommem rbtree 根(权限簿记) */
    void* mapallmem;      /* custommem rbtree 根(全域映射簿记) */
    void* blockstree;     /* custommem rbtree 根(块码区簿记) */
    void* rbt_dynmem;     /* custommem rbtree 根(dynarec arena) */
    void* lockaddress;    /* kh_lockaddress_t*(lock 前缀地址) */
    void* mmaplist;       /* mmaplist_t*(dynarec arena 清单) */
    void* my_alternates;  /* kh_alternate_t*(alternate 查找表) */
    box64context_t* my_context;
} rosetta_box64_globals_t;
#define ROSETTA_GG ((rosetta_box64_globals_t*)(ROSETTA_SNAP_PAGE_ADDR + ROSETTA_GG_OFF))

/* [rosetta 补丁 0012] fork 暖启动 adoption(fork.md §5 v15):
 * guest 侧 dynablock 链表(子壳 adoption 的遍历源;shim 实现;
 * in_jmptbl:主块 1(子壳再登记 jmptbl)/alt 块 0(仅 relocs)) */
void rosetta_x64_dblock_register(void* db, int in_jmptbl);
void rosetta_x64_dblock_unregister(void* db);
/* 进程本地初始化 + atfork 直调(实现 = custommem.c/box64context.c) */
void rosetta_custommem_init_tables(void);
void rosetta_custommem_atfork_child(void);
void rosetta_box64context_atfork_child(void);
/* [rosetta 补丁 0012] adoption 专用信号 helper(表保留;signals.c) */
void rosetta_init_signal_helper_adopt(box64context_t* context);
#endif
int InternalMunmap(void* addr, unsigned long length);

int GetTID(void);
int SchedYield(void);

void EmuX64Syscall(void* emu);
void EmuX64Syscall_linux(void* emu);
void EmuX86Syscall(void* emu);

void* GetSeg43Base(void* emu);
void* GetSegmentBase(void* emu, uint32_t desc);

// These functions only applies to Linux --------------------------
int IsBridgeSignature(char s, char c);
int IsNativeCall(uintptr_t addr, int is32bits, uintptr_t* calladdress, uint16_t* retn);
void EmuInt3(void* emu, void* addr);
void* EmuFork(void* emu, int forktype);

void PersonalityAddrLimit32Bit(void);

int IsAddrElfOrFileMapped(uintptr_t addr);
const char* GetNativeName(void* p, int lib);
const char* GetBridgeName(void* p);
// ----------------------------------------------------------------

#ifndef _WIN32
#include <setjmp.h>
#define LongJmp longjmp
#define SigSetJmp sigsetjmp
#else
#define LongJmp(a, b)
#define SigSetJmp(a, b) 0
#endif

#ifndef _WIN32
#include <setjmp.h>
#define NEW_JUMPBUFF(name) \
    static __thread JUMPBUFF name
#ifdef ANDROID
#define JUMPBUFF sigjmp_buf
#define GET_JUMPBUFF(name) name
#else
#define JUMPBUFF struct __jmp_buf_tag
#define GET_JUMPBUFF(name) &name
#endif
#else
#define JUMPBUFF int
#define NEW_JUMPBUFF(name)
#define GET_JUMPBUFF(name) NULL
#endif

#define PROT_READ  0x1
#define PROT_WRITE 0x2
#define PROT_EXEC  0x4

#if defined(__clang__) && !defined(_WIN32)
extern int isinff(float);
extern int isnanf(float);
#elif defined(_WIN32)
#define isnanf isnan
#define isinff isinf
#endif

void PrintfFtrace(int prefix, const char* fmt, ...);

void* GetEnv(const char* name);

#define IS_EXECUTABLE (1 << 0)
#define IS_FILE       (1 << 1)

// 0 : doesn't exist, 1: does exist.
int FileExist(const char* filename, int flags);
int MakeDir(const char* folder);    // return 1 for success, 0 else

#ifdef _WIN32
#define BOXFILE_BUFSIZE 4096
typedef struct {
    HANDLE hFile;
    char buffer[BOXFILE_BUFSIZE];
    size_t buf_pos;
    size_t buf_size;
    int eof;
} BOXFILE;

BOXFILE* box_fopen(const char* filename, const char* mode);
char* box_fgets(char* str, int num, BOXFILE* stream);
int box_fclose(BOXFILE* stream);
#else
#define BOXFILE    FILE
#define box_fopen  fopen
#define box_fgets  fgets
#define box_fclose fclose
#endif

#endif //__OS_H_
