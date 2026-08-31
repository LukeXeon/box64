#define _GNU_SOURCE
#include <sys/syscall.h>
#include <sched.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/personality.h>
#include <sys/stat.h>
#include <dlfcn.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/resource.h>
#include <malloc.h>

#include "os.h"
#include "signals.h"
#include "emu/x64int_private.h"
#include "bridge.h"
#include "elfloader.h"
#include "env.h"
#include "debug.h"
#include "x64tls.h"
#include "librarian.h"
#include "emu/x64emu_private.h"

int GetTID(void)
{
    return syscall(SYS_gettid);
}

int SchedYield(void)
{
    return sched_yield();
}

int IsBridgeSignature(char s, char c)
{
    return s == 'S' && c == 'C';
}

/* [rosetta 补丁 0002] 平台钩子四件在嵌入形态下由宿主(shim)自供:
 * syscall 出口走 rosetta 传输面(非宿主内核)、fork 走宿主
 * fail-loud(guest fork 语义归 gVisor)——上游实现依赖
 * x64syscall.c(未随嵌入式构建编入)且语义为宿主直通,保留则
 * 链接冲突且运行时语义错误。EmuInt3 保留上游(x64int3.c 随
 * 全量保留编译)。 */
void EmuInt3(void* emu, void* addr)
{
    return x64Int3((x64emu_t*)emu, (uintptr_t*)addr);
}

int IsNativeCall(uintptr_t addr, int is32bits, uintptr_t* calladdress, uint16_t* retn)
{
    return isNativeCallInternal(addr, is32bits, calladdress, retn);
}

#ifndef ROSETTA_EMBED
void* EmuFork(void* emu, int forktype)
{
    return x64emu_fork((x64emu_t*)emu, forktype);
}

void EmuX64Syscall(void* emu)
{
    x64Syscall((x64emu_t*)emu);
}

void EmuX64Syscall_linux(void* emu)
{
    x64Syscall_linux((x64emu_t*)emu);
}

void EmuX86Syscall(void* emu)
{
    x86Syscall((x64emu_t*)emu);
}
#endif

extern int box64_is32bits;

void* GetSeg43Base(void* emu)
{
    tlsdatasize_t* ptr = ((x64emu_t*)emu)->tlsdata;
    return ptr?ptr->data:NULL;
}

void* GetSegmentBase(void* emu, uint32_t desc)
{
    if (!desc) {
        printf_log(LOG_NONE, "Warning, accessing segment NULL\n");
        return NULL;
    }
    int base = desc >> 3;
    int is_ldt = !!(desc&4);
    if(!box64_nolibs) {
        if (!box64_is32bits && (base == 0x8) )
            return GetSeg43Base((x64emu_t*)emu);
        if (box64_is32bits && (base == 0x6))
            return GetSeg43Base((x64emu_t*)emu);
    }
    if (base > 15) {
        printf_log(LOG_NONE, "Warning, accessing segment unknown 0x%x or unset\n", desc);
        return NULL;
    }
    
    base_segment_t* segs = is_ldt?((x64emu_t*)emu)->segldt:((base>5)?((x64emu_t*)emu)->seggdt:my_context->seggdt);
    void* ptr = (void*)segs[base].base;
    return ptr;
}

const char* GetBridgeName(void* p)
{
    return getBridgeName(p);
}

static __thread char native_name[500] = { 0 };

const char* GetNativeName(void* p, int lib)
{
    {
        const char* n = GetBridgeName(p);
        if (n)
            return n;
    }
    Dl_info info;
    if (dladdr(p, &info) == 0) {
        const char* ret = GetNameOffset(my_context->maplib, p);
        if (ret)
            return ret;
        sprintf(native_name, "%s(%p)", "???", p);
        return native_name;
    } else {
        if (info.dli_sname) {
            strcpy(native_name, info.dli_sname);
            if (lib && info.dli_fname) {
                strcat(native_name, "(");
                strcat(native_name, info.dli_fname);
                strcat(native_name, ")");
            }
        } else {
            sprintf(native_name, "%s(%s+%p)", "???", info.dli_fname, (void*)(p - info.dli_fbase));
            return native_name;
        }
    }
    return native_name;
}


void PersonalityAddrLimit32Bit(void)
{
    personality(ADDR_LIMIT_32BIT);
    #ifndef ANDROID
    /*struct rlimit l;
    if(getrlimit(RLIMIT_DATA, &l)<0) return;  // failed
    if(l.rlim_max>3*1024*1024*1024LL) {
        l.rlim_cur = 3*1024*1024*1024LL;
        setrlimit(RLIMIT_DATA, &l);
    }*/
    // setting 32bits malloc options
    mallopt(M_ARENA_TEST, 2);
    mallopt(M_ARENA_MAX, 2);
    mallopt(M_MMAP_THRESHOLD, 128*1024);
    #endif
}

int IsAddrElfOrFileMapped(uintptr_t addr)
{
    return FindElfAddress(my_context, addr) || IsAddrFileMappedNoMemFD(addr);
}

void* InternalMmap(void* addr, unsigned long length, int prot, int flags, int fd, ssize_t offset)
{
#ifdef ROSETTA_EMBED
    /* [rosetta 补丁 0009] 全域钩:box64 的一切映射进 gVisor mm
     * (os.h 注释);fd/offset 直通(guest fd 语义) */
    return rosetta_guest_mmap(addr, length, prot, flags, fd, offset);
#else
    void* ret = (void*)syscall(__NR_mmap, addr, length, prot, flags, fd, offset);
    return ret;
#endif
}

int InternalMunmap(void* addr, unsigned long length)
{
#ifdef ROSETTA_EMBED
    /* [rosetta 补丁 0009] 同上 */
    return rosetta_guest_munmap(addr, length);
#else
    int ret = syscall(__NR_munmap, addr, length);
    return ret;
#endif
}

extern FILE* ftrace;
extern char* ftrace_name;
static int trace_fd = -1;

static void checkFtrace()
{
    trace_fd = fileno(ftrace);
    if (trace_fd < 0 || lseek(trace_fd, 0, SEEK_CUR) == (off_t)-1) {
        ftrace = fopen(ftrace_name, "a");
        trace_fd = fileno(ftrace);
        printf_log(LOG_INFO, "%04d|Recreated trace because fd was invalid\n", GetTID());
    }
}

void PrintfFtrace(int prefix, const char* fmt, ...)
{
    if (ftrace_name) {
        checkFtrace();
    } else if(trace_fd==-1)
        trace_fd = fileno(ftrace);
    // using a combinaison of (v)sprintf an write as it's re-entrant, not like (v)fprintf

    static const char* names[2] = { "BOX64", "BOX32" };

    char tmp[8192];

    if (prefix && (ftrace == stdout || ftrace == stderr)) {
        if (prefix > 1) {
            sprintf(tmp, "[\033[31m%s\033[0m] ", names[box64_is32bits]);
        } else {
            sprintf(tmp, "[%s] ", names[box64_is32bits]);
        }
        write(trace_fd, tmp, strlen(tmp));
    }
    va_list args;
    va_start(args, fmt);
    vsprintf(tmp, fmt, args);
    fflush(ftrace);
    va_end(args);
    write(trace_fd, tmp, strlen(tmp));
}

void* GetEnv(const char* name)
{
    return getenv(name);
}

int FileExist(const char* filename, int flags)
{
    struct stat sb;
    if (stat(filename, &sb) == -1)
        return 0;
    if (flags == -1)
        return 1;
    // check type of file? should be executable, or folder
    if (flags & IS_FILE) {
        if (!S_ISREG(sb.st_mode))
            return 0;
    } else if (!S_ISDIR(sb.st_mode))
        return 0;

    if (flags & IS_EXECUTABLE) {
        if ((sb.st_mode & S_IXUSR) != S_IXUSR)
            return 0; // nope
    }
    return 1;
}

int MakeDir(const char* folder)
{
    int ret = mkdir(folder, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
    if(!ret || ret==EEXIST)
        return 1;
    return 0;
}

size_t FileSize(const char* filename)
{
    struct stat sb;
    if (stat(filename, &sb) == -1)
        return 0;
    // check type of file? should be executable, or folder
    if (!S_ISREG(sb.st_mode))
        return 0;
    return sb.st_size;
}
