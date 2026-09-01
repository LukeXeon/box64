#include <stdlib.h>
#include <stddef.h>

#include "alternate.h"
#include "custommem.h"
#include "khash.h"
#ifdef DYNAREC
#include "box64context.h"
#include "bridge.h"
#endif
#include "debug.h"

// Alternate address handling
typedef struct {
    void* addr;
    #ifdef HAVE_ALTJUMP
    uintptr_t jump;
    void* data;
    #endif
} my_alternate_t;
KHASH_MAP_INIT_INT64(alternate, my_alternate_t)
#ifdef ROSETTA_EMBED
#include "os.h"
/* [rosetta 补丁 0013] 零摆渡:alternate 查找表根宏重定向进 GG
 * (os.h;表存储本在 guest 堆)——fork COW 自动全带,alt 机制
 * 子壳完整可用(P20 时的第八根遗漏由此整类消解) */
#define my_alternates (*((kh_alternate_t**)&ROSETTA_GG->my_alternates))
#else
static kh_alternate_t *my_alternates = NULL;
#endif

int hasAlternate(void* addr) {
    if(!my_alternates)
        return 0;
    khint_t k = kh_get(alternate, my_alternates, (uintptr_t)addr);
    if(k==kh_end(my_alternates))
        return 0;
    return 1;
}

void* getAlternate(void* addr) {
    if(!my_alternates)
        return addr;
    khint_t k = kh_get(alternate, my_alternates, (uintptr_t)addr);
    if(k!=kh_end(my_alternates))
        return kh_value(my_alternates, k).addr;
    return addr;
}
void addAlternate(void* addr, void* alt) {
    if(!my_alternates) {
        my_alternates = kh_init(alternate);
    }
    if(addr==alt)
        return; // nothing to do, alt is same as addr, but it's certainly an issue somewere!
    int ret;
    khint_t k = kh_put(alternate, my_alternates, (uintptr_t)addr, &ret);
    if(!ret)    // already there
        return;
    kh_value(my_alternates, k).addr = alt;
    #ifdef HAVE_ALTJUMP
    kh_value(my_alternates, k).jump = AddAltJump(my_context->alternates, (uintptr_t)addr, (uintptr_t)alt);
    #endif
}

void addCheckAlternate(void* addr, void* alt) {
    if(!hasAlternate(addr))
        addAlternate(addr, alt);
}

void cleanAlternate() {
    if(my_alternates) {
        kh_destroy(alternate, my_alternates);
        my_alternates = NULL;
    }
}

#ifdef HAVE_ALTJUMP
#include "bridge_private.h"
uintptr_t getAlternateJump(void* addr, int is32bits) {
    if(!my_alternates)
        return 0;
    khint_t k = kh_get(alternate, my_alternates, (uintptr_t)addr);
    if(k!=kh_end(my_alternates)) {
        uintptr_t ret = kh_value(my_alternates, k).jump;
        if(is32bits) ret += offsetof(onebridge_t, FF_2);
        return ret;
    }
    return 0;
}
void* getAlternateData(void* addr)
{
    if(!my_alternates)
        return (void*)-1LL;
    khint_t k = kh_get(alternate, my_alternates, (uintptr_t)addr);
    if(k!=kh_end(my_alternates)) {
        return kh_value(my_alternates, k).data;
    }
    return (void*)-1LL;
}
void setAlternateData(void* addr, void* data)
{
    if(!my_alternates)
        return;
    khint_t k = kh_get(alternate, my_alternates, (uintptr_t)addr);
    if(k!=kh_end(my_alternates)) {
        kh_value(my_alternates, k).data = data;
    }
}

#endif