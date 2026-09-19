#include <stdint.h>
#include <stdio.h>
#include <stddef.h>
#include <string.h>

#include "box32_inputevent.h"
#include "debug.h"
#include "box32.h"

#ifndef MAX_PATH
#define MAX_PATH 4096
#endif

#define NEVENTS 64
#if 0
static int n_event_path = 0;
static char* event_path[NEVENTS] = {0};
#endif
static int n_event_fd = 0;
static int event_fd[NEVENTS] = {-1};

void addInputEventFD(int fd)
{
    if(fd<0) return;
    /* [rosetta 补丁 0021] 跨境缓冲落 **guest 堆**(readlink 过桥面)。 */
    char* fullname = (char*)box_malloc(MAX_PATH);
    char* buf = (char*)box_malloc(128);
    if(!fullname || !buf) { box_free(fullname); box_free(buf); return; }
    fullname[0] = 0;
    sprintf(buf, "/proc/self/fd/%d", fd);
    ssize_t r = readlink(buf, fullname, MAX_PATH - 1);
    if(r<0) { box_free(fullname); box_free(buf); return; }
    fullname[r] = 0;
    #define INPUT_EVENT "/dev/input/event"
    if(strstr(fullname, INPUT_EVENT)==fullname)
        if(n_event_fd<NEVENTS) {
            event_fd[n_event_fd++] = fd;
        }
    box_free(fullname);
    box_free(buf);
}

void removeInputEventFD(int fd)
{
    for(int i=0; i<n_event_fd; ++i)
        if(event_fd[i]==fd) {
            event_fd[i] = -1;
            if(n_event_fd==i+1)
                --n_event_fd;
            return;
        }
}

int isFDInputEvent(int fd)
{
    for(int i=0; i<n_event_fd; ++i)
        if(event_fd[i]==fd)
            return 1;
    return 0;
}