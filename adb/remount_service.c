/*
 * Copyright (C) 2008 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/mount.h>
#include <errno.h>

#include "sysdeps.h"

#define  TRACE_TAG  TRACE_ADB
#include "adb.h"

static void write_string(int fd, const char* str)
{
    writex(fd, str, strlen(str));
}

static int system_ro = 1;

/* Returns the mount number of the requested partition from /proc/mtd */
static int find_mount(const char *findme)
{
    int fd;
    int res;
    int size;
    char *token = NULL;
    const char delims[] = "\n";
    char buf[1024];

    fd = unix_open("/proc/mtd", O_RDONLY);
    if (fd < 0)
        return -errno;

    buf[sizeof(buf) - 1] = '\0';
    size = adb_read(fd, buf, sizeof(buf) - 1);
    adb_close(fd);

    token = strtok(buf, delims);

    while (token) {
        char mtdname[16];
        int mtdnum, mtdsize, mtderasesize;

        res = sscanf(token, "mtd%d: %x %x %15s",
                     &mtdnum, &mtdsize, &mtderasesize, mtdname);

        if (res == 4 && !strcmp(mtdname, findme))
            return mtdnum;

        token = strtok(NULL, delims);
    }
    return -1;
}

static int find_mountpoint_and_remount(const char *findme)
{
    int fd;
    int res;
    int size;
    char *token = NULL;
    const char delims[] = "\n";
    char buf[1024];

    fd = unix_open("/proc/mounts", O_RDONLY);
    if (fd < 0)
        return -errno;

    buf[sizeof(buf) - 1] = '\0';
    size = adb_read(fd, buf, sizeof(buf) - 1);
    adb_close(fd);

    token = strtok(buf, delims);
    while (token) {
        char device[64];
        char fstype[16];
        char mountpoint[64];
        char mountoptions[64];
        int option1, option2;

        res = sscanf(token, "%63s %63s %15s %63s %d %d",
                     device, mountpoint, fstype, mountoptions, &option1, &option2);

        if (res == 6 && !strcmp(mountpoint, findme)) {
            system_ro = mount(device, mountpoint, fstype, MS_REMOUNT, NULL);
            return system_ro;
        }

        token = strtok(NULL, delims);
    }
    return -1;
}

/* Init mounts /system as read only, remount to enable writes. */
static int remount_system()
{
    int num;
    char source[64];
    if (system_ro == 0) {
        return 0;
    }
    num = find_mount("\"system\"");
    if (num >= 0) {
        snprintf(source, sizeof source, "/dev/block/mtdblock%d", num);
        system_ro = mount(source, "/system", "yaffs2", MS_REMOUNT, NULL);
    }

    /* Attempt a generic remount based on the existing mounts */
    if (system_ro)  {
        system_ro = find_mountpoint_and_remount("/system");
    }

    return system_ro;
}

void remount_service(int fd, void *cookie)
{
    int ret = remount_system();

    if (!ret)
       write_string(fd, "remount succeeded\n");
    else {
        char    buffer[200];
        snprintf(buffer, sizeof(buffer), "remount failed: %s\n", strerror(errno));
        write_string(fd, buffer);
    }

    adb_close(fd);
}

