/*
 * Copyright (C) 2012 The Android Open Source Project
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

#define LOG_TAG "libfscheck"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <libgen.h>
#include <time.h>
#include <sys/swap.h>
#include <dirent.h>

#include <linux/loop.h>
#include <private/android_filesystem_config.h>
#include <cutils/android_reboot.h>
#include <cutils/partition_utils.h>
#include <cutils/properties.h>
#include <logwrap/logwrap.h>
#include <malloc.h>

#include "fscheck_api.h"

#include <cutils/klog.h>
#define ERROR(x...)   KLOG_ERROR("fscheck", x)

static int fscheck_open_device()
{
    char devpath[PROPERTY_VALUE_MAX] = {'\0'};
    if (property_get("ro.fscheck.device", devpath, NULL) > 0) {
        int fd = open(devpath, O_RDWR|O_CLOEXEC, 0600);
        if (fd < 0) {
            ERROR("%s fail to open %s\n", __func__, devpath);
            return -1;
        }

        off_t devsize = lseek(fd, 0, SEEK_END);
        if (devsize < FSCHECK_BLOB_SIZE) {
            ERROR("%s: %s size (%lu) too small, %d at least\n", __func__, devpath,
                    devsize, FSCHECK_BLOB_SIZE);
            close(fd);
            return -1;
        }
        // Blob is at end of the partition
        lseek(fd, devsize-FSCHECK_BLOB_SIZE, SEEK_SET);
        return fd;
    } else {
        return -1;
    }
}


FscheckBlob *fscheck_get_blob()
{
    int fd = fscheck_open_device();
    if (fd < 0) {
        return NULL;
    }

    FscheckBlob *blob = (FscheckBlob*)malloc(sizeof(FscheckBlob));
    if (!blob) {
        close(fd);
        return NULL;
    }

    size_t size = sizeof(FscheckBlob);
    while (size > 0) {
        int n = read(fd, blob, sizeof(FscheckBlob));
        size -= n;
    }

    if (strcmp(blob->signature, (const char*)FSCHECK_BLOB_SIGNATURE)) {
        // signaturen not match, initialize it
        memset(blob, 0, sizeof(FscheckBlob));
        strcpy(blob->signature, (const char*)FSCHECK_BLOB_SIGNATURE);
        blob->size = sizeof(FscheckBlob);
        blob->fstype = FSCHECK_BLOB_FSTYPE_UNKNOWN;
        blob->stage = FSCHECK_BLOB_STAGE_INITIALIZED;
        blob->fstab[0] = '\0';
    }

    return blob;
}

int fscheck_set_fstab_path(FscheckBlob *blob, const char *path)
{
    if (!blob || !path) {
        return -1;
    }

    if (strlen(path) > FSCHECK_BLOB_FSTAB_FILE_LEN) {
        ERROR("%s file path too long(%d), at most %d\n", __func__, (int)strlen(path),
                FSCHECK_BLOB_FSTAB_FILE_LEN);
        return -1;
    }

    strcpy(blob->fstab, path);

    return 0;
}

void fscheck_free_blob(FscheckBlob *blob)
{
    if (blob) {
        free(blob);
    }
}

int fscheck_write_blob(FscheckBlob *blob)
{
    if (!blob) {
        return -1;
    }

    int fd = fscheck_open_device();
    if (fd < 0) {
        return -1;
    }

    write(fd, blob, blob->size);

    return 0;
}

int fscheck_clear_blob()
{
    int fd = fscheck_open_device();
    if (fd < 0) {
        return -1;
    }

    FscheckBlob blob;
    memset((char*)&blob, 0, sizeof(blob));
    write(fd, &blob, sizeof(blob));

    return 0;
}

void fscheck_print(FscheckBlob *blob)
{
    if (!blob) {
        return;
    }

    ERROR("signature: %s\n", blob->signature);
    ERROR("size: %d\n", blob->size);
    ERROR("fstype = %d\n", blob->fstype);
    ERROR("stage = %d\n", blob->stage);
    ERROR("fstab = %s\n", blob->fstab);
}

