# Copyright 2011 The Android Open Source Project

LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

LOCAL_SRC_FILES:= fscheck.c

LOCAL_MODULE:= libfscheck
LOCAL_STATIC_LIBRARIES := liblogwrap
LOCAL_CFLAGS := -Werror

include $(BUILD_STATIC_LIBRARY)

