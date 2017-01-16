/*
 *  Copyright © 2014 Broadcom
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/seq_file.h>
#include <linux/circ_buf.h>
#include <linux/ctype.h>
#include <linux/debugfs.h>
#include <drm/drmP.h>

#include "vc4_drv.h"
#include "vc4_regs.h"

static const struct drm_info_list vc4_debugfs_list[] = {
	{"hdmi_regs", vc4_hdmi_debugfs_regs, 0},
	{"hvs_regs", vc4_hvs_debugfs_regs, 0},
	{"crtc0_regs", vc4_crtc_debugfs_regs, 0, (void *)(uintptr_t)0},
	{"crtc1_regs", vc4_crtc_debugfs_regs, 0, (void *)(uintptr_t)1},
	{"crtc2_regs", vc4_crtc_debugfs_regs, 0, (void *)(uintptr_t)2},
};

#define VC4_DEBUGFS_ENTRIES ARRAY_SIZE(vc4_debugfs_list)

int
vc4_debugfs_init(struct drm_minor *minor)
{
	return drm_debugfs_create_files(vc4_debugfs_list, VC4_DEBUGFS_ENTRIES,
					minor->debugfs_root, minor);
}

void
vc4_debugfs_cleanup(struct drm_minor *minor)
{
	drm_debugfs_remove_files(vc4_debugfs_list, VC4_DEBUGFS_ENTRIES, minor);
}
