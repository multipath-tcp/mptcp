/*
 * skl-tplg-interface.h - Intel DSP FW private data interface
 *
 * Copyright (C) 2015 Intel Corp
 * Author: Jeeja KP <jeeja.kp@intel.com>
 *	    Nilofer, Samreen <samreen.nilofer@intel.com>
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as version 2, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 */

#ifndef __HDA_TPLG_INTERFACE_H__
#define __HDA_TPLG_INTERFACE_H__

/*
 * Default types range from 0~12. type can range from 0 to 0xff
 * SST types start at higher to avoid any overlapping in future
 */
#define SOC_CONTROL_TYPE_HDA_SST_ALGO_PARAMS	0x100
#define SOC_CONTROL_TYPE_HDA_SST_MUX		0x101
#define SOC_CONTROL_TYPE_HDA_SST_MIX		0x101
#define SOC_CONTROL_TYPE_HDA_SST_BYTE		0x103

#define HDA_SST_CFG_MAX	900 /* size of copier cfg*/
#define MAX_IN_QUEUE 8
#define MAX_OUT_QUEUE 8

/* Event types goes here */
/* Reserve event type 0 for no event handlers */
enum skl_event_types {
	SKL_EVENT_NONE = 0,
	SKL_MIXER_EVENT,
	SKL_MUX_EVENT,
	SKL_VMIXER_EVENT,
	SKL_PGA_EVENT
};

/**
 * enum skl_ch_cfg - channel configuration
 *
 * @SKL_CH_CFG_MONO:	One channel only
 * @SKL_CH_CFG_STEREO:	L & R
 * @SKL_CH_CFG_2_1:	L, R & LFE
 * @SKL_CH_CFG_3_0:	L, C & R
 * @SKL_CH_CFG_3_1:	L, C, R & LFE
 * @SKL_CH_CFG_QUATRO:	L, R, Ls & Rs
 * @SKL_CH_CFG_4_0:	L, C, R & Cs
 * @SKL_CH_CFG_5_0:	L, C, R, Ls & Rs
 * @SKL_CH_CFG_5_1:	L, C, R, Ls, Rs & LFE
 * @SKL_CH_CFG_DUAL_MONO: One channel replicated in two
 * @SKL_CH_CFG_I2S_DUAL_STEREO_0: Stereo(L,R) in 4 slots, 1st stream:[ L, R, -, - ]
 * @SKL_CH_CFG_I2S_DUAL_STEREO_1: Stereo(L,R) in 4 slots, 2nd stream:[ -, -, L, R ]
 * @SKL_CH_CFG_INVALID:	Invalid
 */
enum skl_ch_cfg {
	SKL_CH_CFG_MONO = 0,
	SKL_CH_CFG_STEREO = 1,
	SKL_CH_CFG_2_1 = 2,
	SKL_CH_CFG_3_0 = 3,
	SKL_CH_CFG_3_1 = 4,
	SKL_CH_CFG_QUATRO = 5,
	SKL_CH_CFG_4_0 = 6,
	SKL_CH_CFG_5_0 = 7,
	SKL_CH_CFG_5_1 = 8,
	SKL_CH_CFG_DUAL_MONO = 9,
	SKL_CH_CFG_I2S_DUAL_STEREO_0 = 10,
	SKL_CH_CFG_I2S_DUAL_STEREO_1 = 11,
	SKL_CH_CFG_INVALID
};

enum skl_module_type {
	SKL_MODULE_TYPE_MIXER = 0,
	SKL_MODULE_TYPE_COPIER,
	SKL_MODULE_TYPE_UPDWMIX,
	SKL_MODULE_TYPE_SRCINT
};

enum skl_core_affinity {
	SKL_AFFINITY_CORE_0 = 0,
	SKL_AFFINITY_CORE_1,
	SKL_AFFINITY_CORE_MAX
};

enum skl_pipe_conn_type {
	SKL_PIPE_CONN_TYPE_NONE = 0,
	SKL_PIPE_CONN_TYPE_FE,
	SKL_PIPE_CONN_TYPE_BE
};

enum skl_hw_conn_type {
	SKL_CONN_NONE = 0,
	SKL_CONN_SOURCE = 1,
	SKL_CONN_SINK = 2
};

enum skl_dev_type {
	SKL_DEVICE_BT = 0x0,
	SKL_DEVICE_DMIC = 0x1,
	SKL_DEVICE_I2S = 0x2,
	SKL_DEVICE_SLIMBUS = 0x3,
	SKL_DEVICE_HDALINK = 0x4,
	SKL_DEVICE_HDAHOST = 0x5,
	SKL_DEVICE_NONE
};

struct skl_dfw_module_pin {
	u16 module_id;
	u16 instance_id;
} __packed;

struct skl_dfw_module_fmt {
	u32 channels;
	u32 freq;
	u32 bit_depth;
	u32 valid_bit_depth;
	u32 ch_cfg;
} __packed;

struct skl_dfw_module_caps {
	u32 caps_size;
	u32 caps[HDA_SST_CFG_MAX];
};

struct skl_dfw_pipe {
	u8 pipe_id;
	u8 pipe_priority;
	u16 conn_type;
	u32 memory_pages;
} __packed;

struct skl_dfw_module {
	u16 module_id;
	u16 instance_id;
	u32 max_mcps;
	u8 core_id;
	u8 max_in_queue;
	u8 max_out_queue;
	u8 is_loadable;
	u8 conn_type;
	u8 dev_type;
	u8 hw_conn_type;
	u8 time_slot;
	u32 obs;
	u32 ibs;
	u32 params_fixup;
	u32 converter;
	u32 module_type;
	u32 vbus_id;
	u8 is_dynamic_in_pin;
	u8 is_dynamic_out_pin;
	struct skl_dfw_pipe pipe;
	struct skl_dfw_module_fmt in_fmt;
	struct skl_dfw_module_fmt out_fmt;
	struct skl_dfw_module_pin in_pin[MAX_IN_QUEUE];
	struct skl_dfw_module_pin out_pin[MAX_OUT_QUEUE];
	struct skl_dfw_module_caps caps;
} __packed;

struct skl_dfw_algo_data {
	u32 max;
	char *params;
} __packed;

#endif
