/*
 * Copyright © 2014 Intel Corporation
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next
 * paragraph) shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#ifndef _I915_COMPONENT_H_
#define _I915_COMPONENT_H_

/* MAX_PORT is the number of port
 * It must be sync with I915_MAX_PORTS defined i915_drv.h
 * 5 should be enough as only HSW, BDW, SKL need such fix.
 */
#define MAX_PORTS 5

/**
 * struct i915_audio_component_ops - callbacks defined in gfx driver
 * @owner: the module owner
 * @get_power: get the POWER_DOMAIN_AUDIO power well
 * @put_power: put the POWER_DOMAIN_AUDIO power well
 * @codec_wake_override: Enable/Disable generating the codec wake signal
 * @get_cdclk_freq: get the Core Display Clock in KHz
 * @sync_audio_rate: set n/cts based on the sample rate
 */
struct i915_audio_component_ops {
	struct module *owner;
	void (*get_power)(struct device *);
	void (*put_power)(struct device *);
	void (*codec_wake_override)(struct device *, bool enable);
	int (*get_cdclk_freq)(struct device *);
	int (*sync_audio_rate)(struct device *, int port, int rate);
};

struct i915_audio_component_audio_ops {
	void *audio_ptr;
	/**
	 * Call from i915 driver, notifying the HDA driver that
	 * pin sense and/or ELD information has changed.
	 * @audio_ptr:		HDA driver object
	 * @port:	Which port has changed (PORTA / PORTB / PORTC etc)
	 */
	void (*pin_eld_notify)(void *audio_ptr, int port);
};

/**
 * struct i915_audio_component - used for audio video interaction
 * @dev: the device from gfx driver
 * @aud_sample_rate: the array of audio sample rate per port
 * @ops: callback for audio driver calling
 * @audio_ops: Call from i915 driver
 */
struct i915_audio_component {
	struct device *dev;
	int aud_sample_rate[MAX_PORTS];

	const struct i915_audio_component_ops *ops;

	const struct i915_audio_component_audio_ops *audio_ops;
};

#endif /* _I915_COMPONENT_H_ */
