/*
 *  skl-pcm.c -ASoC HDA Platform driver file implementing PCM functionality
 *
 *  Copyright (C) 2014-2015 Intel Corp
 *  Author:  Jeeja KP <jeeja.kp@intel.com>
 *
 *  ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; version 2 of the License.
 *
 *  This program is distributed in the hope that it will be useful, but
 *  WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  General Public License for more details.
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *
 */

#include <linux/pci.h>
#include <linux/pm_runtime.h>
#include <sound/pcm_params.h>
#include <sound/soc.h>
#include "skl.h"
#include "skl-topology.h"

#define HDA_MONO 1
#define HDA_STEREO 2

static struct snd_pcm_hardware azx_pcm_hw = {
	.info =			(SNDRV_PCM_INFO_MMAP |
				 SNDRV_PCM_INFO_INTERLEAVED |
				 SNDRV_PCM_INFO_BLOCK_TRANSFER |
				 SNDRV_PCM_INFO_MMAP_VALID |
				 SNDRV_PCM_INFO_PAUSE |
				 SNDRV_PCM_INFO_SYNC_START |
				 SNDRV_PCM_INFO_HAS_WALL_CLOCK | /* legacy */
				 SNDRV_PCM_INFO_HAS_LINK_ATIME |
				 SNDRV_PCM_INFO_NO_PERIOD_WAKEUP),
	.formats =		SNDRV_PCM_FMTBIT_S16_LE,
	.rates =		SNDRV_PCM_RATE_48000,
	.rate_min =		48000,
	.rate_max =		48000,
	.channels_min =		2,
	.channels_max =		2,
	.buffer_bytes_max =	AZX_MAX_BUF_SIZE,
	.period_bytes_min =	128,
	.period_bytes_max =	AZX_MAX_BUF_SIZE / 2,
	.periods_min =		2,
	.periods_max =		AZX_MAX_FRAG,
	.fifo_size =		0,
};

static inline
struct hdac_ext_stream *get_hdac_ext_stream(struct snd_pcm_substream *substream)
{
	return substream->runtime->private_data;
}

static struct hdac_ext_bus *get_bus_ctx(struct snd_pcm_substream *substream)
{
	struct hdac_ext_stream *stream = get_hdac_ext_stream(substream);
	struct hdac_stream *hstream = hdac_stream(stream);
	struct hdac_bus *bus = hstream->bus;

	return hbus_to_ebus(bus);
}

static int skl_substream_alloc_pages(struct hdac_ext_bus *ebus,
				 struct snd_pcm_substream *substream,
				 size_t size)
{
	struct hdac_ext_stream *stream = get_hdac_ext_stream(substream);

	hdac_stream(stream)->bufsize = 0;
	hdac_stream(stream)->period_bytes = 0;
	hdac_stream(stream)->format_val = 0;

	return snd_pcm_lib_malloc_pages(substream, size);
}

static int skl_substream_free_pages(struct hdac_bus *bus,
				struct snd_pcm_substream *substream)
{
	return snd_pcm_lib_free_pages(substream);
}

static void skl_set_pcm_constrains(struct hdac_ext_bus *ebus,
				 struct snd_pcm_runtime *runtime)
{
	snd_pcm_hw_constraint_integer(runtime, SNDRV_PCM_HW_PARAM_PERIODS);

	/* avoid wrap-around with wall-clock */
	snd_pcm_hw_constraint_minmax(runtime, SNDRV_PCM_HW_PARAM_BUFFER_TIME,
				     20, 178000000);
}

static enum hdac_ext_stream_type skl_get_host_stream_type(struct hdac_ext_bus *ebus)
{
	if (ebus->ppcap)
		return HDAC_EXT_STREAM_TYPE_HOST;
	else
		return HDAC_EXT_STREAM_TYPE_COUPLED;
}

static int skl_pcm_open(struct snd_pcm_substream *substream,
		struct snd_soc_dai *dai)
{
	struct hdac_ext_bus *ebus = dev_get_drvdata(dai->dev);
	struct hdac_ext_stream *stream;
	struct snd_pcm_runtime *runtime = substream->runtime;
	struct skl_dma_params *dma_params;
	int ret;

	dev_dbg(dai->dev, "%s: %s\n", __func__, dai->name);
	ret = pm_runtime_get_sync(dai->dev);
	if (ret < 0)
		return ret;

	stream = snd_hdac_ext_stream_assign(ebus, substream,
					skl_get_host_stream_type(ebus));
	if (stream == NULL)
		return -EBUSY;

	skl_set_pcm_constrains(ebus, runtime);

	/*
	 * disable WALLCLOCK timestamps for capture streams
	 * until we figure out how to handle digital inputs
	 */
	if (substream->stream == SNDRV_PCM_STREAM_CAPTURE) {
		runtime->hw.info &= ~SNDRV_PCM_INFO_HAS_WALL_CLOCK; /* legacy */
		runtime->hw.info &= ~SNDRV_PCM_INFO_HAS_LINK_ATIME;
	}

	runtime->private_data = stream;

	dma_params = kzalloc(sizeof(*dma_params), GFP_KERNEL);
	if (!dma_params)
		return -ENOMEM;

	dma_params->stream_tag = hdac_stream(stream)->stream_tag;
	snd_soc_dai_set_dma_data(dai, substream, dma_params);

	dev_dbg(dai->dev, "stream tag set in dma params=%d\n",
				 dma_params->stream_tag);
	snd_pcm_set_sync(substream);

	return 0;
}

static int skl_get_format(struct snd_pcm_substream *substream,
		struct snd_soc_dai *dai)
{
	struct snd_soc_pcm_runtime *rtd = snd_pcm_substream_chip(substream);
	struct skl_dma_params *dma_params;
	struct hdac_ext_bus *ebus = dev_get_drvdata(dai->dev);
	int format_val = 0;

	if (ebus->ppcap) {
		struct snd_pcm_runtime *runtime = substream->runtime;

		format_val = snd_hdac_calc_stream_format(runtime->rate,
						runtime->channels,
						runtime->format,
						32, 0);
	} else {
		struct snd_soc_dai *codec_dai = rtd->codec_dai;

		dma_params = snd_soc_dai_get_dma_data(codec_dai, substream);
		if (dma_params)
			format_val = dma_params->format;
	}

	return format_val;
}

static int skl_pcm_prepare(struct snd_pcm_substream *substream,
		struct snd_soc_dai *dai)
{
	struct hdac_ext_stream *stream = get_hdac_ext_stream(substream);
	unsigned int format_val;
	int err;

	dev_dbg(dai->dev, "%s: %s\n", __func__, dai->name);
	if (hdac_stream(stream)->prepared) {
		dev_dbg(dai->dev, "already stream is prepared - returning\n");
		return 0;
	}

	format_val = skl_get_format(substream, dai);
	dev_dbg(dai->dev, "stream_tag=%d formatvalue=%d\n",
				hdac_stream(stream)->stream_tag, format_val);
	snd_hdac_stream_reset(hdac_stream(stream));

	err = snd_hdac_stream_set_params(hdac_stream(stream), format_val);
	if (err < 0)
		return err;

	err = snd_hdac_stream_setup(hdac_stream(stream));
	if (err < 0)
		return err;

	hdac_stream(stream)->prepared = 1;

	return err;
}

static int skl_pcm_hw_params(struct snd_pcm_substream *substream,
				struct snd_pcm_hw_params *params,
				struct snd_soc_dai *dai)
{
	struct hdac_ext_bus *ebus = dev_get_drvdata(dai->dev);
	struct hdac_ext_stream *stream = get_hdac_ext_stream(substream);
	struct snd_pcm_runtime *runtime = substream->runtime;
	struct skl_pipe_params p_params = {0};
	struct skl_module_cfg *m_cfg;
	int ret, dma_id;

	dev_dbg(dai->dev, "%s: %s\n", __func__, dai->name);
	ret = skl_substream_alloc_pages(ebus, substream,
					  params_buffer_bytes(params));
	if (ret < 0)
		return ret;

	dev_dbg(dai->dev, "format_val, rate=%d, ch=%d, format=%d\n",
			runtime->rate, runtime->channels, runtime->format);

	dma_id = hdac_stream(stream)->stream_tag - 1;
	dev_dbg(dai->dev, "dma_id=%d\n", dma_id);

	p_params.s_fmt = snd_pcm_format_width(params_format(params));
	p_params.ch = params_channels(params);
	p_params.s_freq = params_rate(params);
	p_params.host_dma_id = dma_id;
	p_params.stream = substream->stream;

	m_cfg = skl_tplg_fe_get_cpr_module(dai, p_params.stream);
	if (m_cfg)
		skl_tplg_update_pipe_params(dai->dev, m_cfg, &p_params);

	return 0;
}

static void skl_pcm_close(struct snd_pcm_substream *substream,
		struct snd_soc_dai *dai)
{
	struct hdac_ext_stream *stream = get_hdac_ext_stream(substream);
	struct hdac_ext_bus *ebus = dev_get_drvdata(dai->dev);
	struct skl_dma_params *dma_params = NULL;

	dev_dbg(dai->dev, "%s: %s\n", __func__, dai->name);

	snd_hdac_ext_stream_release(stream, skl_get_host_stream_type(ebus));

	dma_params = snd_soc_dai_get_dma_data(dai, substream);
	/*
	 * now we should set this to NULL as we are freeing by the
	 * dma_params
	 */
	snd_soc_dai_set_dma_data(dai, substream, NULL);

	pm_runtime_mark_last_busy(dai->dev);
	pm_runtime_put_autosuspend(dai->dev);
	kfree(dma_params);
}

static int skl_pcm_hw_free(struct snd_pcm_substream *substream,
		struct snd_soc_dai *dai)
{
	struct hdac_ext_bus *ebus = dev_get_drvdata(dai->dev);
	struct hdac_ext_stream *stream = get_hdac_ext_stream(substream);

	dev_dbg(dai->dev, "%s: %s\n", __func__, dai->name);

	snd_hdac_stream_cleanup(hdac_stream(stream));
	hdac_stream(stream)->prepared = 0;

	return skl_substream_free_pages(ebus_to_hbus(ebus), substream);
}

static int skl_be_hw_params(struct snd_pcm_substream *substream,
				struct snd_pcm_hw_params *params,
				struct snd_soc_dai *dai)
{
	struct skl_pipe_params p_params = {0};

	p_params.s_fmt = snd_pcm_format_width(params_format(params));
	p_params.ch = params_channels(params);
	p_params.s_freq = params_rate(params);
	p_params.stream = substream->stream;
	skl_tplg_be_update_params(dai, &p_params);

	return 0;
}

static int skl_pcm_trigger(struct snd_pcm_substream *substream, int cmd,
		struct snd_soc_dai *dai)
{
	struct skl *skl = get_skl_ctx(dai->dev);
	struct skl_sst *ctx = skl->skl_sst;
	struct skl_module_cfg *mconfig;

	mconfig = skl_tplg_fe_get_cpr_module(dai, substream->stream);
	if (!mconfig)
		return -EIO;

	switch (cmd) {
	case SNDRV_PCM_TRIGGER_PAUSE_RELEASE:
	case SNDRV_PCM_TRIGGER_RESUME:
		return skl_run_pipe(ctx, mconfig->pipe);

	case SNDRV_PCM_TRIGGER_PAUSE_PUSH:
	case SNDRV_PCM_TRIGGER_SUSPEND:
		return skl_stop_pipe(ctx, mconfig->pipe);

	default:
		return 0;
	}
}

static int skl_link_hw_params(struct snd_pcm_substream *substream,
				struct snd_pcm_hw_params *params,
				struct snd_soc_dai *dai)
{
	struct hdac_ext_bus *ebus = dev_get_drvdata(dai->dev);
	struct hdac_ext_stream *link_dev;
	struct snd_soc_pcm_runtime *rtd = snd_pcm_substream_chip(substream);
	struct skl_dma_params *dma_params;
	struct snd_soc_dai *codec_dai = rtd->codec_dai;
	struct skl_pipe_params p_params = {0};

	link_dev = snd_hdac_ext_stream_assign(ebus, substream,
					HDAC_EXT_STREAM_TYPE_LINK);
	if (!link_dev)
		return -EBUSY;

	snd_soc_dai_set_dma_data(dai, substream, (void *)link_dev);

	/* set the stream tag in the codec dai dma params  */
	dma_params = (struct skl_dma_params *)
			snd_soc_dai_get_dma_data(codec_dai, substream);
	if (dma_params)
		dma_params->stream_tag =  hdac_stream(link_dev)->stream_tag;
	snd_soc_dai_set_dma_data(codec_dai, substream, (void *)dma_params);

	p_params.s_fmt = snd_pcm_format_width(params_format(params));
	p_params.ch = params_channels(params);
	p_params.s_freq = params_rate(params);
	p_params.stream = substream->stream;
	p_params.link_dma_id = hdac_stream(link_dev)->stream_tag - 1;

	skl_tplg_be_update_params(dai, &p_params);

	return 0;
}

static int skl_link_pcm_prepare(struct snd_pcm_substream *substream,
		struct snd_soc_dai *dai)
{
	struct snd_soc_pcm_runtime *rtd = snd_pcm_substream_chip(substream);
	struct hdac_ext_bus *ebus = dev_get_drvdata(dai->dev);
	struct hdac_ext_stream *link_dev =
			snd_soc_dai_get_dma_data(dai, substream);
	unsigned int format_val = 0;
	struct skl_dma_params *dma_params;
	struct snd_soc_dai *codec_dai = rtd->codec_dai;
	struct hdac_ext_link *link;

	if (link_dev->link_prepared) {
		dev_dbg(dai->dev, "already stream is prepared - returning\n");
		return 0;
	}

	dma_params  = (struct skl_dma_params *)
			snd_soc_dai_get_dma_data(codec_dai, substream);
	if (dma_params)
		format_val = dma_params->format;
	dev_dbg(dai->dev, "stream_tag=%d formatvalue=%d codec_dai_name=%s\n",
			hdac_stream(link_dev)->stream_tag, format_val, codec_dai->name);

	snd_hdac_ext_link_stream_reset(link_dev);

	snd_hdac_ext_link_stream_setup(link_dev, format_val);

	link = snd_hdac_ext_bus_get_link(ebus, rtd->codec->component.name);
	if (!link)
		return -EINVAL;

	snd_hdac_ext_link_set_stream_id(link, hdac_stream(link_dev)->stream_tag);
	link_dev->link_prepared = 1;

	return 0;
}

static int skl_link_pcm_trigger(struct snd_pcm_substream *substream,
	int cmd, struct snd_soc_dai *dai)
{
	struct hdac_ext_stream *link_dev =
				snd_soc_dai_get_dma_data(dai, substream);

	dev_dbg(dai->dev, "In %s cmd=%d\n", __func__, cmd);
	switch (cmd) {
	case SNDRV_PCM_TRIGGER_START:
	case SNDRV_PCM_TRIGGER_PAUSE_RELEASE:
	case SNDRV_PCM_TRIGGER_RESUME:
		snd_hdac_ext_link_stream_start(link_dev);
		break;

	case SNDRV_PCM_TRIGGER_PAUSE_PUSH:
	case SNDRV_PCM_TRIGGER_SUSPEND:
	case SNDRV_PCM_TRIGGER_STOP:
		snd_hdac_ext_link_stream_clear(link_dev);
		break;

	default:
		return -EINVAL;
	}
	return 0;
}

static int skl_link_hw_free(struct snd_pcm_substream *substream,
		struct snd_soc_dai *dai)
{
	struct hdac_ext_bus *ebus = dev_get_drvdata(dai->dev);
	struct snd_soc_pcm_runtime *rtd = snd_pcm_substream_chip(substream);
	struct hdac_ext_stream *link_dev =
				snd_soc_dai_get_dma_data(dai, substream);
	struct hdac_ext_link *link;

	dev_dbg(dai->dev, "%s: %s\n", __func__, dai->name);

	link_dev->link_prepared = 0;

	link = snd_hdac_ext_bus_get_link(ebus, rtd->codec->component.name);
	if (!link)
		return -EINVAL;

	snd_hdac_ext_link_clear_stream_id(link, hdac_stream(link_dev)->stream_tag);
	snd_hdac_ext_stream_release(link_dev, HDAC_EXT_STREAM_TYPE_LINK);
	return 0;
}

static int skl_be_startup(struct snd_pcm_substream *substream,
		struct snd_soc_dai *dai)
{
	return pm_runtime_get_sync(dai->dev);
}

static void skl_be_shutdown(struct snd_pcm_substream *substream,
		struct snd_soc_dai *dai)
{
	pm_runtime_mark_last_busy(dai->dev);
	pm_runtime_put_autosuspend(dai->dev);
}

static struct snd_soc_dai_ops skl_pcm_dai_ops = {
	.startup = skl_pcm_open,
	.shutdown = skl_pcm_close,
	.prepare = skl_pcm_prepare,
	.hw_params = skl_pcm_hw_params,
	.hw_free = skl_pcm_hw_free,
	.trigger = skl_pcm_trigger,
};

static struct snd_soc_dai_ops skl_dmic_dai_ops = {
	.startup = skl_be_startup,
	.hw_params = skl_be_hw_params,
	.shutdown = skl_be_shutdown,
};

static struct snd_soc_dai_ops skl_be_ssp_dai_ops = {
	.startup = skl_be_startup,
	.hw_params = skl_be_hw_params,
	.shutdown = skl_be_shutdown,
};

static struct snd_soc_dai_ops skl_link_dai_ops = {
	.startup = skl_be_startup,
	.prepare = skl_link_pcm_prepare,
	.hw_params = skl_link_hw_params,
	.hw_free = skl_link_hw_free,
	.trigger = skl_link_pcm_trigger,
	.shutdown = skl_be_shutdown,
};

static struct snd_soc_dai_driver skl_platform_dai[] = {
{
	.name = "System Pin",
	.ops = &skl_pcm_dai_ops,
	.playback = {
		.stream_name = "System Playback",
		.channels_min = HDA_MONO,
		.channels_max = HDA_STEREO,
		.rates = SNDRV_PCM_RATE_48000 | SNDRV_PCM_RATE_16000 | SNDRV_PCM_RATE_8000,
		.formats = SNDRV_PCM_FMTBIT_S16_LE | SNDRV_PCM_FMTBIT_S24_LE,
	},
	.capture = {
		.stream_name = "System Capture",
		.channels_min = HDA_MONO,
		.channels_max = HDA_STEREO,
		.rates = SNDRV_PCM_RATE_48000 | SNDRV_PCM_RATE_16000,
		.formats = SNDRV_PCM_FMTBIT_S16_LE | SNDRV_PCM_FMTBIT_S24_LE,
	},
},
{
	.name = "Reference Pin",
	.ops = &skl_pcm_dai_ops,
	.capture = {
		.stream_name = "Reference Capture",
		.channels_min = HDA_MONO,
		.channels_max = HDA_STEREO,
		.rates = SNDRV_PCM_RATE_48000 | SNDRV_PCM_RATE_16000,
		.formats = SNDRV_PCM_FMTBIT_S16_LE | SNDRV_PCM_FMTBIT_S24_LE,
	},
},
{
	.name = "Deepbuffer Pin",
	.ops = &skl_pcm_dai_ops,
	.playback = {
		.stream_name = "Deepbuffer Playback",
		.channels_min = HDA_STEREO,
		.channels_max = HDA_STEREO,
		.rates = SNDRV_PCM_RATE_48000,
		.formats = SNDRV_PCM_FMTBIT_S16_LE | SNDRV_PCM_FMTBIT_S24_LE,
	},
},
{
	.name = "LowLatency Pin",
	.ops = &skl_pcm_dai_ops,
	.playback = {
		.stream_name = "Low Latency Playback",
		.channels_min = HDA_STEREO,
		.channels_max = HDA_STEREO,
		.rates = SNDRV_PCM_RATE_48000,
		.formats = SNDRV_PCM_FMTBIT_S16_LE | SNDRV_PCM_FMTBIT_S24_LE,
	},
},
/* BE CPU  Dais */
{
	.name = "SSP0 Pin",
	.ops = &skl_be_ssp_dai_ops,
	.playback = {
		.stream_name = "ssp0 Tx",
		.channels_min = HDA_STEREO,
		.channels_max = HDA_STEREO,
		.rates = SNDRV_PCM_RATE_48000,
		.formats = SNDRV_PCM_FMTBIT_S16_LE,
	},
	.capture = {
		.stream_name = "ssp0 Rx",
		.channels_min = HDA_STEREO,
		.channels_max = HDA_STEREO,
		.rates = SNDRV_PCM_RATE_48000,
		.formats = SNDRV_PCM_FMTBIT_S16_LE,
	},
},
{
	.name = "iDisp Pin",
	.ops = &skl_link_dai_ops,
	.playback = {
		.stream_name = "iDisp Tx",
		.channels_min = HDA_STEREO,
		.channels_max = HDA_STEREO,
		.rates = SNDRV_PCM_RATE_8000|SNDRV_PCM_RATE_16000|SNDRV_PCM_RATE_48000,
		.formats = SNDRV_PCM_FMTBIT_S16_LE,
	},
},
{
	.name = "DMIC01 Pin",
	.ops = &skl_dmic_dai_ops,
	.capture = {
		.stream_name = "DMIC01 Rx",
		.channels_min = HDA_STEREO,
		.channels_max = HDA_STEREO,
		.rates = SNDRV_PCM_RATE_48000 | SNDRV_PCM_RATE_16000,
		.formats = SNDRV_PCM_FMTBIT_S16_LE | SNDRV_PCM_FMTBIT_S24_LE,
	},
},
{
	.name = "HD-Codec Pin",
	.ops = &skl_link_dai_ops,
	.playback = {
		.stream_name = "HD-Codec Tx",
		.channels_min = HDA_STEREO,
		.channels_max = HDA_STEREO,
		.rates = SNDRV_PCM_RATE_48000,
		.formats = SNDRV_PCM_FMTBIT_S16_LE,
	},
	.capture = {
		.stream_name = "HD-Codec Rx",
		.channels_min = HDA_STEREO,
		.channels_max = HDA_STEREO,
		.rates = SNDRV_PCM_RATE_48000,
		.formats = SNDRV_PCM_FMTBIT_S16_LE,
	},
},
};

static int skl_platform_open(struct snd_pcm_substream *substream)
{
	struct snd_pcm_runtime *runtime;
	struct snd_soc_pcm_runtime *rtd = substream->private_data;
	struct snd_soc_dai_link *dai_link = rtd->dai_link;

	dev_dbg(rtd->cpu_dai->dev, "In %s:%s\n", __func__,
					dai_link->cpu_dai_name);

	runtime = substream->runtime;
	snd_soc_set_runtime_hwparams(substream, &azx_pcm_hw);

	return 0;
}

static int skl_coupled_trigger(struct snd_pcm_substream *substream,
					int cmd)
{
	struct hdac_ext_bus *ebus = get_bus_ctx(substream);
	struct hdac_bus *bus = ebus_to_hbus(ebus);
	struct hdac_ext_stream *stream;
	struct snd_pcm_substream *s;
	bool start;
	int sbits = 0;
	unsigned long cookie;
	struct hdac_stream *hstr;

	stream = get_hdac_ext_stream(substream);
	hstr = hdac_stream(stream);

	dev_dbg(bus->dev, "In %s cmd=%d\n", __func__, cmd);

	if (!hstr->prepared)
		return -EPIPE;

	switch (cmd) {
	case SNDRV_PCM_TRIGGER_START:
	case SNDRV_PCM_TRIGGER_PAUSE_RELEASE:
	case SNDRV_PCM_TRIGGER_RESUME:
		start = true;
		break;

	case SNDRV_PCM_TRIGGER_PAUSE_PUSH:
	case SNDRV_PCM_TRIGGER_SUSPEND:
	case SNDRV_PCM_TRIGGER_STOP:
		start = false;
		break;

	default:
		return -EINVAL;
	}

	snd_pcm_group_for_each_entry(s, substream) {
		if (s->pcm->card != substream->pcm->card)
			continue;
		stream = get_hdac_ext_stream(s);
		sbits |= 1 << hdac_stream(stream)->index;
		snd_pcm_trigger_done(s, substream);
	}

	spin_lock_irqsave(&bus->reg_lock, cookie);

	/* first, set SYNC bits of corresponding streams */
	snd_hdac_stream_sync_trigger(hstr, true, sbits, AZX_REG_SSYNC);

	snd_pcm_group_for_each_entry(s, substream) {
		if (s->pcm->card != substream->pcm->card)
			continue;
		stream = get_hdac_ext_stream(s);
		if (start)
			snd_hdac_stream_start(hdac_stream(stream), true);
		else
			snd_hdac_stream_stop(hdac_stream(stream));
	}
	spin_unlock_irqrestore(&bus->reg_lock, cookie);

	snd_hdac_stream_sync(hstr, start, sbits);

	spin_lock_irqsave(&bus->reg_lock, cookie);

	/* reset SYNC bits */
	snd_hdac_stream_sync_trigger(hstr, false, sbits, AZX_REG_SSYNC);
	if (start)
		snd_hdac_stream_timecounter_init(hstr, sbits);
	spin_unlock_irqrestore(&bus->reg_lock, cookie);

	return 0;
}

static int skl_decoupled_trigger(struct snd_pcm_substream *substream,
		int cmd)
{
	struct hdac_ext_bus *ebus = get_bus_ctx(substream);
	struct hdac_bus *bus = ebus_to_hbus(ebus);
	struct snd_soc_pcm_runtime *rtd = snd_pcm_substream_chip(substream);
	struct snd_soc_dai *cpu_dai = rtd->cpu_dai;
	struct hdac_ext_stream *stream;
	int start;
	unsigned long cookie;
	struct hdac_stream *hstr;

	dev_dbg(bus->dev, "In %s cmd=%d streamname=%s\n", __func__, cmd, cpu_dai->name);

	stream = get_hdac_ext_stream(substream);
	hstr = hdac_stream(stream);

	if (!hstr->prepared)
		return -EPIPE;

	switch (cmd) {
	case SNDRV_PCM_TRIGGER_START:
	case SNDRV_PCM_TRIGGER_PAUSE_RELEASE:
	case SNDRV_PCM_TRIGGER_RESUME:
		start = 1;
		break;

	case SNDRV_PCM_TRIGGER_PAUSE_PUSH:
	case SNDRV_PCM_TRIGGER_SUSPEND:
	case SNDRV_PCM_TRIGGER_STOP:
		start = 0;
		break;

	default:
		return -EINVAL;
	}

	spin_lock_irqsave(&bus->reg_lock, cookie);

	if (start)
		snd_hdac_stream_start(hdac_stream(stream), true);
	else
		snd_hdac_stream_stop(hdac_stream(stream));

	if (start)
		snd_hdac_stream_timecounter_init(hstr, 0);

	spin_unlock_irqrestore(&bus->reg_lock, cookie);

	return 0;
}
static int skl_platform_pcm_trigger(struct snd_pcm_substream *substream,
					int cmd)
{
	struct hdac_ext_bus *ebus = get_bus_ctx(substream);

	if (ebus->ppcap)
		return skl_decoupled_trigger(substream, cmd);
	else
		return skl_coupled_trigger(substream, cmd);
}

/* calculate runtime delay from LPIB */
static int skl_get_delay_from_lpib(struct hdac_ext_bus *ebus,
				struct hdac_ext_stream *sstream,
				unsigned int pos)
{
	struct hdac_bus *bus = ebus_to_hbus(ebus);
	struct hdac_stream *hstream = hdac_stream(sstream);
	struct snd_pcm_substream *substream = hstream->substream;
	int stream = substream->stream;
	unsigned int lpib_pos = snd_hdac_stream_get_pos_lpib(hstream);
	int delay;

	if (stream == SNDRV_PCM_STREAM_PLAYBACK)
		delay = pos - lpib_pos;
	else
		delay = lpib_pos - pos;

	if (delay < 0) {
		if (delay >= hstream->delay_negative_threshold)
			delay = 0;
		else
			delay += hstream->bufsize;
	}

	if (delay >= hstream->period_bytes) {
		dev_info(bus->dev,
			 "Unstable LPIB (%d >= %d); disabling LPIB delay counting\n",
			 delay, hstream->period_bytes);
		delay = 0;
	}

	return bytes_to_frames(substream->runtime, delay);
}

static unsigned int skl_get_position(struct hdac_ext_stream *hstream,
					int codec_delay)
{
	struct hdac_stream *hstr = hdac_stream(hstream);
	struct snd_pcm_substream *substream = hstr->substream;
	struct hdac_ext_bus *ebus = get_bus_ctx(substream);
	unsigned int pos;
	int delay;

	/* use the position buffer as default */
	pos = snd_hdac_stream_get_pos_posbuf(hdac_stream(hstream));

	if (pos >= hdac_stream(hstream)->bufsize)
		pos = 0;

	if (substream->runtime) {
		delay = skl_get_delay_from_lpib(ebus, hstream, pos)
						 + codec_delay;
		substream->runtime->delay += delay;
	}

	return pos;
}

static snd_pcm_uframes_t skl_platform_pcm_pointer
			(struct snd_pcm_substream *substream)
{
	struct hdac_ext_stream *hstream = get_hdac_ext_stream(substream);

	return bytes_to_frames(substream->runtime,
			       skl_get_position(hstream, 0));
}

static u64 skl_adjust_codec_delay(struct snd_pcm_substream *substream,
				u64 nsec)
{
	struct snd_soc_pcm_runtime *rtd = snd_pcm_substream_chip(substream);
	struct snd_soc_dai *codec_dai = rtd->codec_dai;
	u64 codec_frames, codec_nsecs;

	if (!codec_dai->driver->ops->delay)
		return nsec;

	codec_frames = codec_dai->driver->ops->delay(substream, codec_dai);
	codec_nsecs = div_u64(codec_frames * 1000000000LL,
			      substream->runtime->rate);

	if (substream->stream == SNDRV_PCM_STREAM_CAPTURE)
		return nsec + codec_nsecs;

	return (nsec > codec_nsecs) ? nsec - codec_nsecs : 0;
}

static int skl_get_time_info(struct snd_pcm_substream *substream,
			struct timespec *system_ts, struct timespec *audio_ts,
			struct snd_pcm_audio_tstamp_config *audio_tstamp_config,
			struct snd_pcm_audio_tstamp_report *audio_tstamp_report)
{
	struct hdac_ext_stream *sstream = get_hdac_ext_stream(substream);
	struct hdac_stream *hstr = hdac_stream(sstream);
	u64 nsec;

	if ((substream->runtime->hw.info & SNDRV_PCM_INFO_HAS_LINK_ATIME) &&
		(audio_tstamp_config->type_requested == SNDRV_PCM_AUDIO_TSTAMP_TYPE_LINK)) {

		snd_pcm_gettime(substream->runtime, system_ts);

		nsec = timecounter_read(&hstr->tc);
		nsec = div_u64(nsec, 3); /* can be optimized */
		if (audio_tstamp_config->report_delay)
			nsec = skl_adjust_codec_delay(substream, nsec);

		*audio_ts = ns_to_timespec(nsec);

		audio_tstamp_report->actual_type = SNDRV_PCM_AUDIO_TSTAMP_TYPE_LINK;
		audio_tstamp_report->accuracy_report = 1; /* rest of struct is valid */
		audio_tstamp_report->accuracy = 42; /* 24MHzWallClk == 42ns resolution */

	} else {
		audio_tstamp_report->actual_type = SNDRV_PCM_AUDIO_TSTAMP_TYPE_DEFAULT;
	}

	return 0;
}

static struct snd_pcm_ops skl_platform_ops = {
	.open = skl_platform_open,
	.ioctl = snd_pcm_lib_ioctl,
	.trigger = skl_platform_pcm_trigger,
	.pointer = skl_platform_pcm_pointer,
	.get_time_info =  skl_get_time_info,
	.mmap = snd_pcm_lib_default_mmap,
	.page = snd_pcm_sgbuf_ops_page,
};

static void skl_pcm_free(struct snd_pcm *pcm)
{
	snd_pcm_lib_preallocate_free_for_all(pcm);
}

#define MAX_PREALLOC_SIZE	(32 * 1024 * 1024)

static int skl_pcm_new(struct snd_soc_pcm_runtime *rtd)
{
	struct snd_soc_dai *dai = rtd->cpu_dai;
	struct hdac_ext_bus *ebus = dev_get_drvdata(dai->dev);
	struct snd_pcm *pcm = rtd->pcm;
	unsigned int size;
	int retval = 0;
	struct skl *skl = ebus_to_skl(ebus);

	if (dai->driver->playback.channels_min ||
		dai->driver->capture.channels_min) {
		/* buffer pre-allocation */
		size = CONFIG_SND_HDA_PREALLOC_SIZE * 1024;
		if (size > MAX_PREALLOC_SIZE)
			size = MAX_PREALLOC_SIZE;
		retval = snd_pcm_lib_preallocate_pages_for_all(pcm,
						SNDRV_DMA_TYPE_DEV_SG,
						snd_dma_pci_data(skl->pci),
						size, MAX_PREALLOC_SIZE);
		if (retval) {
			dev_err(dai->dev, "dma buffer allocationf fail\n");
			return retval;
		}
	}

	return retval;
}

static int skl_platform_soc_probe(struct snd_soc_platform *platform)
{
	struct hdac_ext_bus *ebus = dev_get_drvdata(platform->dev);

	if (ebus->ppcap)
		return skl_tplg_init(platform, ebus);

	return 0;
}
static struct snd_soc_platform_driver skl_platform_drv  = {
	.probe		= skl_platform_soc_probe,
	.ops		= &skl_platform_ops,
	.pcm_new	= skl_pcm_new,
	.pcm_free	= skl_pcm_free,
};

static const struct snd_soc_component_driver skl_component = {
	.name           = "pcm",
};

int skl_platform_register(struct device *dev)
{
	int ret;
	struct hdac_ext_bus *ebus = dev_get_drvdata(dev);
	struct skl *skl = ebus_to_skl(ebus);

	INIT_LIST_HEAD(&skl->ppl_list);
	INIT_LIST_HEAD(&skl->dapm_path_list);

	ret = snd_soc_register_platform(dev, &skl_platform_drv);
	if (ret) {
		dev_err(dev, "soc platform registration failed %d\n", ret);
		return ret;
	}
	ret = snd_soc_register_component(dev, &skl_component,
				skl_platform_dai,
				ARRAY_SIZE(skl_platform_dai));
	if (ret) {
		dev_err(dev, "soc component registration failed %d\n", ret);
		snd_soc_unregister_platform(dev);
	}

	return ret;

}

int skl_platform_unregister(struct device *dev)
{
	snd_soc_unregister_component(dev);
	snd_soc_unregister_platform(dev);
	return 0;
}
