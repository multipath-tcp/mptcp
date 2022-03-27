/*
 * Copyright (C) 2015 Texas Instruments
 * Author: Jyri Sarha <jsarha@ti.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 *
 */

#include <linux/component.h>
#include <linux/of_graph.h>
#include <drm/drm_of.h>

#include "tilcdc_drv.h"
#include "tilcdc_external.h"

static const struct tilcdc_panel_info panel_info_tda998x = {
		.ac_bias                = 255,
		.ac_bias_intrpt         = 0,
		.dma_burst_sz           = 16,
		.bpp                    = 16,
		.fdd                    = 0x80,
		.tft_alt_mode           = 0,
		.invert_pxl_clk		= 1,
		.sync_edge              = 1,
		.sync_ctrl              = 1,
		.raster_order           = 0,
};

static const struct tilcdc_panel_info panel_info_default = {
		.ac_bias                = 255,
		.ac_bias_intrpt         = 0,
		.dma_burst_sz           = 16,
		.bpp                    = 16,
		.fdd                    = 0x80,
		.tft_alt_mode           = 0,
		.sync_edge              = 0,
		.sync_ctrl              = 1,
		.raster_order           = 0,
};

static
struct drm_connector *tilcdc_encoder_find_connector(struct drm_device *ddev,
						    struct drm_encoder *encoder)
{
	struct drm_connector *connector;
	int i;

	list_for_each_entry(connector, &ddev->mode_config.connector_list, head)
		for (i = 0; i < DRM_CONNECTOR_MAX_ENCODER; i++)
			if (connector->encoder_ids[i] == encoder->base.id)
				return connector;

	dev_err(ddev->dev, "No connector found for %s encoder (id %d)\n",
		encoder->name, encoder->base.id);

	return NULL;
}

int tilcdc_add_component_encoder(struct drm_device *ddev)
{
	struct tilcdc_drm_private *priv = ddev->dev_private;
	struct drm_encoder *encoder = NULL, *iter;

	list_for_each_entry(iter, &ddev->mode_config.encoder_list, head)
		if (iter->possible_crtcs & (1 << priv->crtc->index)) {
			encoder = iter;
			break;
		}

	if (!encoder) {
		dev_err(ddev->dev, "%s: No suitable encoder found\n", __func__);
		return -ENODEV;
	}

	priv->external_connector =
		tilcdc_encoder_find_connector(ddev, encoder);

	if (!priv->external_connector)
		return -ENODEV;

	/* Only tda998x is supported at the moment. */
	tilcdc_crtc_set_simulate_vesa_sync(priv->crtc, true);
	tilcdc_crtc_set_panel_info(priv->crtc, &panel_info_tda998x);

	return 0;
}

static const struct drm_encoder_funcs tilcdc_external_encoder_funcs = {
	.destroy	= drm_encoder_cleanup,
};

static
int tilcdc_attach_bridge(struct drm_device *ddev, struct drm_bridge *bridge)
{
	struct tilcdc_drm_private *priv = ddev->dev_private;
	int ret;

	priv->external_encoder->possible_crtcs = BIT(0);

	ret = drm_bridge_attach(priv->external_encoder, bridge, NULL);
	if (ret) {
		dev_err(ddev->dev, "drm_bridge_attach() failed %d\n", ret);
		return ret;
	}

	tilcdc_crtc_set_panel_info(priv->crtc, &panel_info_default);

	priv->external_connector =
		tilcdc_encoder_find_connector(ddev, priv->external_encoder);
	if (!priv->external_connector)
		return -ENODEV;

	return 0;
}

int tilcdc_attach_external_device(struct drm_device *ddev)
{
	struct tilcdc_drm_private *priv = ddev->dev_private;
	struct device_node *remote_node;
	struct drm_bridge *bridge;
	int ret;

	remote_node = of_graph_get_remote_node(ddev->dev->of_node, 0, 0);
	if (!remote_node)
		return 0;

	bridge = of_drm_find_bridge(remote_node);
	of_node_put(remote_node);
	if (!bridge)
		return -EPROBE_DEFER;

	priv->external_encoder = devm_kzalloc(ddev->dev,
					      sizeof(*priv->external_encoder),
					      GFP_KERNEL);
	if (!priv->external_encoder)
		return -ENOMEM;

	ret = drm_encoder_init(ddev, priv->external_encoder,
			       &tilcdc_external_encoder_funcs,
			       DRM_MODE_ENCODER_NONE, NULL);
	if (ret) {
		dev_err(ddev->dev, "drm_encoder_init() failed %d\n", ret);
		return ret;
	}

	ret = tilcdc_attach_bridge(ddev, bridge);
	if (ret)
		drm_encoder_cleanup(priv->external_encoder);

	return ret;
}

static int dev_match_of(struct device *dev, void *data)
{
	return dev->of_node == data;
}

int tilcdc_get_external_components(struct device *dev,
				   struct component_match **match)
{
	struct device_node *node;

	node = of_graph_get_remote_node(dev->of_node, 0, 0);

	if (!of_device_is_compatible(node, "nxp,tda998x")) {
		of_node_put(node);
		return 0;
	}

	if (match)
		drm_of_component_match_add(dev, match, dev_match_of, node);
	of_node_put(node);
	return 1;
}
