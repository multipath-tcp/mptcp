/*
 * Copyright (C) 2014-2015 Broadcom
 * Copyright (C) 2013 Red Hat
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/clk.h>
#include <linux/component.h>
#include <linux/device.h>
#include <linux/io.h>
#include <linux/module.h>
#include <linux/of_platform.h>
#include <linux/platform_device.h>
#include "drm_fb_cma_helper.h"

#include "vc4_drv.h"
#include "vc4_regs.h"

#define DRIVER_NAME "vc4"
#define DRIVER_DESC "Broadcom VC4 graphics"
#define DRIVER_DATE "20140616"
#define DRIVER_MAJOR 0
#define DRIVER_MINOR 0
#define DRIVER_PATCHLEVEL 0

/* Helper function for mapping the regs on a platform device. */
void __iomem *vc4_ioremap_regs(struct platform_device *dev, int index)
{
	struct resource *res;
	void __iomem *map;

	res = platform_get_resource(dev, IORESOURCE_MEM, index);
	map = devm_ioremap_resource(&dev->dev, res);
	if (IS_ERR(map)) {
		DRM_ERROR("Failed to map registers: %ld\n", PTR_ERR(map));
		return map;
	}

	return map;
}

static void vc4_drm_preclose(struct drm_device *dev, struct drm_file *file)
{
	struct drm_crtc *crtc;

	list_for_each_entry(crtc, &dev->mode_config.crtc_list, head)
		vc4_cancel_page_flip(crtc, file);
}

static void vc4_lastclose(struct drm_device *dev)
{
	struct vc4_dev *vc4 = to_vc4_dev(dev);

	if (vc4->fbdev)
		drm_fbdev_cma_restore_mode(vc4->fbdev);
}

static const struct file_operations vc4_drm_fops = {
	.owner = THIS_MODULE,
	.open = drm_open,
	.release = drm_release,
	.unlocked_ioctl = drm_ioctl,
	.mmap = drm_gem_cma_mmap,
	.poll = drm_poll,
	.read = drm_read,
#ifdef CONFIG_COMPAT
	.compat_ioctl = drm_compat_ioctl,
#endif
	.llseek = noop_llseek,
};

static const struct drm_ioctl_desc vc4_drm_ioctls[] = {
};

static struct drm_driver vc4_drm_driver = {
	.driver_features = (DRIVER_MODESET |
			    DRIVER_ATOMIC |
			    DRIVER_GEM |
			    DRIVER_PRIME),
	.lastclose = vc4_lastclose,
	.preclose = vc4_drm_preclose,

	.enable_vblank = vc4_enable_vblank,
	.disable_vblank = vc4_disable_vblank,
	.get_vblank_counter = drm_vblank_count,

#if defined(CONFIG_DEBUG_FS)
	.debugfs_init = vc4_debugfs_init,
	.debugfs_cleanup = vc4_debugfs_cleanup,
#endif

	.gem_free_object = drm_gem_cma_free_object,
	.gem_vm_ops = &drm_gem_cma_vm_ops,

	.prime_handle_to_fd = drm_gem_prime_handle_to_fd,
	.prime_fd_to_handle = drm_gem_prime_fd_to_handle,
	.gem_prime_import = drm_gem_prime_import,
	.gem_prime_export = drm_gem_prime_export,
	.gem_prime_get_sg_table	= drm_gem_cma_prime_get_sg_table,
	.gem_prime_import_sg_table = drm_gem_cma_prime_import_sg_table,
	.gem_prime_vmap = drm_gem_cma_prime_vmap,
	.gem_prime_vunmap = drm_gem_cma_prime_vunmap,
	.gem_prime_mmap = drm_gem_cma_prime_mmap,

	.dumb_create = vc4_dumb_create,
	.dumb_map_offset = drm_gem_cma_dumb_map_offset,
	.dumb_destroy = drm_gem_dumb_destroy,

	.ioctls = vc4_drm_ioctls,
	.num_ioctls = ARRAY_SIZE(vc4_drm_ioctls),
	.fops = &vc4_drm_fops,

	.name = DRIVER_NAME,
	.desc = DRIVER_DESC,
	.date = DRIVER_DATE,
	.major = DRIVER_MAJOR,
	.minor = DRIVER_MINOR,
	.patchlevel = DRIVER_PATCHLEVEL,
};

static int compare_dev(struct device *dev, void *data)
{
	return dev == data;
}

static void vc4_match_add_drivers(struct device *dev,
				  struct component_match **match,
				  struct platform_driver *const *drivers,
				  int count)
{
	int i;

	for (i = 0; i < count; i++) {
		struct device_driver *drv = &drivers[i]->driver;
		struct device *p = NULL, *d;

		while ((d = bus_find_device(&platform_bus_type, p, drv,
					    (void *)platform_bus_type.match))) {
			put_device(p);
			component_match_add(dev, match, compare_dev, d);
			p = d;
		}
		put_device(p);
	}
}

static int vc4_drm_bind(struct device *dev)
{
	struct platform_device *pdev = to_platform_device(dev);
	struct drm_device *drm;
	struct drm_connector *connector;
	struct vc4_dev *vc4;
	int ret = 0;

	dev->coherent_dma_mask = DMA_BIT_MASK(32);

	vc4 = devm_kzalloc(dev, sizeof(*vc4), GFP_KERNEL);
	if (!vc4)
		return -ENOMEM;

	drm = drm_dev_alloc(&vc4_drm_driver, dev);
	if (!drm)
		return -ENOMEM;
	platform_set_drvdata(pdev, drm);
	vc4->dev = drm;
	drm->dev_private = vc4;

	drm_dev_set_unique(drm, dev_name(dev));

	drm_mode_config_init(drm);
	if (ret)
		goto unref;

	ret = component_bind_all(dev, drm);
	if (ret)
		goto unref;

	ret = drm_dev_register(drm, 0);
	if (ret < 0)
		goto unbind_all;

	/* Connector registration has to occur after DRM device
	 * registration, because it creates sysfs entries based on the
	 * DRM device.
	 */
	list_for_each_entry(connector, &drm->mode_config.connector_list, head) {
		ret = drm_connector_register(connector);
		if (ret)
			goto unregister;
	}

	vc4_kms_load(drm);

	return 0;

unregister:
	drm_dev_unregister(drm);
unbind_all:
	component_unbind_all(dev, drm);
unref:
	drm_dev_unref(drm);
	return ret;
}

static void vc4_drm_unbind(struct device *dev)
{
	struct platform_device *pdev = to_platform_device(dev);
	struct drm_device *drm = platform_get_drvdata(pdev);
	struct vc4_dev *vc4 = to_vc4_dev(drm);

	if (vc4->fbdev)
		drm_fbdev_cma_fini(vc4->fbdev);

	drm_mode_config_cleanup(drm);

	drm_put_dev(drm);
}

static const struct component_master_ops vc4_drm_ops = {
	.bind = vc4_drm_bind,
	.unbind = vc4_drm_unbind,
};

static struct platform_driver *const component_drivers[] = {
	&vc4_hdmi_driver,
	&vc4_crtc_driver,
	&vc4_hvs_driver,
};

static int vc4_platform_drm_probe(struct platform_device *pdev)
{
	struct component_match *match = NULL;
	struct device *dev = &pdev->dev;

	vc4_match_add_drivers(dev, &match,
			      component_drivers, ARRAY_SIZE(component_drivers));

	return component_master_add_with_match(dev, &vc4_drm_ops, match);
}

static int vc4_platform_drm_remove(struct platform_device *pdev)
{
	component_master_del(&pdev->dev, &vc4_drm_ops);

	return 0;
}

static const struct of_device_id vc4_of_match[] = {
	{ .compatible = "brcm,bcm2835-vc4", },
	{},
};
MODULE_DEVICE_TABLE(of, vc4_of_match);

static struct platform_driver vc4_platform_driver = {
	.probe		= vc4_platform_drm_probe,
	.remove		= vc4_platform_drm_remove,
	.driver		= {
		.name	= "vc4-drm",
		.of_match_table = vc4_of_match,
	},
};

static int __init vc4_drm_register(void)
{
	int i, ret;

	for (i = 0; i < ARRAY_SIZE(component_drivers); i++) {
		ret = platform_driver_register(component_drivers[i]);
		if (ret) {
			while (--i >= 0)
				platform_driver_unregister(component_drivers[i]);
			return ret;
		}
	}
	return platform_driver_register(&vc4_platform_driver);
}

static void __exit vc4_drm_unregister(void)
{
	int i;

	for (i = ARRAY_SIZE(component_drivers) - 1; i >= 0; i--)
		platform_driver_unregister(component_drivers[i]);

	platform_driver_unregister(&vc4_platform_driver);
}

module_init(vc4_drm_register);
module_exit(vc4_drm_unregister);

MODULE_ALIAS("platform:vc4-drm");
MODULE_DESCRIPTION("Broadcom VC4 DRM Driver");
MODULE_AUTHOR("Eric Anholt <eric@anholt.net>");
MODULE_LICENSE("GPL v2");
