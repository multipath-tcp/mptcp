// SPDX-License-Identifier: GPL-2.0+
/*
 * PCI Express Hot Plug Controller Driver
 *
 * Copyright (C) 1995,2001 Compaq Computer Corporation
 * Copyright (C) 2001 Greg Kroah-Hartman (greg@kroah.com)
 * Copyright (C) 2001 IBM Corp.
 * Copyright (C) 2003-2004 Intel Corporation
 *
 * All rights reserved.
 *
 * Send feedback to <greg@kroah.com>, <kristen.c.accardi@intel.com>
 *
 * Authors:
 *   Dan Zink <dan.zink@compaq.com>
 *   Greg Kroah-Hartman <greg@kroah.com>
 *   Dely Sy <dely.l.sy@intel.com>"
 */

#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/pci.h>
#include "pciehp.h"
#include <linux/interrupt.h>
#include <linux/time.h>

#include "../pci.h"

/* Global variables */
bool pciehp_debug;
bool pciehp_poll_mode;
int pciehp_poll_time;

/*
 * not really modular, but the easiest way to keep compat with existing
 * bootargs behaviour is to continue using module_param here.
 */
module_param(pciehp_debug, bool, 0644);
module_param(pciehp_poll_mode, bool, 0644);
module_param(pciehp_poll_time, int, 0644);
MODULE_PARM_DESC(pciehp_debug, "Debugging mode enabled or not");
MODULE_PARM_DESC(pciehp_poll_mode, "Using polling mechanism for hot-plug events or not");
MODULE_PARM_DESC(pciehp_poll_time, "Polling mechanism frequency, in seconds");

#define PCIE_MODULE_NAME "pciehp"

static int set_attention_status(struct hotplug_slot *slot, u8 value);
static int enable_slot(struct hotplug_slot *slot);
static int disable_slot(struct hotplug_slot *slot);
static int get_power_status(struct hotplug_slot *slot, u8 *value);
static int get_attention_status(struct hotplug_slot *slot, u8 *value);
static int get_latch_status(struct hotplug_slot *slot, u8 *value);
static int get_adapter_status(struct hotplug_slot *slot, u8 *value);
static int reset_slot(struct hotplug_slot *slot, int probe);

static int init_slot(struct controller *ctrl)
{
	struct slot *slot = ctrl->slot;
	struct hotplug_slot *hotplug = NULL;
	struct hotplug_slot_info *info = NULL;
	struct hotplug_slot_ops *ops = NULL;
	char name[SLOT_NAME_SIZE];
	int retval = -ENOMEM;

	hotplug = kzalloc(sizeof(*hotplug), GFP_KERNEL);
	if (!hotplug)
		goto out;

	info = kzalloc(sizeof(*info), GFP_KERNEL);
	if (!info)
		goto out;

	/* Setup hotplug slot ops */
	ops = kzalloc(sizeof(*ops), GFP_KERNEL);
	if (!ops)
		goto out;

	ops->enable_slot = enable_slot;
	ops->disable_slot = disable_slot;
	ops->get_power_status = get_power_status;
	ops->get_adapter_status = get_adapter_status;
	ops->reset_slot = reset_slot;
	if (MRL_SENS(ctrl))
		ops->get_latch_status = get_latch_status;
	if (ATTN_LED(ctrl)) {
		ops->get_attention_status = get_attention_status;
		ops->set_attention_status = set_attention_status;
	} else if (ctrl->pcie->port->hotplug_user_indicators) {
		ops->get_attention_status = pciehp_get_raw_indicator_status;
		ops->set_attention_status = pciehp_set_raw_indicator_status;
	}

	/* register this slot with the hotplug pci core */
	hotplug->info = info;
	hotplug->private = slot;
	hotplug->ops = ops;
	slot->hotplug_slot = hotplug;
	snprintf(name, SLOT_NAME_SIZE, "%u", PSN(ctrl));

	retval = pci_hp_initialize(hotplug,
				   ctrl->pcie->port->subordinate, 0, name);
	if (retval)
		ctrl_err(ctrl, "pci_hp_initialize failed: error %d\n", retval);
out:
	if (retval) {
		kfree(ops);
		kfree(info);
		kfree(hotplug);
	}
	return retval;
}

static void cleanup_slot(struct controller *ctrl)
{
	struct hotplug_slot *hotplug_slot = ctrl->slot->hotplug_slot;

	pci_hp_destroy(hotplug_slot);
	kfree(hotplug_slot->ops);
	kfree(hotplug_slot->info);
	kfree(hotplug_slot);
}

/*
 * set_attention_status - Turns the Amber LED for a slot on, off or blink
 */
static int set_attention_status(struct hotplug_slot *hotplug_slot, u8 status)
{
	struct slot *slot = hotplug_slot->private;
	struct pci_dev *pdev = slot->ctrl->pcie->port;

	pci_config_pm_runtime_get(pdev);
	pciehp_set_attention_status(slot, status);
	pci_config_pm_runtime_put(pdev);
	return 0;
}


static int enable_slot(struct hotplug_slot *hotplug_slot)
{
	struct slot *slot = hotplug_slot->private;

	return pciehp_sysfs_enable_slot(slot);
}


static int disable_slot(struct hotplug_slot *hotplug_slot)
{
	struct slot *slot = hotplug_slot->private;

	return pciehp_sysfs_disable_slot(slot);
}

static int get_power_status(struct hotplug_slot *hotplug_slot, u8 *value)
{
	struct slot *slot = hotplug_slot->private;
	struct pci_dev *pdev = slot->ctrl->pcie->port;

	pci_config_pm_runtime_get(pdev);
	pciehp_get_power_status(slot, value);
	pci_config_pm_runtime_put(pdev);
	return 0;
}

static int get_attention_status(struct hotplug_slot *hotplug_slot, u8 *value)
{
	struct slot *slot = hotplug_slot->private;

	pciehp_get_attention_status(slot, value);
	return 0;
}

static int get_latch_status(struct hotplug_slot *hotplug_slot, u8 *value)
{
	struct slot *slot = hotplug_slot->private;
	struct pci_dev *pdev = slot->ctrl->pcie->port;

	pci_config_pm_runtime_get(pdev);
	pciehp_get_latch_status(slot, value);
	pci_config_pm_runtime_put(pdev);
	return 0;
}

static int get_adapter_status(struct hotplug_slot *hotplug_slot, u8 *value)
{
	struct slot *slot = hotplug_slot->private;
	struct pci_dev *pdev = slot->ctrl->pcie->port;

	pci_config_pm_runtime_get(pdev);
	pciehp_get_adapter_status(slot, value);
	pci_config_pm_runtime_put(pdev);
	return 0;
}

static int reset_slot(struct hotplug_slot *hotplug_slot, int probe)
{
	struct slot *slot = hotplug_slot->private;

	return pciehp_reset_slot(slot, probe);
}

/**
 * pciehp_check_presence() - synthesize event if presence has changed
 *
 * On probe and resume, an explicit presence check is necessary to bring up an
 * occupied slot or bring down an unoccupied slot.  This can't be triggered by
 * events in the Slot Status register, they may be stale and are therefore
 * cleared.  Secondly, sending an interrupt for "events that occur while
 * interrupt generation is disabled [when] interrupt generation is subsequently
 * enabled" is optional per PCIe r4.0, sec 6.7.3.4.
 */
static void pciehp_check_presence(struct controller *ctrl)
{
	struct slot *slot = ctrl->slot;
	u8 occupied;

	down_read_nested(&ctrl->reset_lock, ctrl->depth);
	mutex_lock(&slot->lock);

	pciehp_get_adapter_status(slot, &occupied);
	if ((occupied && (slot->state == OFF_STATE ||
			  slot->state == BLINKINGON_STATE)) ||
	    (!occupied && (slot->state == ON_STATE ||
			   slot->state == BLINKINGOFF_STATE)))
		pciehp_request(ctrl, PCI_EXP_SLTSTA_PDC);

	mutex_unlock(&slot->lock);
	up_read(&ctrl->reset_lock);
}

static int pciehp_probe(struct pcie_device *dev)
{
	int rc;
	struct controller *ctrl;
	struct slot *slot;

	/* If this is not a "hotplug" service, we have no business here. */
	if (dev->service != PCIE_PORT_SERVICE_HP)
		return -ENODEV;

	if (!dev->port->subordinate) {
		/* Can happen if we run out of bus numbers during probe */
		dev_err(&dev->device,
			"Hotplug bridge without secondary bus, ignoring\n");
		return -ENODEV;
	}

	ctrl = pcie_init(dev);
	if (!ctrl) {
		dev_err(&dev->device, "Controller initialization failed\n");
		return -ENODEV;
	}
	set_service_data(dev, ctrl);

	/* Setup the slot information structures */
	rc = init_slot(ctrl);
	if (rc) {
		if (rc == -EBUSY)
			ctrl_warn(ctrl, "Slot already registered by another hotplug driver\n");
		else
			ctrl_err(ctrl, "Slot initialization failed (%d)\n", rc);
		goto err_out_release_ctlr;
	}

	/* Enable events after we have setup the data structures */
	rc = pcie_init_notification(ctrl);
	if (rc) {
		ctrl_err(ctrl, "Notification initialization failed (%d)\n", rc);
		goto err_out_free_ctrl_slot;
	}

	/* Publish to user space */
	slot = ctrl->slot;
	rc = pci_hp_add(slot->hotplug_slot);
	if (rc) {
		ctrl_err(ctrl, "Publication to user space failed (%d)\n", rc);
		goto err_out_shutdown_notification;
	}

	pciehp_check_presence(ctrl);

	return 0;

err_out_shutdown_notification:
	pcie_shutdown_notification(ctrl);
err_out_free_ctrl_slot:
	cleanup_slot(ctrl);
err_out_release_ctlr:
	pciehp_release_ctrl(ctrl);
	return -ENODEV;
}

static void pciehp_remove(struct pcie_device *dev)
{
	struct controller *ctrl = get_service_data(dev);

	pci_hp_del(ctrl->slot->hotplug_slot);
	pcie_shutdown_notification(ctrl);
	cleanup_slot(ctrl);
	pciehp_release_ctrl(ctrl);
}

#ifdef CONFIG_PM
static int pciehp_suspend(struct pcie_device *dev)
{
	return 0;
}

static int pciehp_resume_noirq(struct pcie_device *dev)
{
	struct controller *ctrl = get_service_data(dev);
	struct slot *slot = ctrl->slot;

	/* pci_restore_state() just wrote to the Slot Control register */
	ctrl->cmd_started = jiffies;
	ctrl->cmd_busy = true;

	/* clear spurious events from rediscovery of inserted card */
	if (slot->state == ON_STATE || slot->state == BLINKINGOFF_STATE)
		pcie_clear_hotplug_events(ctrl);

	return 0;
}

static int pciehp_resume(struct pcie_device *dev)
{
	struct controller *ctrl = get_service_data(dev);

	pciehp_check_presence(ctrl);

	return 0;
}
#endif /* PM */

static struct pcie_port_service_driver hpdriver_portdrv = {
	.name		= PCIE_MODULE_NAME,
	.port_type	= PCIE_ANY_PORT,
	.service	= PCIE_PORT_SERVICE_HP,

	.probe		= pciehp_probe,
	.remove		= pciehp_remove,

#ifdef	CONFIG_PM
	.suspend	= pciehp_suspend,
	.resume_noirq	= pciehp_resume_noirq,
	.resume		= pciehp_resume,
#endif	/* PM */
};

int __init pcie_hp_init(void)
{
	int retval = 0;

	retval = pcie_port_service_register(&hpdriver_portdrv);
	dbg("pcie_port_service_register = %d\n", retval);
	if (retval)
		dbg("Failure to register service\n");

	return retval;
}
