/*
 * ARM GIC v2m MSI(-X) support
 * Support for Message Signaled Interrupts for systems that
 * implement ARM Generic Interrupt Controller: GICv2m.
 *
 * Copyright (C) 2014 Advanced Micro Devices, Inc.
 * Authors: Suravee Suthikulpanit <suravee.suthikulpanit@amd.com>
 *	    Harish Kasiviswanathan <harish.kasiviswanathan@amd.com>
 *	    Brandon Anderson <brandon.anderson@amd.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation.
 */

#define pr_fmt(fmt) "GICv2m: " fmt

#include <linux/irq.h>
#include <linux/irqdomain.h>
#include <linux/kernel.h>
#include <linux/of_address.h>
#include <linux/of_pci.h>
#include <linux/slab.h>
#include <linux/spinlock.h>

/*
* MSI_TYPER:
*     [31:26] Reserved
*     [25:16] lowest SPI assigned to MSI
*     [15:10] Reserved
*     [9:0]   Numer of SPIs assigned to MSI
*/
#define V2M_MSI_TYPER		       0x008
#define V2M_MSI_TYPER_BASE_SHIFT       16
#define V2M_MSI_TYPER_BASE_MASK	       0x3FF
#define V2M_MSI_TYPER_NUM_MASK	       0x3FF
#define V2M_MSI_SETSPI_NS	       0x040
#define V2M_MIN_SPI		       32
#define V2M_MAX_SPI		       1019
#define V2M_MSI_IIDR		       0xFCC

#define V2M_MSI_TYPER_BASE_SPI(x)      \
	       (((x) >> V2M_MSI_TYPER_BASE_SHIFT) & V2M_MSI_TYPER_BASE_MASK)

#define V2M_MSI_TYPER_NUM_SPI(x)       ((x) & V2M_MSI_TYPER_NUM_MASK)

/* APM X-Gene with GICv2m MSI_IIDR register value */
#define XGENE_GICV2M_MSI_IIDR		0x06000170

/* List of flags for specific v2m implementation */
#define GICV2M_NEEDS_SPI_OFFSET		0x00000001

static LIST_HEAD(v2m_nodes);
static DEFINE_SPINLOCK(v2m_lock);

struct v2m_data {
	struct list_head entry;
	struct device_node *node;
	struct resource res;	/* GICv2m resource */
	void __iomem *base;	/* GICv2m virt address */
	u32 spi_start;		/* The SPI number that MSIs start */
	u32 nr_spis;		/* The number of SPIs for MSIs */
	unsigned long *bm;	/* MSI vector bitmap */
	u32 flags;		/* v2m flags for specific implementation */
};

static void gicv2m_mask_msi_irq(struct irq_data *d)
{
	pci_msi_mask_irq(d);
	irq_chip_mask_parent(d);
}

static void gicv2m_unmask_msi_irq(struct irq_data *d)
{
	pci_msi_unmask_irq(d);
	irq_chip_unmask_parent(d);
}

static struct irq_chip gicv2m_msi_irq_chip = {
	.name			= "MSI",
	.irq_mask		= gicv2m_mask_msi_irq,
	.irq_unmask		= gicv2m_unmask_msi_irq,
	.irq_eoi		= irq_chip_eoi_parent,
	.irq_write_msi_msg	= pci_msi_domain_write_msg,
};

static struct msi_domain_info gicv2m_msi_domain_info = {
	.flags	= (MSI_FLAG_USE_DEF_DOM_OPS | MSI_FLAG_USE_DEF_CHIP_OPS |
		   MSI_FLAG_PCI_MSIX),
	.chip	= &gicv2m_msi_irq_chip,
};

static int gicv2m_set_affinity(struct irq_data *irq_data,
			       const struct cpumask *mask, bool force)
{
	int ret;

	ret = irq_chip_set_affinity_parent(irq_data, mask, force);
	if (ret == IRQ_SET_MASK_OK)
		ret = IRQ_SET_MASK_OK_DONE;

	return ret;
}

static void gicv2m_compose_msi_msg(struct irq_data *data, struct msi_msg *msg)
{
	struct v2m_data *v2m = irq_data_get_irq_chip_data(data);
	phys_addr_t addr = v2m->res.start + V2M_MSI_SETSPI_NS;

	msg->address_hi = upper_32_bits(addr);
	msg->address_lo = lower_32_bits(addr);
	msg->data = data->hwirq;

	if (v2m->flags & GICV2M_NEEDS_SPI_OFFSET)
		msg->data -= v2m->spi_start;
}

static struct irq_chip gicv2m_irq_chip = {
	.name			= "GICv2m",
	.irq_mask		= irq_chip_mask_parent,
	.irq_unmask		= irq_chip_unmask_parent,
	.irq_eoi		= irq_chip_eoi_parent,
	.irq_set_affinity	= gicv2m_set_affinity,
	.irq_compose_msi_msg	= gicv2m_compose_msi_msg,
};

static int gicv2m_irq_gic_domain_alloc(struct irq_domain *domain,
				       unsigned int virq,
				       irq_hw_number_t hwirq)
{
	struct irq_fwspec fwspec;
	struct irq_data *d;
	int err;

	if (is_of_node(domain->parent->fwnode)) {
		fwspec.fwnode = domain->parent->fwnode;
		fwspec.param_count = 3;
		fwspec.param[0] = 0;
		fwspec.param[1] = hwirq - 32;
		fwspec.param[2] = IRQ_TYPE_EDGE_RISING;
	} else {
		return -EINVAL;
	}

	err = irq_domain_alloc_irqs_parent(domain, virq, 1, &fwspec);
	if (err)
		return err;

	/* Configure the interrupt line to be edge */
	d = irq_domain_get_irq_data(domain->parent, virq);
	d->chip->irq_set_type(d, IRQ_TYPE_EDGE_RISING);
	return 0;
}

static void gicv2m_unalloc_msi(struct v2m_data *v2m, unsigned int hwirq)
{
	int pos;

	pos = hwirq - v2m->spi_start;
	if (pos < 0 || pos >= v2m->nr_spis) {
		pr_err("Failed to teardown msi. Invalid hwirq %d\n", hwirq);
		return;
	}

	spin_lock(&v2m_lock);
	__clear_bit(pos, v2m->bm);
	spin_unlock(&v2m_lock);
}

static int gicv2m_irq_domain_alloc(struct irq_domain *domain, unsigned int virq,
				   unsigned int nr_irqs, void *args)
{
	struct v2m_data *v2m = NULL, *tmp;
	int hwirq, offset, err = 0;

	spin_lock(&v2m_lock);
	list_for_each_entry(tmp, &v2m_nodes, entry) {
		offset = find_first_zero_bit(tmp->bm, tmp->nr_spis);
		if (offset < tmp->nr_spis) {
			__set_bit(offset, tmp->bm);
			v2m = tmp;
			break;
		}
	}
	spin_unlock(&v2m_lock);

	if (!v2m)
		return -ENOSPC;

	hwirq = v2m->spi_start + offset;

	err = gicv2m_irq_gic_domain_alloc(domain, virq, hwirq);
	if (err) {
		gicv2m_unalloc_msi(v2m, hwirq);
		return err;
	}

	irq_domain_set_hwirq_and_chip(domain, virq, hwirq,
				      &gicv2m_irq_chip, v2m);

	return 0;
}

static void gicv2m_irq_domain_free(struct irq_domain *domain,
				   unsigned int virq, unsigned int nr_irqs)
{
	struct irq_data *d = irq_domain_get_irq_data(domain, virq);
	struct v2m_data *v2m = irq_data_get_irq_chip_data(d);

	BUG_ON(nr_irqs != 1);
	gicv2m_unalloc_msi(v2m, d->hwirq);
	irq_domain_free_irqs_parent(domain, virq, nr_irqs);
}

static const struct irq_domain_ops gicv2m_domain_ops = {
	.alloc			= gicv2m_irq_domain_alloc,
	.free			= gicv2m_irq_domain_free,
};

static bool is_msi_spi_valid(u32 base, u32 num)
{
	if (base < V2M_MIN_SPI) {
		pr_err("Invalid MSI base SPI (base:%u)\n", base);
		return false;
	}

	if ((num == 0) || (base + num > V2M_MAX_SPI)) {
		pr_err("Number of SPIs (%u) exceed maximum (%u)\n",
		       num, V2M_MAX_SPI - V2M_MIN_SPI + 1);
		return false;
	}

	return true;
}

static struct irq_chip gicv2m_pmsi_irq_chip = {
	.name			= "pMSI",
};

static struct msi_domain_ops gicv2m_pmsi_ops = {
};

static struct msi_domain_info gicv2m_pmsi_domain_info = {
	.flags	= (MSI_FLAG_USE_DEF_DOM_OPS | MSI_FLAG_USE_DEF_CHIP_OPS),
	.ops	= &gicv2m_pmsi_ops,
	.chip	= &gicv2m_pmsi_irq_chip,
};

static void gicv2m_teardown(void)
{
	struct v2m_data *v2m, *tmp;

	list_for_each_entry_safe(v2m, tmp, &v2m_nodes, entry) {
		list_del(&v2m->entry);
		kfree(v2m->bm);
		iounmap(v2m->base);
		of_node_put(v2m->node);
		kfree(v2m);
	}
}

static int gicv2m_allocate_domains(struct irq_domain *parent)
{
	struct irq_domain *inner_domain, *pci_domain, *plat_domain;
	struct v2m_data *v2m;

	v2m = list_first_entry_or_null(&v2m_nodes, struct v2m_data, entry);
	if (!v2m)
		return 0;

	inner_domain = irq_domain_create_tree(of_node_to_fwnode(v2m->node),
					      &gicv2m_domain_ops, v2m);
	if (!inner_domain) {
		pr_err("Failed to create GICv2m domain\n");
		return -ENOMEM;
	}

	inner_domain->bus_token = DOMAIN_BUS_NEXUS;
	inner_domain->parent = parent;
	pci_domain = pci_msi_create_irq_domain(of_node_to_fwnode(v2m->node),
					       &gicv2m_msi_domain_info,
					       inner_domain);
	plat_domain = platform_msi_create_irq_domain(of_node_to_fwnode(v2m->node),
						     &gicv2m_pmsi_domain_info,
						     inner_domain);
	if (!pci_domain || !plat_domain) {
		pr_err("Failed to create MSI domains\n");
		if (plat_domain)
			irq_domain_remove(plat_domain);
		if (pci_domain)
			irq_domain_remove(pci_domain);
		irq_domain_remove(inner_domain);
		return -ENOMEM;
	}

	return 0;
}

static int __init gicv2m_init_one(struct device_node *node,
				  struct irq_domain *parent)
{
	int ret;
	struct v2m_data *v2m;

	v2m = kzalloc(sizeof(struct v2m_data), GFP_KERNEL);
	if (!v2m) {
		pr_err("Failed to allocate struct v2m_data.\n");
		return -ENOMEM;
	}

	INIT_LIST_HEAD(&v2m->entry);
	v2m->node = node;

	ret = of_address_to_resource(node, 0, &v2m->res);
	if (ret) {
		pr_err("Failed to allocate v2m resource.\n");
		goto err_free_v2m;
	}

	v2m->base = ioremap(v2m->res.start, resource_size(&v2m->res));
	if (!v2m->base) {
		pr_err("Failed to map GICv2m resource\n");
		ret = -ENOMEM;
		goto err_free_v2m;
	}

	if (!of_property_read_u32(node, "arm,msi-base-spi", &v2m->spi_start) &&
	    !of_property_read_u32(node, "arm,msi-num-spis", &v2m->nr_spis)) {
		pr_info("Overriding V2M MSI_TYPER (base:%u, num:%u)\n",
			v2m->spi_start, v2m->nr_spis);
	} else {
		u32 typer = readl_relaxed(v2m->base + V2M_MSI_TYPER);

		v2m->spi_start = V2M_MSI_TYPER_BASE_SPI(typer);
		v2m->nr_spis = V2M_MSI_TYPER_NUM_SPI(typer);
	}

	if (!is_msi_spi_valid(v2m->spi_start, v2m->nr_spis)) {
		ret = -EINVAL;
		goto err_iounmap;
	}

	/*
	 * APM X-Gene GICv2m implementation has an erratum where
	 * the MSI data needs to be the offset from the spi_start
	 * in order to trigger the correct MSI interrupt. This is
	 * different from the standard GICv2m implementation where
	 * the MSI data is the absolute value within the range from
	 * spi_start to (spi_start + num_spis).
	 */
	if (readl_relaxed(v2m->base + V2M_MSI_IIDR) == XGENE_GICV2M_MSI_IIDR)
		v2m->flags |= GICV2M_NEEDS_SPI_OFFSET;

	v2m->bm = kzalloc(sizeof(long) * BITS_TO_LONGS(v2m->nr_spis),
			  GFP_KERNEL);
	if (!v2m->bm) {
		ret = -ENOMEM;
		goto err_iounmap;
	}

	list_add_tail(&v2m->entry, &v2m_nodes);
	pr_info("Node %s: range[%#lx:%#lx], SPI[%d:%d]\n", node->name,
		(unsigned long)v2m->res.start, (unsigned long)v2m->res.end,
		v2m->spi_start, (v2m->spi_start + v2m->nr_spis));

	return 0;

err_iounmap:
	iounmap(v2m->base);
err_free_v2m:
	kfree(v2m);
	return ret;
}

static struct of_device_id gicv2m_device_id[] = {
	{	.compatible	= "arm,gic-v2m-frame",	},
	{},
};

int __init gicv2m_of_init(struct device_node *node, struct irq_domain *parent)
{
	int ret = 0;
	struct device_node *child;

	for (child = of_find_matching_node(node, gicv2m_device_id); child;
	     child = of_find_matching_node(child, gicv2m_device_id)) {
		if (!of_find_property(child, "msi-controller", NULL))
			continue;

		ret = gicv2m_init_one(child, parent);
		if (ret) {
			of_node_put(node);
			break;
		}
	}

	if (!ret)
		ret = gicv2m_allocate_domains(parent);
	if (ret)
		gicv2m_teardown();
	return ret;
}
