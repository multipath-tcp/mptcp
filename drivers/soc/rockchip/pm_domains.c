/*
 * Rockchip Generic power domain support.
 *
 * Copyright (c) 2015 ROCKCHIP, Co. Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/io.h>
#include <linux/err.h>
#include <linux/pm_clock.h>
#include <linux/pm_domain.h>
#include <linux/of_address.h>
#include <linux/of_platform.h>
#include <linux/clk.h>
#include <linux/regmap.h>
#include <linux/mfd/syscon.h>
#include <dt-bindings/power/rk3288-power.h>

struct rockchip_domain_info {
	int pwr_mask;
	int status_mask;
	int req_mask;
	int idle_mask;
	int ack_mask;
};

struct rockchip_pmu_info {
	u32 pwr_offset;
	u32 status_offset;
	u32 req_offset;
	u32 idle_offset;
	u32 ack_offset;

	u32 core_pwrcnt_offset;
	u32 gpu_pwrcnt_offset;

	unsigned int core_power_transition_time;
	unsigned int gpu_power_transition_time;

	int num_domains;
	const struct rockchip_domain_info *domain_info;
};

struct rockchip_pm_domain {
	struct generic_pm_domain genpd;
	const struct rockchip_domain_info *info;
	struct rockchip_pmu *pmu;
	int num_clks;
	struct clk *clks[];
};

struct rockchip_pmu {
	struct device *dev;
	struct regmap *regmap;
	const struct rockchip_pmu_info *info;
	struct mutex mutex; /* mutex lock for pmu */
	struct genpd_onecell_data genpd_data;
	struct generic_pm_domain *domains[];
};

#define to_rockchip_pd(gpd) container_of(gpd, struct rockchip_pm_domain, genpd)

#define DOMAIN(pwr, status, req, idle, ack)	\
{						\
	.pwr_mask = BIT(pwr),			\
	.status_mask = BIT(status),		\
	.req_mask = BIT(req),			\
	.idle_mask = BIT(idle),			\
	.ack_mask = BIT(ack),			\
}

#define DOMAIN_RK3288(pwr, status, req)		\
	DOMAIN(pwr, status, req, req, (req) + 16)

static bool rockchip_pmu_domain_is_idle(struct rockchip_pm_domain *pd)
{
	struct rockchip_pmu *pmu = pd->pmu;
	const struct rockchip_domain_info *pd_info = pd->info;
	unsigned int val;

	regmap_read(pmu->regmap, pmu->info->idle_offset, &val);
	return (val & pd_info->idle_mask) == pd_info->idle_mask;
}

static int rockchip_pmu_set_idle_request(struct rockchip_pm_domain *pd,
					 bool idle)
{
	const struct rockchip_domain_info *pd_info = pd->info;
	struct rockchip_pmu *pmu = pd->pmu;
	unsigned int val;

	regmap_update_bits(pmu->regmap, pmu->info->req_offset,
			   pd_info->req_mask, idle ? -1U : 0);

	dsb(sy);

	do {
		regmap_read(pmu->regmap, pmu->info->ack_offset, &val);
	} while ((val & pd_info->ack_mask) != (idle ? pd_info->ack_mask : 0));

	while (rockchip_pmu_domain_is_idle(pd) != idle)
		cpu_relax();

	return 0;
}

static bool rockchip_pmu_domain_is_on(struct rockchip_pm_domain *pd)
{
	struct rockchip_pmu *pmu = pd->pmu;
	unsigned int val;

	regmap_read(pmu->regmap, pmu->info->status_offset, &val);

	/* 1'b0: power on, 1'b1: power off */
	return !(val & pd->info->status_mask);
}

static void rockchip_do_pmu_set_power_domain(struct rockchip_pm_domain *pd,
					     bool on)
{
	struct rockchip_pmu *pmu = pd->pmu;

	regmap_update_bits(pmu->regmap, pmu->info->pwr_offset,
			   pd->info->pwr_mask, on ? 0 : -1U);

	dsb(sy);

	while (rockchip_pmu_domain_is_on(pd) != on)
		cpu_relax();
}

static int rockchip_pd_power(struct rockchip_pm_domain *pd, bool power_on)
{
	int i;

	mutex_lock(&pd->pmu->mutex);

	if (rockchip_pmu_domain_is_on(pd) != power_on) {
		for (i = 0; i < pd->num_clks; i++)
			clk_enable(pd->clks[i]);

		if (!power_on) {
			/* FIXME: add code to save AXI_QOS */

			/* if powering down, idle request to NIU first */
			rockchip_pmu_set_idle_request(pd, true);
		}

		rockchip_do_pmu_set_power_domain(pd, power_on);

		if (power_on) {
			/* if powering up, leave idle mode */
			rockchip_pmu_set_idle_request(pd, false);

			/* FIXME: add code to restore AXI_QOS */
		}

		for (i = pd->num_clks - 1; i >= 0; i--)
			clk_disable(pd->clks[i]);
	}

	mutex_unlock(&pd->pmu->mutex);
	return 0;
}

static int rockchip_pd_power_on(struct generic_pm_domain *domain)
{
	struct rockchip_pm_domain *pd = to_rockchip_pd(domain);

	return rockchip_pd_power(pd, true);
}

static int rockchip_pd_power_off(struct generic_pm_domain *domain)
{
	struct rockchip_pm_domain *pd = to_rockchip_pd(domain);

	return rockchip_pd_power(pd, false);
}

static int rockchip_pd_attach_dev(struct generic_pm_domain *genpd,
				  struct device *dev)
{
	struct clk *clk;
	int i;
	int error;

	dev_dbg(dev, "attaching to power domain '%s'\n", genpd->name);

	error = pm_clk_create(dev);
	if (error) {
		dev_err(dev, "pm_clk_create failed %d\n", error);
		return error;
	}

	i = 0;
	while ((clk = of_clk_get(dev->of_node, i++)) && !IS_ERR(clk)) {
		dev_dbg(dev, "adding clock '%pC' to list of PM clocks\n", clk);
		error = pm_clk_add_clk(dev, clk);
		if (error) {
			dev_err(dev, "pm_clk_add_clk failed %d\n", error);
			clk_put(clk);
			pm_clk_destroy(dev);
			return error;
		}
	}

	return 0;
}

static void rockchip_pd_detach_dev(struct generic_pm_domain *genpd,
				   struct device *dev)
{
	dev_dbg(dev, "detaching from power domain '%s'\n", genpd->name);

	pm_clk_destroy(dev);
}

static int rockchip_pm_add_one_domain(struct rockchip_pmu *pmu,
				      struct device_node *node)
{
	const struct rockchip_domain_info *pd_info;
	struct rockchip_pm_domain *pd;
	struct clk *clk;
	int clk_cnt;
	int i;
	u32 id;
	int error;

	error = of_property_read_u32(node, "reg", &id);
	if (error) {
		dev_err(pmu->dev,
			"%s: failed to retrieve domain id (reg): %d\n",
			node->name, error);
		return -EINVAL;
	}

	if (id >= pmu->info->num_domains) {
		dev_err(pmu->dev, "%s: invalid domain id %d\n",
			node->name, id);
		return -EINVAL;
	}

	pd_info = &pmu->info->domain_info[id];
	if (!pd_info) {
		dev_err(pmu->dev, "%s: undefined domain id %d\n",
			node->name, id);
		return -EINVAL;
	}

	clk_cnt = of_count_phandle_with_args(node, "clocks", "#clock-cells");
	pd = devm_kzalloc(pmu->dev,
			  sizeof(*pd) + clk_cnt * sizeof(pd->clks[0]),
			  GFP_KERNEL);
	if (!pd)
		return -ENOMEM;

	pd->info = pd_info;
	pd->pmu = pmu;

	for (i = 0; i < clk_cnt; i++) {
		clk = of_clk_get(node, i);
		if (IS_ERR(clk)) {
			error = PTR_ERR(clk);
			dev_err(pmu->dev,
				"%s: failed to get clk at index %d: %d\n",
				node->name, i, error);
			goto err_out;
		}

		error = clk_prepare(clk);
		if (error) {
			dev_err(pmu->dev,
				"%s: failed to prepare clk %pC (index %d): %d\n",
				node->name, clk, i, error);
			clk_put(clk);
			goto err_out;
		}

		pd->clks[pd->num_clks++] = clk;

		dev_dbg(pmu->dev, "added clock '%pC' to domain '%s'\n",
			clk, node->name);
	}

	error = rockchip_pd_power(pd, true);
	if (error) {
		dev_err(pmu->dev,
			"failed to power on domain '%s': %d\n",
			node->name, error);
		goto err_out;
	}

	pd->genpd.name = node->name;
	pd->genpd.power_off = rockchip_pd_power_off;
	pd->genpd.power_on = rockchip_pd_power_on;
	pd->genpd.attach_dev = rockchip_pd_attach_dev;
	pd->genpd.detach_dev = rockchip_pd_detach_dev;
	pd->genpd.flags = GENPD_FLAG_PM_CLK;
	pm_genpd_init(&pd->genpd, NULL, false);

	pmu->genpd_data.domains[id] = &pd->genpd;
	return 0;

err_out:
	while (--i >= 0) {
		clk_unprepare(pd->clks[i]);
		clk_put(pd->clks[i]);
	}
	return error;
}

static void rockchip_pm_remove_one_domain(struct rockchip_pm_domain *pd)
{
	int i;

	for (i = 0; i < pd->num_clks; i++) {
		clk_unprepare(pd->clks[i]);
		clk_put(pd->clks[i]);
	}

	/* protect the zeroing of pm->num_clks */
	mutex_lock(&pd->pmu->mutex);
	pd->num_clks = 0;
	mutex_unlock(&pd->pmu->mutex);

	/* devm will free our memory */
}

static void rockchip_pm_domain_cleanup(struct rockchip_pmu *pmu)
{
	struct generic_pm_domain *genpd;
	struct rockchip_pm_domain *pd;
	int i;

	for (i = 0; i < pmu->genpd_data.num_domains; i++) {
		genpd = pmu->genpd_data.domains[i];
		if (genpd) {
			pd = to_rockchip_pd(genpd);
			rockchip_pm_remove_one_domain(pd);
		}
	}

	/* devm will free our memory */
}

static void rockchip_configure_pd_cnt(struct rockchip_pmu *pmu,
				      u32 domain_reg_offset,
				      unsigned int count)
{
	/* First configure domain power down transition count ... */
	regmap_write(pmu->regmap, domain_reg_offset, count);
	/* ... and then power up count. */
	regmap_write(pmu->regmap, domain_reg_offset + 4, count);
}

static int rockchip_pm_domain_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct device_node *np = dev->of_node;
	struct device_node *node;
	struct device *parent;
	struct rockchip_pmu *pmu;
	const struct of_device_id *match;
	const struct rockchip_pmu_info *pmu_info;
	int error;

	if (!np) {
		dev_err(dev, "device tree node not found\n");
		return -ENODEV;
	}

	match = of_match_device(dev->driver->of_match_table, dev);
	if (!match || !match->data) {
		dev_err(dev, "missing pmu data\n");
		return -EINVAL;
	}

	pmu_info = match->data;

	pmu = devm_kzalloc(dev,
			   sizeof(*pmu) +
				pmu_info->num_domains * sizeof(pmu->domains[0]),
			   GFP_KERNEL);
	if (!pmu)
		return -ENOMEM;

	pmu->dev = &pdev->dev;
	mutex_init(&pmu->mutex);

	pmu->info = pmu_info;

	pmu->genpd_data.domains = pmu->domains;
	pmu->genpd_data.num_domains = pmu_info->num_domains;

	parent = dev->parent;
	if (!parent) {
		dev_err(dev, "no parent for syscon devices\n");
		return -ENODEV;
	}

	pmu->regmap = syscon_node_to_regmap(parent->of_node);

	/*
	 * Configure power up and down transition delays for CORE
	 * and GPU domains.
	 */
	rockchip_configure_pd_cnt(pmu, pmu_info->core_pwrcnt_offset,
				  pmu_info->core_power_transition_time);
	rockchip_configure_pd_cnt(pmu, pmu_info->gpu_pwrcnt_offset,
				  pmu_info->gpu_power_transition_time);

	error = -ENODEV;

	for_each_available_child_of_node(np, node) {
		error = rockchip_pm_add_one_domain(pmu, node);
		if (error) {
			dev_err(dev, "failed to handle node %s: %d\n",
				node->name, error);
			goto err_out;
		}
	}

	if (error) {
		dev_dbg(dev, "no power domains defined\n");
		goto err_out;
	}

	of_genpd_add_provider_onecell(np, &pmu->genpd_data);

	return 0;

err_out:
	rockchip_pm_domain_cleanup(pmu);
	return error;
}

static const struct rockchip_domain_info rk3288_pm_domains[] = {
	[RK3288_PD_VIO]		= DOMAIN_RK3288(7, 7, 4),
	[RK3288_PD_HEVC]	= DOMAIN_RK3288(14, 10, 9),
	[RK3288_PD_VIDEO]	= DOMAIN_RK3288(8, 8, 3),
	[RK3288_PD_GPU]		= DOMAIN_RK3288(9, 9, 2),
};

static const struct rockchip_pmu_info rk3288_pmu = {
	.pwr_offset = 0x08,
	.status_offset = 0x0c,
	.req_offset = 0x10,
	.idle_offset = 0x14,
	.ack_offset = 0x14,

	.core_pwrcnt_offset = 0x34,
	.gpu_pwrcnt_offset = 0x3c,

	.core_power_transition_time = 24, /* 1us */
	.gpu_power_transition_time = 24, /* 1us */

	.num_domains = ARRAY_SIZE(rk3288_pm_domains),
	.domain_info = rk3288_pm_domains,
};

static const struct of_device_id rockchip_pm_domain_dt_match[] = {
	{
		.compatible = "rockchip,rk3288-power-controller",
		.data = (void *)&rk3288_pmu,
	},
	{ /* sentinel */ },
};

static struct platform_driver rockchip_pm_domain_driver = {
	.probe = rockchip_pm_domain_probe,
	.driver = {
		.name   = "rockchip-pm-domain",
		.of_match_table = rockchip_pm_domain_dt_match,
		/*
		 * We can't forcibly eject devices form power domain,
		 * so we can't really remove power domains once they
		 * were added.
		 */
		.suppress_bind_attrs = true,
	},
};

static int __init rockchip_pm_domain_drv_register(void)
{
	return platform_driver_register(&rockchip_pm_domain_driver);
}
postcore_initcall(rockchip_pm_domain_drv_register);
