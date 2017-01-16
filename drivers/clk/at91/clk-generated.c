/*
 *  Copyright (C) 2015 Atmel Corporation,
 *                     Nicolas Ferre <nicolas.ferre@atmel.com>
 *
 * Based on clk-programmable & clk-peripheral drivers by Boris BREZILLON.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 */

#include <linux/clk-provider.h>
#include <linux/clkdev.h>
#include <linux/clk/at91_pmc.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/io.h>

#include "pmc.h"

#define PERIPHERAL_MAX		64
#define PERIPHERAL_ID_MIN	2

#define GENERATED_SOURCE_MAX	6
#define GENERATED_MAX_DIV	255

struct clk_generated {
	struct clk_hw hw;
	struct at91_pmc *pmc;
	struct clk_range range;
	u32 id;
	u32 gckdiv;
	u8 parent_id;
};

#define to_clk_generated(hw) \
	container_of(hw, struct clk_generated, hw)

static int clk_generated_enable(struct clk_hw *hw)
{
	struct clk_generated *gck = to_clk_generated(hw);
	struct at91_pmc *pmc = gck->pmc;
	u32 tmp;

	pr_debug("GCLK: %s, gckdiv = %d, parent id = %d\n",
		 __func__, gck->gckdiv, gck->parent_id);

	pmc_lock(pmc);
	pmc_write(pmc, AT91_PMC_PCR, (gck->id & AT91_PMC_PCR_PID_MASK));
	tmp = pmc_read(pmc, AT91_PMC_PCR) &
			~(AT91_PMC_PCR_GCKDIV_MASK | AT91_PMC_PCR_GCKCSS_MASK);
	pmc_write(pmc, AT91_PMC_PCR, tmp | AT91_PMC_PCR_GCKCSS(gck->parent_id)
					 | AT91_PMC_PCR_CMD
					 | AT91_PMC_PCR_GCKDIV(gck->gckdiv)
					 | AT91_PMC_PCR_GCKEN);
	pmc_unlock(pmc);
	return 0;
}

static void clk_generated_disable(struct clk_hw *hw)
{
	struct clk_generated *gck = to_clk_generated(hw);
	struct at91_pmc *pmc = gck->pmc;
	u32 tmp;

	pmc_lock(pmc);
	pmc_write(pmc, AT91_PMC_PCR, (gck->id & AT91_PMC_PCR_PID_MASK));
	tmp = pmc_read(pmc, AT91_PMC_PCR) & ~AT91_PMC_PCR_GCKEN;
	pmc_write(pmc, AT91_PMC_PCR, tmp | AT91_PMC_PCR_CMD);
	pmc_unlock(pmc);
}

static int clk_generated_is_enabled(struct clk_hw *hw)
{
	struct clk_generated *gck = to_clk_generated(hw);
	struct at91_pmc *pmc = gck->pmc;
	int ret;

	pmc_lock(pmc);
	pmc_write(pmc, AT91_PMC_PCR, (gck->id & AT91_PMC_PCR_PID_MASK));
	ret = !!(pmc_read(pmc, AT91_PMC_PCR) & AT91_PMC_PCR_GCKEN);
	pmc_unlock(pmc);

	return ret;
}

static unsigned long
clk_generated_recalc_rate(struct clk_hw *hw,
			  unsigned long parent_rate)
{
	struct clk_generated *gck = to_clk_generated(hw);

	return DIV_ROUND_CLOSEST(parent_rate, gck->gckdiv + 1);
}

static int clk_generated_determine_rate(struct clk_hw *hw,
					struct clk_rate_request *req)
{
	struct clk_generated *gck = to_clk_generated(hw);
	struct clk_hw *parent = NULL;
	long best_rate = -EINVAL;
	unsigned long tmp_rate, min_rate;
	int best_diff = -1;
	int tmp_diff;
	int i;

	for (i = 0; i < clk_hw_get_num_parents(hw); i++) {
		u32 div;
		unsigned long parent_rate;

		parent = clk_hw_get_parent_by_index(hw, i);
		if (!parent)
			continue;

		parent_rate = clk_hw_get_rate(parent);
		min_rate = DIV_ROUND_CLOSEST(parent_rate, GENERATED_MAX_DIV + 1);
		if (!parent_rate ||
		    (gck->range.max && min_rate > gck->range.max))
			continue;

		for (div = 1; div < GENERATED_MAX_DIV + 2; div++) {
			tmp_rate = DIV_ROUND_CLOSEST(parent_rate, div);
			tmp_diff = abs(req->rate - tmp_rate);

			if (best_diff < 0 || best_diff > tmp_diff) {
				best_rate = tmp_rate;
				best_diff = tmp_diff;
				req->best_parent_rate = parent_rate;
				req->best_parent_hw = parent;
			}

			if (!best_diff || tmp_rate < req->rate)
				break;
		}

		if (!best_diff)
			break;
	}

	pr_debug("GCLK: %s, best_rate = %ld, parent clk: %s @ %ld\n",
		 __func__, best_rate,
		 __clk_get_name((req->best_parent_hw)->clk),
		 req->best_parent_rate);

	if (best_rate < 0)
		return best_rate;

	req->rate = best_rate;
	return 0;
}

/* No modification of hardware as we have the flag CLK_SET_PARENT_GATE set */
static int clk_generated_set_parent(struct clk_hw *hw, u8 index)
{
	struct clk_generated *gck = to_clk_generated(hw);

	if (index >= clk_hw_get_num_parents(hw))
		return -EINVAL;

	gck->parent_id = index;
	return 0;
}

static u8 clk_generated_get_parent(struct clk_hw *hw)
{
	struct clk_generated *gck = to_clk_generated(hw);

	return gck->parent_id;
}

/* No modification of hardware as we have the flag CLK_SET_RATE_GATE set */
static int clk_generated_set_rate(struct clk_hw *hw,
				  unsigned long rate,
				  unsigned long parent_rate)
{
	struct clk_generated *gck = to_clk_generated(hw);
	u32 div;

	if (!rate)
		return -EINVAL;

	if (gck->range.max && rate > gck->range.max)
		return -EINVAL;

	div = DIV_ROUND_CLOSEST(parent_rate, rate);
	if (div > GENERATED_MAX_DIV + 1 || !div)
		return -EINVAL;

	gck->gckdiv = div - 1;
	return 0;
}

static const struct clk_ops generated_ops = {
	.enable = clk_generated_enable,
	.disable = clk_generated_disable,
	.is_enabled = clk_generated_is_enabled,
	.recalc_rate = clk_generated_recalc_rate,
	.determine_rate = clk_generated_determine_rate,
	.get_parent = clk_generated_get_parent,
	.set_parent = clk_generated_set_parent,
	.set_rate = clk_generated_set_rate,
};

/**
 * clk_generated_startup - Initialize a given clock to its default parent and
 * divisor parameter.
 *
 * @gck:	Generated clock to set the startup parameters for.
 *
 * Take parameters from the hardware and update local clock configuration
 * accordingly.
 */
static void clk_generated_startup(struct clk_generated *gck)
{
	struct at91_pmc *pmc = gck->pmc;
	u32 tmp;

	pmc_lock(pmc);
	pmc_write(pmc, AT91_PMC_PCR, (gck->id & AT91_PMC_PCR_PID_MASK));
	tmp = pmc_read(pmc, AT91_PMC_PCR);
	pmc_unlock(pmc);

	gck->parent_id = (tmp & AT91_PMC_PCR_GCKCSS_MASK)
					>> AT91_PMC_PCR_GCKCSS_OFFSET;
	gck->gckdiv = (tmp & AT91_PMC_PCR_GCKDIV_MASK)
					>> AT91_PMC_PCR_GCKDIV_OFFSET;
}

static struct clk * __init
at91_clk_register_generated(struct at91_pmc *pmc, const char *name,
			    const char **parent_names, u8 num_parents,
			    u8 id, const struct clk_range *range)
{
	struct clk_generated *gck;
	struct clk *clk = NULL;
	struct clk_init_data init;

	gck = kzalloc(sizeof(*gck), GFP_KERNEL);
	if (!gck)
		return ERR_PTR(-ENOMEM);

	init.name = name;
	init.ops = &generated_ops;
	init.parent_names = parent_names;
	init.num_parents = num_parents;
	init.flags = CLK_SET_RATE_GATE | CLK_SET_PARENT_GATE;

	gck->id = id;
	gck->hw.init = &init;
	gck->pmc = pmc;
	gck->range = *range;

	clk = clk_register(NULL, &gck->hw);
	if (IS_ERR(clk))
		kfree(gck);
	else
		clk_generated_startup(gck);

	return clk;
}

void __init of_sama5d2_clk_generated_setup(struct device_node *np,
					   struct at91_pmc *pmc)
{
	int num;
	u32 id;
	const char *name;
	struct clk *clk;
	int num_parents;
	const char *parent_names[GENERATED_SOURCE_MAX];
	struct device_node *gcknp;
	struct clk_range range = CLK_RANGE(0, 0);

	num_parents = of_clk_get_parent_count(np);
	if (num_parents <= 0 || num_parents > GENERATED_SOURCE_MAX)
		return;

	of_clk_parent_fill(np, parent_names, num_parents);

	num = of_get_child_count(np);
	if (!num || num > PERIPHERAL_MAX)
		return;

	for_each_child_of_node(np, gcknp) {
		if (of_property_read_u32(gcknp, "reg", &id))
			continue;

		if (id < PERIPHERAL_ID_MIN || id >= PERIPHERAL_MAX)
			continue;

		if (of_property_read_string(np, "clock-output-names", &name))
			name = gcknp->name;

		of_at91_get_clk_range(gcknp, "atmel,clk-output-range",
				      &range);

		clk = at91_clk_register_generated(pmc, name, parent_names,
						  num_parents, id, &range);
		if (IS_ERR(clk))
			continue;

		of_clk_add_provider(gcknp, of_clk_src_simple_get, clk);
	}
}
