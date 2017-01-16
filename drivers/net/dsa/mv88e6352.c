/*
 * net/dsa/mv88e6352.c - Marvell 88e6352 switch chip support
 *
 * Copyright (c) 2014 Guenter Roeck
 *
 * Derived from mv88e6123_61_65.c
 * Copyright (c) 2008-2009 Marvell Semiconductor
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <linux/delay.h>
#include <linux/jiffies.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/platform_device.h>
#include <linux/phy.h>
#include <net/dsa.h>
#include "mv88e6xxx.h"

static const struct mv88e6xxx_switch_id mv88e6352_table[] = {
	{ PORT_SWITCH_ID_6172, "Marvell 88E6172" },
	{ PORT_SWITCH_ID_6176, "Marvell 88E6176" },
	{ PORT_SWITCH_ID_6320, "Marvell 88E6320" },
	{ PORT_SWITCH_ID_6320_A1, "Marvell 88E6320 (A1)" },
	{ PORT_SWITCH_ID_6320_A2, "Marvell 88e6320 (A2)" },
	{ PORT_SWITCH_ID_6321, "Marvell 88E6321" },
	{ PORT_SWITCH_ID_6321_A1, "Marvell 88E6321 (A1)" },
	{ PORT_SWITCH_ID_6321_A2, "Marvell 88e6321 (A2)" },
	{ PORT_SWITCH_ID_6352, "Marvell 88E6352" },
	{ PORT_SWITCH_ID_6352_A0, "Marvell 88E6352 (A0)" },
	{ PORT_SWITCH_ID_6352_A1, "Marvell 88E6352 (A1)" },
};

static char *mv88e6352_probe(struct device *host_dev, int sw_addr)
{
	return mv88e6xxx_lookup_name(host_dev, sw_addr, mv88e6352_table,
				     ARRAY_SIZE(mv88e6352_table));
}

static int mv88e6352_setup_global(struct dsa_switch *ds)
{
	u32 upstream_port = dsa_upstream_port(ds);
	int ret;
	u32 reg;

	ret = mv88e6xxx_setup_global(ds);
	if (ret)
		return ret;

	/* Discard packets with excessive collisions,
	 * mask all interrupt sources, enable PPU (bit 14, undocumented).
	 */
	REG_WRITE(REG_GLOBAL, GLOBAL_CONTROL,
		  GLOBAL_CONTROL_PPU_ENABLE | GLOBAL_CONTROL_DISCARD_EXCESS);

	/* Configure the upstream port, and configure the upstream
	 * port as the port to which ingress and egress monitor frames
	 * are to be sent.
	 */
	reg = upstream_port << GLOBAL_MONITOR_CONTROL_INGRESS_SHIFT |
		upstream_port << GLOBAL_MONITOR_CONTROL_EGRESS_SHIFT |
		upstream_port << GLOBAL_MONITOR_CONTROL_ARP_SHIFT;
	REG_WRITE(REG_GLOBAL, GLOBAL_MONITOR_CONTROL, reg);

	/* Disable remote management for now, and set the switch's
	 * DSA device number.
	 */
	REG_WRITE(REG_GLOBAL, 0x1c, ds->index & 0x1f);

	return 0;
}

static int mv88e6352_setup(struct dsa_switch *ds)
{
	struct mv88e6xxx_priv_state *ps = ds_to_priv(ds);
	int ret;

	ret = mv88e6xxx_setup_common(ds);
	if (ret < 0)
		return ret;

	ps->num_ports = 7;

	mutex_init(&ps->eeprom_mutex);

	ret = mv88e6xxx_switch_reset(ds, true);
	if (ret < 0)
		return ret;

	ret = mv88e6352_setup_global(ds);
	if (ret < 0)
		return ret;

	return mv88e6xxx_setup_ports(ds);
}

static int mv88e6352_read_eeprom_word(struct dsa_switch *ds, int addr)
{
	struct mv88e6xxx_priv_state *ps = ds_to_priv(ds);
	int ret;

	mutex_lock(&ps->eeprom_mutex);

	ret = mv88e6xxx_reg_write(ds, REG_GLOBAL2, GLOBAL2_EEPROM_OP,
				  GLOBAL2_EEPROM_OP_READ |
				  (addr & GLOBAL2_EEPROM_OP_ADDR_MASK));
	if (ret < 0)
		goto error;

	ret = mv88e6xxx_eeprom_busy_wait(ds);
	if (ret < 0)
		goto error;

	ret = mv88e6xxx_reg_read(ds, REG_GLOBAL2, GLOBAL2_EEPROM_DATA);
error:
	mutex_unlock(&ps->eeprom_mutex);
	return ret;
}

static int mv88e6352_get_eeprom(struct dsa_switch *ds,
				struct ethtool_eeprom *eeprom, u8 *data)
{
	int offset;
	int len;
	int ret;

	offset = eeprom->offset;
	len = eeprom->len;
	eeprom->len = 0;

	eeprom->magic = 0xc3ec4951;

	ret = mv88e6xxx_eeprom_load_wait(ds);
	if (ret < 0)
		return ret;

	if (offset & 1) {
		int word;

		word = mv88e6352_read_eeprom_word(ds, offset >> 1);
		if (word < 0)
			return word;

		*data++ = (word >> 8) & 0xff;

		offset++;
		len--;
		eeprom->len++;
	}

	while (len >= 2) {
		int word;

		word = mv88e6352_read_eeprom_word(ds, offset >> 1);
		if (word < 0)
			return word;

		*data++ = word & 0xff;
		*data++ = (word >> 8) & 0xff;

		offset += 2;
		len -= 2;
		eeprom->len += 2;
	}

	if (len) {
		int word;

		word = mv88e6352_read_eeprom_word(ds, offset >> 1);
		if (word < 0)
			return word;

		*data++ = word & 0xff;

		offset++;
		len--;
		eeprom->len++;
	}

	return 0;
}

static int mv88e6352_eeprom_is_readonly(struct dsa_switch *ds)
{
	int ret;

	ret = mv88e6xxx_reg_read(ds, REG_GLOBAL2, GLOBAL2_EEPROM_OP);
	if (ret < 0)
		return ret;

	if (!(ret & GLOBAL2_EEPROM_OP_WRITE_EN))
		return -EROFS;

	return 0;
}

static int mv88e6352_write_eeprom_word(struct dsa_switch *ds, int addr,
				       u16 data)
{
	struct mv88e6xxx_priv_state *ps = ds_to_priv(ds);
	int ret;

	mutex_lock(&ps->eeprom_mutex);

	ret = mv88e6xxx_reg_write(ds, REG_GLOBAL2, GLOBAL2_EEPROM_DATA, data);
	if (ret < 0)
		goto error;

	ret = mv88e6xxx_reg_write(ds, REG_GLOBAL2, GLOBAL2_EEPROM_OP,
				  GLOBAL2_EEPROM_OP_WRITE |
				  (addr & GLOBAL2_EEPROM_OP_ADDR_MASK));
	if (ret < 0)
		goto error;

	ret = mv88e6xxx_eeprom_busy_wait(ds);
error:
	mutex_unlock(&ps->eeprom_mutex);
	return ret;
}

static int mv88e6352_set_eeprom(struct dsa_switch *ds,
				struct ethtool_eeprom *eeprom, u8 *data)
{
	int offset;
	int ret;
	int len;

	if (eeprom->magic != 0xc3ec4951)
		return -EINVAL;

	ret = mv88e6352_eeprom_is_readonly(ds);
	if (ret)
		return ret;

	offset = eeprom->offset;
	len = eeprom->len;
	eeprom->len = 0;

	ret = mv88e6xxx_eeprom_load_wait(ds);
	if (ret < 0)
		return ret;

	if (offset & 1) {
		int word;

		word = mv88e6352_read_eeprom_word(ds, offset >> 1);
		if (word < 0)
			return word;

		word = (*data++ << 8) | (word & 0xff);

		ret = mv88e6352_write_eeprom_word(ds, offset >> 1, word);
		if (ret < 0)
			return ret;

		offset++;
		len--;
		eeprom->len++;
	}

	while (len >= 2) {
		int word;

		word = *data++;
		word |= *data++ << 8;

		ret = mv88e6352_write_eeprom_word(ds, offset >> 1, word);
		if (ret < 0)
			return ret;

		offset += 2;
		len -= 2;
		eeprom->len += 2;
	}

	if (len) {
		int word;

		word = mv88e6352_read_eeprom_word(ds, offset >> 1);
		if (word < 0)
			return word;

		word = (word & 0xff00) | *data++;

		ret = mv88e6352_write_eeprom_word(ds, offset >> 1, word);
		if (ret < 0)
			return ret;

		offset++;
		len--;
		eeprom->len++;
	}

	return 0;
}

struct dsa_switch_driver mv88e6352_switch_driver = {
	.tag_protocol		= DSA_TAG_PROTO_EDSA,
	.priv_size		= sizeof(struct mv88e6xxx_priv_state),
	.probe			= mv88e6352_probe,
	.setup			= mv88e6352_setup,
	.set_addr		= mv88e6xxx_set_addr_indirect,
	.phy_read		= mv88e6xxx_phy_read_indirect,
	.phy_write		= mv88e6xxx_phy_write_indirect,
	.get_strings		= mv88e6xxx_get_strings,
	.get_ethtool_stats	= mv88e6xxx_get_ethtool_stats,
	.get_sset_count		= mv88e6xxx_get_sset_count,
	.adjust_link		= mv88e6xxx_adjust_link,
	.set_eee		= mv88e6xxx_set_eee,
	.get_eee		= mv88e6xxx_get_eee,
#ifdef CONFIG_NET_DSA_HWMON
	.get_temp		= mv88e6xxx_get_temp,
	.get_temp_limit		= mv88e6xxx_get_temp_limit,
	.set_temp_limit		= mv88e6xxx_set_temp_limit,
	.get_temp_alarm		= mv88e6xxx_get_temp_alarm,
#endif
	.get_eeprom		= mv88e6352_get_eeprom,
	.set_eeprom		= mv88e6352_set_eeprom,
	.get_regs_len		= mv88e6xxx_get_regs_len,
	.get_regs		= mv88e6xxx_get_regs,
	.port_join_bridge	= mv88e6xxx_port_bridge_join,
	.port_leave_bridge	= mv88e6xxx_port_bridge_leave,
	.port_stp_update	= mv88e6xxx_port_stp_update,
	.port_pvid_get		= mv88e6xxx_port_pvid_get,
	.port_vlan_prepare	= mv88e6xxx_port_vlan_prepare,
	.port_vlan_add		= mv88e6xxx_port_vlan_add,
	.port_vlan_del		= mv88e6xxx_port_vlan_del,
	.vlan_getnext		= mv88e6xxx_vlan_getnext,
	.port_fdb_prepare	= mv88e6xxx_port_fdb_prepare,
	.port_fdb_add		= mv88e6xxx_port_fdb_add,
	.port_fdb_del		= mv88e6xxx_port_fdb_del,
	.port_fdb_dump		= mv88e6xxx_port_fdb_dump,
};

MODULE_ALIAS("platform:mv88e6172");
MODULE_ALIAS("platform:mv88e6176");
MODULE_ALIAS("platform:mv88e6320");
MODULE_ALIAS("platform:mv88e6321");
MODULE_ALIAS("platform:mv88e6352");
