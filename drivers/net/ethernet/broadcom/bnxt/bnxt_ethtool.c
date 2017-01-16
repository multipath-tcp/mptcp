/* Broadcom NetXtreme-C/E network driver.
 *
 * Copyright (c) 2014-2015 Broadcom Corporation
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation.
 */

#include <linux/ethtool.h>
#include <linux/interrupt.h>
#include <linux/pci.h>
#include <linux/etherdevice.h>
#include <linux/crc32.h>
#include <linux/firmware.h>
#include "bnxt_hsi.h"
#include "bnxt.h"
#include "bnxt_ethtool.h"
#include "bnxt_nvm_defs.h"	/* NVRAM content constant and structure defs */
#include "bnxt_fw_hdr.h"	/* Firmware hdr constant and structure defs */
#define FLASH_NVRAM_TIMEOUT	((HWRM_CMD_TIMEOUT) * 100)

static u32 bnxt_get_msglevel(struct net_device *dev)
{
	struct bnxt *bp = netdev_priv(dev);

	return bp->msg_enable;
}

static void bnxt_set_msglevel(struct net_device *dev, u32 value)
{
	struct bnxt *bp = netdev_priv(dev);

	bp->msg_enable = value;
}

static int bnxt_get_coalesce(struct net_device *dev,
			     struct ethtool_coalesce *coal)
{
	struct bnxt *bp = netdev_priv(dev);

	memset(coal, 0, sizeof(*coal));

	coal->rx_coalesce_usecs =
		max_t(u16, BNXT_COAL_TIMER_TO_USEC(bp->coal_ticks), 1);
	coal->rx_max_coalesced_frames = bp->coal_bufs / 2;
	coal->rx_coalesce_usecs_irq =
		max_t(u16, BNXT_COAL_TIMER_TO_USEC(bp->coal_ticks_irq), 1);
	coal->rx_max_coalesced_frames_irq = bp->coal_bufs_irq / 2;

	return 0;
}

static int bnxt_set_coalesce(struct net_device *dev,
			     struct ethtool_coalesce *coal)
{
	struct bnxt *bp = netdev_priv(dev);
	int rc = 0;

	bp->coal_ticks = BNXT_USEC_TO_COAL_TIMER(coal->rx_coalesce_usecs);
	bp->coal_bufs = coal->rx_max_coalesced_frames * 2;
	bp->coal_ticks_irq =
		BNXT_USEC_TO_COAL_TIMER(coal->rx_coalesce_usecs_irq);
	bp->coal_bufs_irq = coal->rx_max_coalesced_frames_irq * 2;

	if (netif_running(dev))
		rc = bnxt_hwrm_set_coal(bp);

	return rc;
}

#define BNXT_NUM_STATS	21

static int bnxt_get_sset_count(struct net_device *dev, int sset)
{
	struct bnxt *bp = netdev_priv(dev);

	switch (sset) {
	case ETH_SS_STATS:
		return BNXT_NUM_STATS * bp->cp_nr_rings;
	default:
		return -EOPNOTSUPP;
	}
}

static void bnxt_get_ethtool_stats(struct net_device *dev,
				   struct ethtool_stats *stats, u64 *buf)
{
	u32 i, j = 0;
	struct bnxt *bp = netdev_priv(dev);
	u32 buf_size = sizeof(struct ctx_hw_stats) * bp->cp_nr_rings;
	u32 stat_fields = sizeof(struct ctx_hw_stats) / 8;

	memset(buf, 0, buf_size);

	if (!bp->bnapi)
		return;

	for (i = 0; i < bp->cp_nr_rings; i++) {
		struct bnxt_napi *bnapi = bp->bnapi[i];
		struct bnxt_cp_ring_info *cpr = &bnapi->cp_ring;
		__le64 *hw_stats = (__le64 *)cpr->hw_stats;
		int k;

		for (k = 0; k < stat_fields; j++, k++)
			buf[j] = le64_to_cpu(hw_stats[k]);
		buf[j++] = cpr->rx_l4_csum_errors;
	}
}

static void bnxt_get_strings(struct net_device *dev, u32 stringset, u8 *buf)
{
	struct bnxt *bp = netdev_priv(dev);
	u32 i;

	switch (stringset) {
	/* The number of strings must match BNXT_NUM_STATS defined above. */
	case ETH_SS_STATS:
		for (i = 0; i < bp->cp_nr_rings; i++) {
			sprintf(buf, "[%d]: rx_ucast_packets", i);
			buf += ETH_GSTRING_LEN;
			sprintf(buf, "[%d]: rx_mcast_packets", i);
			buf += ETH_GSTRING_LEN;
			sprintf(buf, "[%d]: rx_bcast_packets", i);
			buf += ETH_GSTRING_LEN;
			sprintf(buf, "[%d]: rx_discards", i);
			buf += ETH_GSTRING_LEN;
			sprintf(buf, "[%d]: rx_drops", i);
			buf += ETH_GSTRING_LEN;
			sprintf(buf, "[%d]: rx_ucast_bytes", i);
			buf += ETH_GSTRING_LEN;
			sprintf(buf, "[%d]: rx_mcast_bytes", i);
			buf += ETH_GSTRING_LEN;
			sprintf(buf, "[%d]: rx_bcast_bytes", i);
			buf += ETH_GSTRING_LEN;
			sprintf(buf, "[%d]: tx_ucast_packets", i);
			buf += ETH_GSTRING_LEN;
			sprintf(buf, "[%d]: tx_mcast_packets", i);
			buf += ETH_GSTRING_LEN;
			sprintf(buf, "[%d]: tx_bcast_packets", i);
			buf += ETH_GSTRING_LEN;
			sprintf(buf, "[%d]: tx_discards", i);
			buf += ETH_GSTRING_LEN;
			sprintf(buf, "[%d]: tx_drops", i);
			buf += ETH_GSTRING_LEN;
			sprintf(buf, "[%d]: tx_ucast_bytes", i);
			buf += ETH_GSTRING_LEN;
			sprintf(buf, "[%d]: tx_mcast_bytes", i);
			buf += ETH_GSTRING_LEN;
			sprintf(buf, "[%d]: tx_bcast_bytes", i);
			buf += ETH_GSTRING_LEN;
			sprintf(buf, "[%d]: tpa_packets", i);
			buf += ETH_GSTRING_LEN;
			sprintf(buf, "[%d]: tpa_bytes", i);
			buf += ETH_GSTRING_LEN;
			sprintf(buf, "[%d]: tpa_events", i);
			buf += ETH_GSTRING_LEN;
			sprintf(buf, "[%d]: tpa_aborts", i);
			buf += ETH_GSTRING_LEN;
			sprintf(buf, "[%d]: rx_l4_csum_errors", i);
			buf += ETH_GSTRING_LEN;
		}
		break;
	default:
		netdev_err(bp->dev, "bnxt_get_strings invalid request %x\n",
			   stringset);
		break;
	}
}

static void bnxt_get_ringparam(struct net_device *dev,
			       struct ethtool_ringparam *ering)
{
	struct bnxt *bp = netdev_priv(dev);

	ering->rx_max_pending = BNXT_MAX_RX_DESC_CNT;
	ering->rx_jumbo_max_pending = BNXT_MAX_RX_JUM_DESC_CNT;
	ering->tx_max_pending = BNXT_MAX_TX_DESC_CNT;

	ering->rx_pending = bp->rx_ring_size;
	ering->rx_jumbo_pending = bp->rx_agg_ring_size;
	ering->tx_pending = bp->tx_ring_size;
}

static int bnxt_set_ringparam(struct net_device *dev,
			      struct ethtool_ringparam *ering)
{
	struct bnxt *bp = netdev_priv(dev);

	if ((ering->rx_pending > BNXT_MAX_RX_DESC_CNT) ||
	    (ering->tx_pending > BNXT_MAX_TX_DESC_CNT) ||
	    (ering->tx_pending <= MAX_SKB_FRAGS))
		return -EINVAL;

	if (netif_running(dev))
		bnxt_close_nic(bp, false, false);

	bp->rx_ring_size = ering->rx_pending;
	bp->tx_ring_size = ering->tx_pending;
	bnxt_set_ring_params(bp);

	if (netif_running(dev))
		return bnxt_open_nic(bp, false, false);

	return 0;
}

static void bnxt_get_channels(struct net_device *dev,
			      struct ethtool_channels *channel)
{
	struct bnxt *bp = netdev_priv(dev);
	int max_rx_rings, max_tx_rings, tcs;

	bnxt_get_max_rings(bp, &max_rx_rings, &max_tx_rings);
	tcs = netdev_get_num_tc(dev);
	if (tcs > 1)
		max_tx_rings /= tcs;

	channel->max_rx = max_rx_rings;
	channel->max_tx = max_tx_rings;
	channel->max_other = 0;
	channel->max_combined = 0;
	channel->rx_count = bp->rx_nr_rings;
	channel->tx_count = bp->tx_nr_rings_per_tc;
}

static int bnxt_set_channels(struct net_device *dev,
			     struct ethtool_channels *channel)
{
	struct bnxt *bp = netdev_priv(dev);
	int max_rx_rings, max_tx_rings, tcs;
	u32 rc = 0;

	if (channel->other_count || channel->combined_count ||
	    !channel->rx_count || !channel->tx_count)
		return -EINVAL;

	bnxt_get_max_rings(bp, &max_rx_rings, &max_tx_rings);
	tcs = netdev_get_num_tc(dev);
	if (tcs > 1)
		max_tx_rings /= tcs;

	if (channel->rx_count > max_rx_rings ||
	    channel->tx_count > max_tx_rings)
		return -EINVAL;

	if (netif_running(dev)) {
		if (BNXT_PF(bp)) {
			/* TODO CHIMP_FW: Send message to all VF's
			 * before PF unload
			 */
		}
		rc = bnxt_close_nic(bp, true, false);
		if (rc) {
			netdev_err(bp->dev, "Set channel failure rc :%x\n",
				   rc);
			return rc;
		}
	}

	bp->rx_nr_rings = channel->rx_count;
	bp->tx_nr_rings_per_tc = channel->tx_count;
	bp->tx_nr_rings = bp->tx_nr_rings_per_tc;
	if (tcs > 1)
		bp->tx_nr_rings = bp->tx_nr_rings_per_tc * tcs;
	bp->cp_nr_rings = max_t(int, bp->tx_nr_rings, bp->rx_nr_rings);
	bp->num_stat_ctxs = bp->cp_nr_rings;

	if (netif_running(dev)) {
		rc = bnxt_open_nic(bp, true, false);
		if ((!rc) && BNXT_PF(bp)) {
			/* TODO CHIMP_FW: Send message to all VF's
			 * to renable
			 */
		}
	}

	return rc;
}

#ifdef CONFIG_RFS_ACCEL
static int bnxt_grxclsrlall(struct bnxt *bp, struct ethtool_rxnfc *cmd,
			    u32 *rule_locs)
{
	int i, j = 0;

	cmd->data = bp->ntp_fltr_count;
	for (i = 0; i < BNXT_NTP_FLTR_HASH_SIZE; i++) {
		struct hlist_head *head;
		struct bnxt_ntuple_filter *fltr;

		head = &bp->ntp_fltr_hash_tbl[i];
		rcu_read_lock();
		hlist_for_each_entry_rcu(fltr, head, hash) {
			if (j == cmd->rule_cnt)
				break;
			rule_locs[j++] = fltr->sw_id;
		}
		rcu_read_unlock();
		if (j == cmd->rule_cnt)
			break;
	}
	cmd->rule_cnt = j;
	return 0;
}

static int bnxt_grxclsrule(struct bnxt *bp, struct ethtool_rxnfc *cmd)
{
	struct ethtool_rx_flow_spec *fs =
		(struct ethtool_rx_flow_spec *)&cmd->fs;
	struct bnxt_ntuple_filter *fltr;
	struct flow_keys *fkeys;
	int i, rc = -EINVAL;

	if (fs->location < 0 || fs->location >= BNXT_NTP_FLTR_MAX_FLTR)
		return rc;

	for (i = 0; i < BNXT_NTP_FLTR_HASH_SIZE; i++) {
		struct hlist_head *head;

		head = &bp->ntp_fltr_hash_tbl[i];
		rcu_read_lock();
		hlist_for_each_entry_rcu(fltr, head, hash) {
			if (fltr->sw_id == fs->location)
				goto fltr_found;
		}
		rcu_read_unlock();
	}
	return rc;

fltr_found:
	fkeys = &fltr->fkeys;
	if (fkeys->basic.ip_proto == IPPROTO_TCP)
		fs->flow_type = TCP_V4_FLOW;
	else if (fkeys->basic.ip_proto == IPPROTO_UDP)
		fs->flow_type = UDP_V4_FLOW;
	else
		goto fltr_err;

	fs->h_u.tcp_ip4_spec.ip4src = fkeys->addrs.v4addrs.src;
	fs->m_u.tcp_ip4_spec.ip4src = cpu_to_be32(~0);

	fs->h_u.tcp_ip4_spec.ip4dst = fkeys->addrs.v4addrs.dst;
	fs->m_u.tcp_ip4_spec.ip4dst = cpu_to_be32(~0);

	fs->h_u.tcp_ip4_spec.psrc = fkeys->ports.src;
	fs->m_u.tcp_ip4_spec.psrc = cpu_to_be16(~0);

	fs->h_u.tcp_ip4_spec.pdst = fkeys->ports.dst;
	fs->m_u.tcp_ip4_spec.pdst = cpu_to_be16(~0);

	fs->ring_cookie = fltr->rxq;
	rc = 0;

fltr_err:
	rcu_read_unlock();

	return rc;
}

static int bnxt_get_rxnfc(struct net_device *dev, struct ethtool_rxnfc *cmd,
			  u32 *rule_locs)
{
	struct bnxt *bp = netdev_priv(dev);
	int rc = 0;

	switch (cmd->cmd) {
	case ETHTOOL_GRXRINGS:
		cmd->data = bp->rx_nr_rings;
		break;

	case ETHTOOL_GRXCLSRLCNT:
		cmd->rule_cnt = bp->ntp_fltr_count;
		cmd->data = BNXT_NTP_FLTR_MAX_FLTR;
		break;

	case ETHTOOL_GRXCLSRLALL:
		rc = bnxt_grxclsrlall(bp, cmd, (u32 *)rule_locs);
		break;

	case ETHTOOL_GRXCLSRULE:
		rc = bnxt_grxclsrule(bp, cmd);
		break;

	default:
		rc = -EOPNOTSUPP;
		break;
	}

	return rc;
}
#endif

static u32 bnxt_get_rxfh_indir_size(struct net_device *dev)
{
	return HW_HASH_INDEX_SIZE;
}

static u32 bnxt_get_rxfh_key_size(struct net_device *dev)
{
	return HW_HASH_KEY_SIZE;
}

static int bnxt_get_rxfh(struct net_device *dev, u32 *indir, u8 *key,
			 u8 *hfunc)
{
	struct bnxt *bp = netdev_priv(dev);
	struct bnxt_vnic_info *vnic = &bp->vnic_info[0];
	int i = 0;

	if (hfunc)
		*hfunc = ETH_RSS_HASH_TOP;

	if (indir)
		for (i = 0; i < HW_HASH_INDEX_SIZE; i++)
			indir[i] = le16_to_cpu(vnic->rss_table[i]);

	if (key)
		memcpy(key, vnic->rss_hash_key, HW_HASH_KEY_SIZE);

	return 0;
}

static void bnxt_get_drvinfo(struct net_device *dev,
			     struct ethtool_drvinfo *info)
{
	struct bnxt *bp = netdev_priv(dev);

	strlcpy(info->driver, DRV_MODULE_NAME, sizeof(info->driver));
	strlcpy(info->version, DRV_MODULE_VERSION, sizeof(info->version));
	strlcpy(info->fw_version, bp->fw_ver_str, sizeof(info->fw_version));
	strlcpy(info->bus_info, pci_name(bp->pdev), sizeof(info->bus_info));
	info->n_stats = BNXT_NUM_STATS * bp->cp_nr_rings;
	info->testinfo_len = BNXT_NUM_TESTS(bp);
	/* TODO CHIMP_FW: eeprom dump details */
	info->eedump_len = 0;
	/* TODO CHIMP FW: reg dump details */
	info->regdump_len = 0;
}

static u32 bnxt_fw_to_ethtool_support_spds(struct bnxt_link_info *link_info)
{
	u16 fw_speeds = link_info->support_speeds;
	u32 speed_mask = 0;

	if (fw_speeds & BNXT_LINK_SPEED_MSK_100MB)
		speed_mask |= SUPPORTED_100baseT_Full;
	if (fw_speeds & BNXT_LINK_SPEED_MSK_1GB)
		speed_mask |= SUPPORTED_1000baseT_Full;
	if (fw_speeds & BNXT_LINK_SPEED_MSK_2_5GB)
		speed_mask |= SUPPORTED_2500baseX_Full;
	if (fw_speeds & BNXT_LINK_SPEED_MSK_10GB)
		speed_mask |= SUPPORTED_10000baseT_Full;
	/* TODO: support 25GB, 50GB with different cable type */
	if (fw_speeds & BNXT_LINK_SPEED_MSK_20GB)
		speed_mask |= SUPPORTED_20000baseMLD2_Full |
			SUPPORTED_20000baseKR2_Full;
	if (fw_speeds & BNXT_LINK_SPEED_MSK_40GB)
		speed_mask |= SUPPORTED_40000baseKR4_Full |
			SUPPORTED_40000baseCR4_Full |
			SUPPORTED_40000baseSR4_Full |
			SUPPORTED_40000baseLR4_Full;

	return speed_mask;
}

static u32 bnxt_fw_to_ethtool_advertised_spds(struct bnxt_link_info *link_info)
{
	u16 fw_speeds = link_info->auto_link_speeds;
	u32 speed_mask = 0;

	/* TODO: support 25GB, 40GB, 50GB with different cable type */
	/* set the advertised speeds */
	if (fw_speeds & BNXT_LINK_SPEED_MSK_100MB)
		speed_mask |= ADVERTISED_100baseT_Full;
	if (fw_speeds & BNXT_LINK_SPEED_MSK_1GB)
		speed_mask |= ADVERTISED_1000baseT_Full;
	if (fw_speeds & BNXT_LINK_SPEED_MSK_2_5GB)
		speed_mask |= ADVERTISED_2500baseX_Full;
	if (fw_speeds & BNXT_LINK_SPEED_MSK_10GB)
		speed_mask |= ADVERTISED_10000baseT_Full;
	/* TODO: how to advertise 20, 25, 40, 50GB with different cable type ?*/
	if (fw_speeds & BNXT_LINK_SPEED_MSK_20GB)
		speed_mask |= ADVERTISED_20000baseMLD2_Full |
			      ADVERTISED_20000baseKR2_Full;
	if (fw_speeds & BNXT_LINK_SPEED_MSK_40GB)
		speed_mask |= ADVERTISED_40000baseKR4_Full |
			      ADVERTISED_40000baseCR4_Full |
			      ADVERTISED_40000baseSR4_Full |
			      ADVERTISED_40000baseLR4_Full;
	return speed_mask;
}

u32 bnxt_fw_to_ethtool_speed(u16 fw_link_speed)
{
	switch (fw_link_speed) {
	case BNXT_LINK_SPEED_100MB:
		return SPEED_100;
	case BNXT_LINK_SPEED_1GB:
		return SPEED_1000;
	case BNXT_LINK_SPEED_2_5GB:
		return SPEED_2500;
	case BNXT_LINK_SPEED_10GB:
		return SPEED_10000;
	case BNXT_LINK_SPEED_20GB:
		return SPEED_20000;
	case BNXT_LINK_SPEED_25GB:
		return SPEED_25000;
	case BNXT_LINK_SPEED_40GB:
		return SPEED_40000;
	case BNXT_LINK_SPEED_50GB:
		return SPEED_50000;
	default:
		return SPEED_UNKNOWN;
	}
}

static int bnxt_get_settings(struct net_device *dev, struct ethtool_cmd *cmd)
{
	struct bnxt *bp = netdev_priv(dev);
	struct bnxt_link_info *link_info = &bp->link_info;
	u16 ethtool_speed;

	cmd->supported = bnxt_fw_to_ethtool_support_spds(link_info);

	if (link_info->auto_link_speeds)
		cmd->supported |= SUPPORTED_Autoneg;

	if (BNXT_AUTO_MODE(link_info->auto_mode)) {
		cmd->advertising =
			bnxt_fw_to_ethtool_advertised_spds(link_info);
		cmd->advertising |= ADVERTISED_Autoneg;
		cmd->autoneg = AUTONEG_ENABLE;
	} else {
		cmd->autoneg = AUTONEG_DISABLE;
		cmd->advertising = 0;
	}
	if (link_info->auto_pause_setting & BNXT_LINK_PAUSE_BOTH) {
		if ((link_info->auto_pause_setting & BNXT_LINK_PAUSE_BOTH) ==
		    BNXT_LINK_PAUSE_BOTH) {
			cmd->advertising |= ADVERTISED_Pause;
			cmd->supported |= SUPPORTED_Pause;
		} else {
			cmd->advertising |= ADVERTISED_Asym_Pause;
			cmd->supported |= SUPPORTED_Asym_Pause;
			if (link_info->auto_pause_setting &
			    BNXT_LINK_PAUSE_RX)
				cmd->advertising |= ADVERTISED_Pause;
		}
	} else if (link_info->force_pause_setting & BNXT_LINK_PAUSE_BOTH) {
		if ((link_info->force_pause_setting & BNXT_LINK_PAUSE_BOTH) ==
		    BNXT_LINK_PAUSE_BOTH) {
			cmd->supported |= SUPPORTED_Pause;
		} else {
			cmd->supported |= SUPPORTED_Asym_Pause;
			if (link_info->force_pause_setting &
			    BNXT_LINK_PAUSE_RX)
				cmd->supported |= SUPPORTED_Pause;
		}
	}

	cmd->port = PORT_NONE;
	if (link_info->media_type == PORT_PHY_QCFG_RESP_MEDIA_TYPE_TP) {
		cmd->port = PORT_TP;
		cmd->supported |= SUPPORTED_TP;
		cmd->advertising |= ADVERTISED_TP;
	} else {
		cmd->supported |= SUPPORTED_FIBRE;
		cmd->advertising |= ADVERTISED_FIBRE;

		if (link_info->media_type == PORT_PHY_QCFG_RESP_MEDIA_TYPE_DAC)
			cmd->port = PORT_DA;
		else if (link_info->media_type ==
			 PORT_PHY_QCFG_RESP_MEDIA_TYPE_FIBRE)
			cmd->port = PORT_FIBRE;
	}

	if (link_info->phy_link_status == BNXT_LINK_LINK) {
		if (link_info->duplex & BNXT_LINK_DUPLEX_FULL)
			cmd->duplex = DUPLEX_FULL;
	} else {
		cmd->duplex = DUPLEX_UNKNOWN;
	}
	ethtool_speed = bnxt_fw_to_ethtool_speed(link_info->link_speed);
	ethtool_cmd_speed_set(cmd, ethtool_speed);
	if (link_info->transceiver ==
		PORT_PHY_QCFG_RESP_TRANSCEIVER_TYPE_XCVR_INTERNAL)
		cmd->transceiver = XCVR_INTERNAL;
	else
		cmd->transceiver = XCVR_EXTERNAL;
	cmd->phy_address = link_info->phy_addr;

	return 0;
}

static u32 bnxt_get_fw_speed(struct net_device *dev, u16 ethtool_speed)
{
	switch (ethtool_speed) {
	case SPEED_100:
		return PORT_PHY_CFG_REQ_AUTO_LINK_SPEED_100MB;
	case SPEED_1000:
		return PORT_PHY_CFG_REQ_AUTO_LINK_SPEED_1GB;
	case SPEED_2500:
		return PORT_PHY_CFG_REQ_AUTO_LINK_SPEED_2_5GB;
	case SPEED_10000:
		return PORT_PHY_CFG_REQ_AUTO_LINK_SPEED_10GB;
	case SPEED_20000:
		return PORT_PHY_CFG_REQ_AUTO_LINK_SPEED_20GB;
	case SPEED_25000:
		return PORT_PHY_CFG_REQ_AUTO_LINK_SPEED_25GB;
	case SPEED_40000:
		return PORT_PHY_CFG_REQ_AUTO_LINK_SPEED_40GB;
	case SPEED_50000:
		return PORT_PHY_CFG_REQ_AUTO_LINK_SPEED_50GB;
	default:
		netdev_err(dev, "unsupported speed!\n");
		break;
	}
	return 0;
}

static u16 bnxt_get_fw_auto_link_speeds(u32 advertising)
{
	u16 fw_speed_mask = 0;

	/* only support autoneg at speed 100, 1000, and 10000 */
	if (advertising & (ADVERTISED_100baseT_Full |
			   ADVERTISED_100baseT_Half)) {
		fw_speed_mask |= BNXT_LINK_SPEED_MSK_100MB;
	}
	if (advertising & (ADVERTISED_1000baseT_Full |
			   ADVERTISED_1000baseT_Half)) {
		fw_speed_mask |= BNXT_LINK_SPEED_MSK_1GB;
	}
	if (advertising & ADVERTISED_10000baseT_Full)
		fw_speed_mask |= BNXT_LINK_SPEED_MSK_10GB;

	return fw_speed_mask;
}

static int bnxt_set_settings(struct net_device *dev, struct ethtool_cmd *cmd)
{
	int rc = 0;
	struct bnxt *bp = netdev_priv(dev);
	struct bnxt_link_info *link_info = &bp->link_info;
	u32 speed, fw_advertising = 0;
	bool set_pause = false;

	if (BNXT_VF(bp))
		return rc;

	if (cmd->autoneg == AUTONEG_ENABLE) {
		if (link_info->media_type != PORT_PHY_QCFG_RESP_MEDIA_TYPE_TP) {
			netdev_err(dev, "Media type doesn't support autoneg\n");
			rc = -EINVAL;
			goto set_setting_exit;
		}
		if (cmd->advertising & ~(BNXT_ALL_COPPER_ETHTOOL_SPEED |
					 ADVERTISED_Autoneg |
					 ADVERTISED_TP |
					 ADVERTISED_Pause |
					 ADVERTISED_Asym_Pause)) {
			netdev_err(dev, "Unsupported advertising mask (adv: 0x%x)\n",
				   cmd->advertising);
			rc = -EINVAL;
			goto set_setting_exit;
		}
		fw_advertising = bnxt_get_fw_auto_link_speeds(cmd->advertising);
		if (fw_advertising & ~link_info->support_speeds) {
			netdev_err(dev, "Advertising parameters are not supported! (adv: 0x%x)\n",
				   cmd->advertising);
			rc = -EINVAL;
			goto set_setting_exit;
		}
		link_info->autoneg |= BNXT_AUTONEG_SPEED;
		if (!fw_advertising)
			link_info->advertising = link_info->support_speeds;
		else
			link_info->advertising = fw_advertising;
		/* any change to autoneg will cause link change, therefore the
		 * driver should put back the original pause setting in autoneg
		 */
		set_pause = true;
	} else {
		/* TODO: currently don't support half duplex */
		if (cmd->duplex == DUPLEX_HALF) {
			netdev_err(dev, "HALF DUPLEX is not supported!\n");
			rc = -EINVAL;
			goto set_setting_exit;
		}
		/* If received a request for an unknown duplex, assume full*/
		if (cmd->duplex == DUPLEX_UNKNOWN)
			cmd->duplex = DUPLEX_FULL;
		speed = ethtool_cmd_speed(cmd);
		link_info->req_link_speed = bnxt_get_fw_speed(dev, speed);
		link_info->req_duplex = BNXT_LINK_DUPLEX_FULL;
		link_info->autoneg &= ~BNXT_AUTONEG_SPEED;
		link_info->advertising = 0;
	}

	if (netif_running(dev))
		rc = bnxt_hwrm_set_link_setting(bp, set_pause);

set_setting_exit:
	return rc;
}

static void bnxt_get_pauseparam(struct net_device *dev,
				struct ethtool_pauseparam *epause)
{
	struct bnxt *bp = netdev_priv(dev);
	struct bnxt_link_info *link_info = &bp->link_info;

	if (BNXT_VF(bp))
		return;
	epause->autoneg = !!(link_info->auto_pause_setting &
			     BNXT_LINK_PAUSE_BOTH);
	epause->rx_pause = ((link_info->pause & BNXT_LINK_PAUSE_RX) != 0);
	epause->tx_pause = ((link_info->pause & BNXT_LINK_PAUSE_TX) != 0);
}

static int bnxt_set_pauseparam(struct net_device *dev,
			       struct ethtool_pauseparam *epause)
{
	int rc = 0;
	struct bnxt *bp = netdev_priv(dev);
	struct bnxt_link_info *link_info = &bp->link_info;

	if (BNXT_VF(bp))
		return rc;

	if (epause->autoneg) {
		link_info->autoneg |= BNXT_AUTONEG_FLOW_CTRL;
		link_info->req_flow_ctrl |= BNXT_LINK_PAUSE_BOTH;
	} else {
		/* when transition from auto pause to force pause,
		 * force a link change
		 */
		if (link_info->autoneg & BNXT_AUTONEG_FLOW_CTRL)
			link_info->force_link_chng = true;
		link_info->autoneg &= ~BNXT_AUTONEG_FLOW_CTRL;
		link_info->req_flow_ctrl &= ~BNXT_LINK_PAUSE_BOTH;
	}
	if (epause->rx_pause)
		link_info->req_flow_ctrl |= BNXT_LINK_PAUSE_RX;
	else
		link_info->req_flow_ctrl &= ~BNXT_LINK_PAUSE_RX;

	if (epause->tx_pause)
		link_info->req_flow_ctrl |= BNXT_LINK_PAUSE_TX;
	else
		link_info->req_flow_ctrl &= ~BNXT_LINK_PAUSE_TX;

	if (netif_running(dev))
		rc = bnxt_hwrm_set_pause(bp);
	return rc;
}

static u32 bnxt_get_link(struct net_device *dev)
{
	struct bnxt *bp = netdev_priv(dev);

	/* TODO: handle MF, VF, driver close case */
	return bp->link_info.link_up;
}

static int bnxt_flash_nvram(struct net_device *dev,
			    u16 dir_type,
			    u16 dir_ordinal,
			    u16 dir_ext,
			    u16 dir_attr,
			    const u8 *data,
			    size_t data_len)
{
	struct bnxt *bp = netdev_priv(dev);
	int rc;
	struct hwrm_nvm_write_input req = {0};
	dma_addr_t dma_handle;
	u8 *kmem;

	bnxt_hwrm_cmd_hdr_init(bp, &req, HWRM_NVM_WRITE, -1, -1);

	req.dir_type = cpu_to_le16(dir_type);
	req.dir_ordinal = cpu_to_le16(dir_ordinal);
	req.dir_ext = cpu_to_le16(dir_ext);
	req.dir_attr = cpu_to_le16(dir_attr);
	req.dir_data_length = cpu_to_le32(data_len);

	kmem = dma_alloc_coherent(&bp->pdev->dev, data_len, &dma_handle,
				  GFP_KERNEL);
	if (!kmem) {
		netdev_err(dev, "dma_alloc_coherent failure, length = %u\n",
			   (unsigned)data_len);
		return -ENOMEM;
	}
	memcpy(kmem, data, data_len);
	req.host_src_addr = cpu_to_le64(dma_handle);

	rc = hwrm_send_message(bp, &req, sizeof(req), FLASH_NVRAM_TIMEOUT);
	dma_free_coherent(&bp->pdev->dev, data_len, kmem, dma_handle);

	return rc;
}

static int bnxt_flash_firmware(struct net_device *dev,
			       u16 dir_type,
			       const u8 *fw_data,
			       size_t fw_size)
{
	int	rc = 0;
	u16	code_type;
	u32	stored_crc;
	u32	calculated_crc;
	struct bnxt_fw_header *header = (struct bnxt_fw_header *)fw_data;

	switch (dir_type) {
	case BNX_DIR_TYPE_BOOTCODE:
	case BNX_DIR_TYPE_BOOTCODE_2:
		code_type = CODE_BOOT;
		break;
	default:
		netdev_err(dev, "Unsupported directory entry type: %u\n",
			   dir_type);
		return -EINVAL;
	}
	if (fw_size < sizeof(struct bnxt_fw_header)) {
		netdev_err(dev, "Invalid firmware file size: %u\n",
			   (unsigned int)fw_size);
		return -EINVAL;
	}
	if (header->signature != cpu_to_le32(BNXT_FIRMWARE_BIN_SIGNATURE)) {
		netdev_err(dev, "Invalid firmware signature: %08X\n",
			   le32_to_cpu(header->signature));
		return -EINVAL;
	}
	if (header->code_type != code_type) {
		netdev_err(dev, "Expected firmware type: %d, read: %d\n",
			   code_type, header->code_type);
		return -EINVAL;
	}
	if (header->device != DEVICE_CUMULUS_FAMILY) {
		netdev_err(dev, "Expected firmware device family %d, read: %d\n",
			   DEVICE_CUMULUS_FAMILY, header->device);
		return -EINVAL;
	}
	/* Confirm the CRC32 checksum of the file: */
	stored_crc = le32_to_cpu(*(__le32 *)(fw_data + fw_size -
					     sizeof(stored_crc)));
	calculated_crc = ~crc32(~0, fw_data, fw_size - sizeof(stored_crc));
	if (calculated_crc != stored_crc) {
		netdev_err(dev, "Firmware file CRC32 checksum (%08lX) does not match calculated checksum (%08lX)\n",
			   (unsigned long)stored_crc,
			   (unsigned long)calculated_crc);
		return -EINVAL;
	}
	/* TODO: Validate digital signature (RSA-encrypted SHA-256 hash) here */
	rc = bnxt_flash_nvram(dev, dir_type, BNX_DIR_ORDINAL_FIRST,
			      0, 0, fw_data, fw_size);
	if (rc == 0) {	/* Firmware update successful */
		/* TODO: Notify processor it needs to reset itself
		 */
	}
	return rc;
}

static bool bnxt_dir_type_is_ape_bin_format(u16 dir_type)
{
	switch (dir_type) {
	case BNX_DIR_TYPE_CHIMP_PATCH:
	case BNX_DIR_TYPE_BOOTCODE:
	case BNX_DIR_TYPE_BOOTCODE_2:
	case BNX_DIR_TYPE_APE_FW:
	case BNX_DIR_TYPE_APE_PATCH:
	case BNX_DIR_TYPE_KONG_FW:
	case BNX_DIR_TYPE_KONG_PATCH:
		return true;
	}

	return false;
}

static bool bnxt_dir_type_is_unprotected_exec_format(u16 dir_type)
{
	switch (dir_type) {
	case BNX_DIR_TYPE_AVS:
	case BNX_DIR_TYPE_EXP_ROM_MBA:
	case BNX_DIR_TYPE_PCIE:
	case BNX_DIR_TYPE_TSCF_UCODE:
	case BNX_DIR_TYPE_EXT_PHY:
	case BNX_DIR_TYPE_CCM:
	case BNX_DIR_TYPE_ISCSI_BOOT:
	case BNX_DIR_TYPE_ISCSI_BOOT_IPV6:
	case BNX_DIR_TYPE_ISCSI_BOOT_IPV4N6:
		return true;
	}

	return false;
}

static bool bnxt_dir_type_is_executable(u16 dir_type)
{
	return bnxt_dir_type_is_ape_bin_format(dir_type) ||
		bnxt_dir_type_is_unprotected_exec_format(dir_type);
}

static int bnxt_flash_firmware_from_file(struct net_device *dev,
					 u16 dir_type,
					 const char *filename)
{
	const struct firmware  *fw;
	int			rc;

	if (bnxt_dir_type_is_executable(dir_type) == false)
		return -EINVAL;

	rc = request_firmware(&fw, filename, &dev->dev);
	if (rc != 0) {
		netdev_err(dev, "Error %d requesting firmware file: %s\n",
			   rc, filename);
		return rc;
	}
	if (bnxt_dir_type_is_ape_bin_format(dir_type) == true)
		rc = bnxt_flash_firmware(dev, dir_type, fw->data, fw->size);
	else
		rc = bnxt_flash_nvram(dev, dir_type, BNX_DIR_ORDINAL_FIRST,
				      0, 0, fw->data, fw->size);
	release_firmware(fw);
	return rc;
}

static int bnxt_flash_package_from_file(struct net_device *dev,
					char *filename)
{
	netdev_err(dev, "packages are not yet supported\n");
	return -EINVAL;
}

static int bnxt_flash_device(struct net_device *dev,
			     struct ethtool_flash *flash)
{
	if (!BNXT_PF((struct bnxt *)netdev_priv(dev))) {
		netdev_err(dev, "flashdev not supported from a virtual function\n");
		return -EINVAL;
	}

	if (flash->region == ETHTOOL_FLASH_ALL_REGIONS)
		return bnxt_flash_package_from_file(dev, flash->data);

	return bnxt_flash_firmware_from_file(dev, flash->region, flash->data);
}

static int nvm_get_dir_info(struct net_device *dev, u32 *entries, u32 *length)
{
	struct bnxt *bp = netdev_priv(dev);
	int rc;
	struct hwrm_nvm_get_dir_info_input req = {0};
	struct hwrm_nvm_get_dir_info_output *output = bp->hwrm_cmd_resp_addr;

	bnxt_hwrm_cmd_hdr_init(bp, &req, HWRM_NVM_GET_DIR_INFO, -1, -1);

	mutex_lock(&bp->hwrm_cmd_lock);
	rc = _hwrm_send_message(bp, &req, sizeof(req), HWRM_CMD_TIMEOUT);
	if (!rc) {
		*entries = le32_to_cpu(output->entries);
		*length = le32_to_cpu(output->entry_length);
	}
	mutex_unlock(&bp->hwrm_cmd_lock);
	return rc;
}

static int bnxt_get_eeprom_len(struct net_device *dev)
{
	/* The -1 return value allows the entire 32-bit range of offsets to be
	 * passed via the ethtool command-line utility.
	 */
	return -1;
}

static int bnxt_get_nvram_directory(struct net_device *dev, u32 len, u8 *data)
{
	struct bnxt *bp = netdev_priv(dev);
	int rc;
	u32 dir_entries;
	u32 entry_length;
	u8 *buf;
	size_t buflen;
	dma_addr_t dma_handle;
	struct hwrm_nvm_get_dir_entries_input req = {0};

	rc = nvm_get_dir_info(dev, &dir_entries, &entry_length);
	if (rc != 0)
		return rc;

	/* Insert 2 bytes of directory info (count and size of entries) */
	if (len < 2)
		return -EINVAL;

	*data++ = dir_entries;
	*data++ = entry_length;
	len -= 2;
	memset(data, 0xff, len);

	buflen = dir_entries * entry_length;
	buf = dma_alloc_coherent(&bp->pdev->dev, buflen, &dma_handle,
				 GFP_KERNEL);
	if (!buf) {
		netdev_err(dev, "dma_alloc_coherent failure, length = %u\n",
			   (unsigned)buflen);
		return -ENOMEM;
	}
	bnxt_hwrm_cmd_hdr_init(bp, &req, HWRM_NVM_GET_DIR_ENTRIES, -1, -1);
	req.host_dest_addr = cpu_to_le64(dma_handle);
	rc = hwrm_send_message(bp, &req, sizeof(req), HWRM_CMD_TIMEOUT);
	if (rc == 0)
		memcpy(data, buf, len > buflen ? buflen : len);
	dma_free_coherent(&bp->pdev->dev, buflen, buf, dma_handle);
	return rc;
}

static int bnxt_get_nvram_item(struct net_device *dev, u32 index, u32 offset,
			       u32 length, u8 *data)
{
	struct bnxt *bp = netdev_priv(dev);
	int rc;
	u8 *buf;
	dma_addr_t dma_handle;
	struct hwrm_nvm_read_input req = {0};

	buf = dma_alloc_coherent(&bp->pdev->dev, length, &dma_handle,
				 GFP_KERNEL);
	if (!buf) {
		netdev_err(dev, "dma_alloc_coherent failure, length = %u\n",
			   (unsigned)length);
		return -ENOMEM;
	}
	bnxt_hwrm_cmd_hdr_init(bp, &req, HWRM_NVM_READ, -1, -1);
	req.host_dest_addr = cpu_to_le64(dma_handle);
	req.dir_idx = cpu_to_le16(index);
	req.offset = cpu_to_le32(offset);
	req.len = cpu_to_le32(length);

	rc = hwrm_send_message(bp, &req, sizeof(req), HWRM_CMD_TIMEOUT);
	if (rc == 0)
		memcpy(data, buf, length);
	dma_free_coherent(&bp->pdev->dev, length, buf, dma_handle);
	return rc;
}

static int bnxt_get_eeprom(struct net_device *dev,
			   struct ethtool_eeprom *eeprom,
			   u8 *data)
{
	u32 index;
	u32 offset;

	if (eeprom->offset == 0) /* special offset value to get directory */
		return bnxt_get_nvram_directory(dev, eeprom->len, data);

	index = eeprom->offset >> 24;
	offset = eeprom->offset & 0xffffff;

	if (index == 0) {
		netdev_err(dev, "unsupported index value: %d\n", index);
		return -EINVAL;
	}

	return bnxt_get_nvram_item(dev, index - 1, offset, eeprom->len, data);
}

static int bnxt_erase_nvram_directory(struct net_device *dev, u8 index)
{
	struct bnxt *bp = netdev_priv(dev);
	struct hwrm_nvm_erase_dir_entry_input req = {0};

	bnxt_hwrm_cmd_hdr_init(bp, &req, HWRM_NVM_ERASE_DIR_ENTRY, -1, -1);
	req.dir_idx = cpu_to_le16(index);
	return hwrm_send_message(bp, &req, sizeof(req), HWRM_CMD_TIMEOUT);
}

static int bnxt_set_eeprom(struct net_device *dev,
			   struct ethtool_eeprom *eeprom,
			   u8 *data)
{
	struct bnxt *bp = netdev_priv(dev);
	u8 index, dir_op;
	u16 type, ext, ordinal, attr;

	if (!BNXT_PF(bp)) {
		netdev_err(dev, "NVM write not supported from a virtual function\n");
		return -EINVAL;
	}

	type = eeprom->magic >> 16;

	if (type == 0xffff) { /* special value for directory operations */
		index = eeprom->magic & 0xff;
		dir_op = eeprom->magic >> 8;
		if (index == 0)
			return -EINVAL;
		switch (dir_op) {
		case 0x0e: /* erase */
			if (eeprom->offset != ~eeprom->magic)
				return -EINVAL;
			return bnxt_erase_nvram_directory(dev, index - 1);
		default:
			return -EINVAL;
		}
	}

	/* Create or re-write an NVM item: */
	if (bnxt_dir_type_is_executable(type) == true)
		return -EINVAL;
	ext = eeprom->magic & 0xffff;
	ordinal = eeprom->offset >> 16;
	attr = eeprom->offset & 0xffff;

	return bnxt_flash_nvram(dev, type, ordinal, ext, attr, data,
				eeprom->len);
}

const struct ethtool_ops bnxt_ethtool_ops = {
	.get_settings		= bnxt_get_settings,
	.set_settings		= bnxt_set_settings,
	.get_pauseparam		= bnxt_get_pauseparam,
	.set_pauseparam		= bnxt_set_pauseparam,
	.get_drvinfo		= bnxt_get_drvinfo,
	.get_coalesce		= bnxt_get_coalesce,
	.set_coalesce		= bnxt_set_coalesce,
	.get_msglevel		= bnxt_get_msglevel,
	.set_msglevel		= bnxt_set_msglevel,
	.get_sset_count		= bnxt_get_sset_count,
	.get_strings		= bnxt_get_strings,
	.get_ethtool_stats	= bnxt_get_ethtool_stats,
	.set_ringparam		= bnxt_set_ringparam,
	.get_ringparam		= bnxt_get_ringparam,
	.get_channels		= bnxt_get_channels,
	.set_channels		= bnxt_set_channels,
#ifdef CONFIG_RFS_ACCEL
	.get_rxnfc		= bnxt_get_rxnfc,
#endif
	.get_rxfh_indir_size    = bnxt_get_rxfh_indir_size,
	.get_rxfh_key_size      = bnxt_get_rxfh_key_size,
	.get_rxfh               = bnxt_get_rxfh,
	.flash_device		= bnxt_flash_device,
	.get_eeprom_len         = bnxt_get_eeprom_len,
	.get_eeprom             = bnxt_get_eeprom,
	.set_eeprom		= bnxt_set_eeprom,
	.get_link		= bnxt_get_link,
};
