/* QLogic qed NIC Driver
 * Copyright (c) 2015 QLogic Corporation
 *
 * This software is available under the terms of the GNU General Public License
 * (GPL) Version 2, available from the file COPYING in the main directory of
 * this source tree.
 */

#include <linux/types.h>
#include <asm/byteorder.h>
#include <linux/bitops.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include "qed.h"
#include <linux/qed/qed_chain.h>
#include "qed_cxt.h"
#include "qed_hsi.h"
#include "qed_hw.h"
#include "qed_int.h"
#include "qed_reg_addr.h"
#include "qed_sp.h"

int qed_sp_init_request(struct qed_hwfn *p_hwfn,
			struct qed_spq_entry **pp_ent,
			u32 cid,
			u16 opaque_fid,
			u8 cmd,
			u8 protocol,
			struct qed_sp_init_request_params *p_params)
{
	int rc = -EINVAL;
	struct qed_spq_entry *p_ent = NULL;
	u32 opaque_cid = opaque_fid << 16 | cid;

	if (!pp_ent)
		return -ENOMEM;

	rc = qed_spq_get_entry(p_hwfn, pp_ent);

	if (rc != 0)
		return rc;

	p_ent = *pp_ent;

	p_ent->elem.hdr.cid		= cpu_to_le32(opaque_cid);
	p_ent->elem.hdr.cmd_id		= cmd;
	p_ent->elem.hdr.protocol_id	= protocol;

	p_ent->priority		= QED_SPQ_PRIORITY_NORMAL;
	p_ent->comp_mode	= p_params->comp_mode;
	p_ent->comp_done.done	= 0;

	switch (p_ent->comp_mode) {
	case QED_SPQ_MODE_EBLOCK:
		p_ent->comp_cb.cookie = &p_ent->comp_done;
		break;

	case QED_SPQ_MODE_BLOCK:
		if (!p_params->p_comp_data)
			return -EINVAL;

		p_ent->comp_cb.cookie = p_params->p_comp_data->cookie;
		break;

	case QED_SPQ_MODE_CB:
		if (!p_params->p_comp_data)
			p_ent->comp_cb.function = NULL;
		else
			p_ent->comp_cb = *p_params->p_comp_data;
		break;

	default:
		DP_NOTICE(p_hwfn, "Unknown SPQE completion mode %d\n",
			  p_ent->comp_mode);
		return -EINVAL;
	}

	DP_VERBOSE(p_hwfn, QED_MSG_SPQ,
		   "Initialized: CID %08x cmd %02x protocol %02x data_addr %lu comp_mode [%s]\n",
		   opaque_cid, cmd, protocol,
		   (unsigned long)&p_ent->ramrod,
		   D_TRINE(p_ent->comp_mode, QED_SPQ_MODE_EBLOCK,
			   QED_SPQ_MODE_BLOCK, "MODE_EBLOCK", "MODE_BLOCK",
			   "MODE_CB"));
	if (p_params->ramrod_data_size)
		memset(&p_ent->ramrod, 0, p_params->ramrod_data_size);

	return 0;
}

int qed_sp_pf_start(struct qed_hwfn *p_hwfn,
		    enum mf_mode mode)
{
	struct qed_sp_init_request_params params;
	struct pf_start_ramrod_data *p_ramrod = NULL;
	u16 sb = qed_int_get_sp_sb_id(p_hwfn);
	u8 sb_index = p_hwfn->p_eq->eq_sb_index;
	struct qed_spq_entry *p_ent = NULL;
	int rc = -EINVAL;

	/* update initial eq producer */
	qed_eq_prod_update(p_hwfn,
			   qed_chain_get_prod_idx(&p_hwfn->p_eq->chain));

	memset(&params, 0, sizeof(params));
	params.ramrod_data_size = sizeof(*p_ramrod);
	params.comp_mode = QED_SPQ_MODE_EBLOCK;

	rc = qed_sp_init_request(p_hwfn,
				 &p_ent,
				 qed_spq_get_cid(p_hwfn),
				 p_hwfn->hw_info.opaque_fid,
				 COMMON_RAMROD_PF_START,
				 PROTOCOLID_COMMON,
				 &params);
	if (rc)
		return rc;

	p_ramrod = &p_ent->ramrod.pf_start;

	p_ramrod->event_ring_sb_id	= cpu_to_le16(sb);
	p_ramrod->event_ring_sb_index	= sb_index;
	p_ramrod->path_id		= QED_PATH_ID(p_hwfn);
	p_ramrod->dont_log_ramrods	= 0;
	p_ramrod->log_type_mask		= cpu_to_le16(0xf);
	p_ramrod->mf_mode = mode;
	p_ramrod->outer_tag = p_hwfn->hw_info.ovlan;

	/* Place EQ address in RAMROD */
	p_ramrod->event_ring_pbl_addr.hi =
			DMA_HI_LE(p_hwfn->p_eq->chain.pbl.p_phys_table);
	p_ramrod->event_ring_pbl_addr.lo =
			DMA_LO_LE(p_hwfn->p_eq->chain.pbl.p_phys_table);
	p_ramrod->event_ring_num_pages = (u8)p_hwfn->p_eq->chain.page_cnt;

	p_ramrod->consolid_q_pbl_addr.hi =
			DMA_HI_LE(p_hwfn->p_consq->chain.pbl.p_phys_table);
	p_ramrod->consolid_q_pbl_addr.lo =
			DMA_LO_LE(p_hwfn->p_consq->chain.pbl.p_phys_table);

	p_hwfn->hw_info.personality = PERSONALITY_ETH;

	DP_VERBOSE(p_hwfn, QED_MSG_SPQ,
		   "Setting event_ring_sb [id %04x index %02x], mf [%s] outer_tag [%d]\n",
		   sb, sb_index,
		   (p_ramrod->mf_mode == SF) ? "SF" : "Multi-Pf",
		   p_ramrod->outer_tag);

	return qed_spq_post(p_hwfn, p_ent, NULL);
}

int qed_sp_pf_stop(struct qed_hwfn *p_hwfn)
{
	struct qed_sp_init_request_params params;
	struct qed_spq_entry *p_ent = NULL;
	int rc = -EINVAL;

	memset(&params, 0, sizeof(params));
	params.comp_mode = QED_SPQ_MODE_EBLOCK;

	rc = qed_sp_init_request(p_hwfn, &p_ent, qed_spq_get_cid(p_hwfn),
				 p_hwfn->hw_info.opaque_fid,
				 COMMON_RAMROD_PF_STOP, PROTOCOLID_COMMON,
				 &params);
	if (rc)
		return rc;

	return qed_spq_post(p_hwfn, p_ent, NULL);
}
