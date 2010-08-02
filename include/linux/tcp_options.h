/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Definitions for the TCP module.
 *
 * Version:	@(#)tcp.h	1.0.5	05/23/93
 *
 * Authors:	Ross Biro
 *		Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *              S. Barré: Added this file, to recuperate a portion
 *              of the previous tcp.h file, in order to support mtcp
 *              includes interdependence.
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */

#ifndef _TCP_OPTIONS_H
#define _TCP_OPTIONS_H

#include <linux/types.h>
#include <net/mtcp_pm.h>

#define OPTION_SACK_ADVERTISE	(1 << 0)
#define OPTION_TS		(1 << 1)
#define OPTION_MD5		(1 << 2)
#define OPTION_MPC              (1 << 3)
#define OPTION_TOKEN            (1 << 4)
#define OPTION_DSN              (1 << 5)
#define OPTION_ADDR             (1 << 6)
#define OPTION_JOIN             (1 << 7)

struct tcp_out_options {
	u8 options;		/* bit field of OPTION_* */
	u8 ws;			/* window scale, 0 to disable */
	u8 num_sack_blocks;	/* number of SACK blocks to include */
	u16 mss;		/* 0 to disable */
	__u32 tsval, tsecr;	/* need to include OPTION_TS */
	__u32 data_seq;         /* data sequence number, for MPTCP */
	__u16 data_len;         /* data level length, for MPTCP*/
	__u32 sub_seq;          /* subflow seqnum, for MPTCP*/
#ifdef CONFIG_MTCP_PM
	__u32 token;            /* token for mptcp */
	struct mtcp_loc4 *addr4;  /* v4 addresses for MPTCP */
	int num_addr4;          /* Number of addresses v4, MPTCP*/
	u8      addr_id;        /* address id */
#endif
};

struct tcp_options_received {
/*	PAWS/RTTM data	*/
	long	ts_recent_stamp;/* Time we stored ts_recent (for aging) */
	u32	ts_recent;	/* Time stamp to echo next		*/
	u32	rcv_tsval;	/* Time stamp value             	*/
	u32	rcv_tsecr;	/* Time stamp echo reply        	*/
	u32 	saw_tstamp : 1,	/* Saw TIMESTAMP on last packet		*/
		tstamp_ok : 1,	/* TIMESTAMP seen on SYN packet		*/
		dsack : 1,	/* D-SACK is scheduled			*/
		wscale_ok : 1,	/* Wscale seen on SYN packet		*/
		sack_ok : 4,	/* SACK seen on SYN packet		*/
		snd_wscale : 4,	/* Window scaling received from sender	*/
		rcv_wscale : 4,	/* Window scaling to send to receiver	*/
		saw_mpc : 1;    /* MPC option seen, for MPTCP */
/*	SACKs data	*/
	u8	eff_sacks;	/* Size of SACK array to send with next packet */
	u8	num_sacks;	/* Number of SACK blocks		*/
	u16	user_mss;  	/* mss requested by user in ioctl */
	u16	mss_clamp;	/* Maximal mss, negotiated at connection setup */
#ifdef CONFIG_MTCP_PM
 	u32     mtcp_rem_token; /* Remote token, for mptcp */
	u32     rcv_isn; /*Needed to retrieve abs subflow seqnum from the
			   relative version.*/	
#endif
};

struct multipath_options {	
#ifdef CONFIG_MTCP_PM
	int    num_addr4; 
	int    num_addr6;
	struct mtcp_loc4 addr4[MTCP_MAX_ADDR];
	struct mtcp_loc6 addr6[MTCP_MAX_ADDR];
	u8     list_rcvd:1; /*1 if IP list has been received*/	
#endif
};

#endif /*_TCP_OPTIONS_H*/
