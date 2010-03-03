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
 	u32     mtcp_rem_token; /* Remote token, for mptcp*/
#endif
};

#endif /*_TCP_OPTIONS_H*/
