/*
 *	Linux SHIM6 implementation
 *
 *	Author:
 *	Sébastien Barré		<sebastien.barre@uclouvain.be>
 *
 *	date : October 2007
 *
 *	This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 *
 */

#ifndef _LINUX_SHIM6_H
#define _LINUX_SHIM6_H

#ifndef __KERNEL__
#include <sys/types.h>
#include <netinet/in.h>
#else
#include <linux/in6.h>
#include <asm/byteorder.h>
#include <asm/types.h>
#endif /*__KERNEL__*/
#include <linux/netlink.h>

struct shim6_path {
	struct in6_addr    local;
	struct in6_addr    remote;
	uint8_t            flags;
#define PROBED 0x1
#define SHIM6_DATA_TRANSLATE 0x2 /* Translation activated*/
};

/*shim6 data to be stored inside struct xfrm_state*/
struct shim6_data {
	/*inbound - ct is ct_local
	 *outbound - ct is ct_peer*/
	__u64               ct;
/*flags*/
	__u8		    flags;
#define SHIM6_DATA_INBOUND   0x1 /* context is inbound*/
#define SHIM6_DATA_UPD       0x2 /* context update*/

	/*inbound - local is ULID_local, remote is ULID_peer
	 *outbound - local is lp_local, remote is lp_peer 
	 *     Only for outbound multiple simultaneous paths can
	 *     be defined (multipath) 
	 */
	int                 npaths; /*1 if inbound or normal shim6, 
				      n paths if outbound and multipath mode*/
	int                 cur_path_idx; /*Index of the path currently used*/
	struct shim6_path   paths[0];	
};

/*Computes the total length of a struct shim6_data (including paths)
 * @data must be a struct shim6_data*
 */
#define SHIM6_DATA_LENGTH(data) (sizeof(*(data))+			\
				 (data)->npaths*sizeof(struct shim6_path)) 


/*type values for shim6 messages*/
enum shim6_types_init {
	SHIM6_TYPE_I1 = 1,
	SHIM6_TYPE_R1,
	SHIM6_TYPE_I2,
	SHIM6_TYPE_R2,
	SHIM6_TYPE_R1BIS,
	SHIM6_TYPE_I2BIS,
	SHIM6_TYPE_INIT_MAX
};

enum shim6_types_comm {
	SHIM6_TYPE_UPD_REQ = 64, /*update request*/
	SHIM6_TYPE_UPD_ACK,      /*update aknowledgement*/
	SHIM6_TYPE_KEEPALIVE,
	SHIM6_TYPE_PROBE,
	SHIM6_TYPE_COMM_MAX
};


/* get a context tag, from its parts in a message
 * @ct is in host byte order
 * @ct1, @ct2, @ct3 are in network byte order*/
static inline void get_ct(__u64* ct, __u8 ct_1, __u8 ct_2, __u32 ct_3) 
{
	__u64 temp_ct;
	*ct=ct_1;
	*ct<<=40;
	temp_ct=ct_2;
	*ct+=(temp_ct<<32) + ntohl(ct_3);
}

/* set a context tag, to its parts in a message
 * @ct is in host byte order
 * @ct1, @ct2, @ct3 are in network byte order
 *
 * We define it as a macro, since ct_1 is a bit field, and we cannot pass the
 * address of a bitfield as an argument to a function.
 */

#define set_ct(ct, ct_1, ct_2, ct_3) \
	do {ct_1=(ct>>40)&0x7F; \
 ct_2=(ct>>32)&0xFF; \
 ct_3=htonl(ct&0xFFFFFFFF); } while(0);

/*defines for computing size of option fields in shim6 packets
 * @length is the length of the option field, without padding nor tl header*/
#define TOTAL_LENGTH(length) (11+length-(length+3)%8) /*see section 5.15
							(draft shim6-proto-08)*/
#define PAD_LENGTH(length) (7 - ((length+3)%8))

/*Common part for shim6/reap control messages*/
struct shim6hdr_ctl
{
	__u8    nexthdr; /*MUST be NEXTHDR_NONE*/
	__u8    hdrlen;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u16   type:7,
		P:1,
		hip_compat:1, /*MUST be 0*/
	        type_spec:7;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__u16   P:1,
		type:7,
		type_spec:7,
		hip_compat:1;
#else
#error Problem with endianness: fix either configure script (user sp.) or \
	<asm/byteorder.h> (kernel space)
#endif
	__u16   csum;	
};

/*Possible values for the P bit*/
#define SHIM6_MSG_CONTROL              0
#define SHIM6_MSG_PAYLOAD              1

/*=================
 *  Shim6 Listener
 *=================
 */

extern void shim6_listener_init(void);
extern void shim6_listener_exit(void);


/*=================
 *     REAP
 *=================
 */


/* Maximum number of probe reports in the sent or recvd part
 * Currently it is 15, the maximum allowed by the size of
 * the precvd field in the probe message.
 */
#define MAX_SENT_PROBES_REPORT        15
#define MAX_RECVD_PROBES_REPORT       15


#define MAX_PROBE_LEN (16+MAX_SENT_PROBES_REPORT*40+ \
                          MAX_RECVD_PROBES_REPORT*40)
#define MIN_PROBE_LEN 56 /*A probe with only one probe report (at least
			   one sent probe report is mandatory, and is the 
			   probe currently sent)*/
#define MAX_SHIM6_PATHS 32 /*Max number of paths that Shim6 can manage*/


/*REAP states*/
#define REAP_OPERATIONAL              0
#define REAP_EXPLORING                1
#define REAP_INBOUND_OK               2

/*REAP default parameters*/
#define REAP_SEND_TIMEOUT             15 /*seconds*/

/*Structures for the probe messages. We have two structures :
 * - The first is structure for the beginning of the probe message.
 * - The second is the 'sent probes' and 'recvd probes' report part, there 
 *   are psent+precvd (struct reaphdr_probe) copies of this structure in one 
 *   probe message.
 */

struct reaphdr_probe
{
	struct shim6hdr_ctl common;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u8    ct_1:7,
		R:1; /*Reserved : zero on transmit*/	  
#elif defined(__BIG_ENDIAN_BITFIELD)
	__u8    R:1, /*Reserved : zero on transmit*/
	        ct_1:7;
#else
#error Problem with endianness: fix either configure script (user sp.) or \
<asm/byteorder.h> (kernel space)
#endif
	__u8    ct_2;
	__u32   ct_3;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u16   psent:4,
		precvd:4,
		reserved_1:6,
		 sta:2;		
#elif defined(__BIG_ENDIAN_BITFIELD)
	 __u16   precvd:4,
		 psent:4,
		 sta:2,	     
		 reserved_1:6;
#else
#error Problem with endianness: fix either configure script (user sp.) or \
<asm/byteorder.h> (kernel space)
#endif
	__u16   reserved_2;
};

typedef struct reaphdr_probe reaphdr_probe;

/*This is the last part */
 struct probe_address
 {
	 struct in6_addr src;
	 struct in6_addr dest;
	 __u32           nonce;
	 __u32           option;
 };


/*Structure for the reap keepalive*/

struct reaphdr_ka
{
	struct shim6hdr_ctl common;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u8    ct_1:7,
		R:1; /*Reserved : zero on transmit*/	  
#elif defined(__BIG_ENDIAN_BITFIELD)
	__u8    R:1, /*Reserved : zero on transmit*/
	        ct_1:7;
#else
#error Problem with endianness: fix either configure script (user sp.) or \
<asm/byteorder.h> (kernel space)
#endif
	__u8    ct_2;
	__u32   ct_3;
	__u32   pad; /*to have a length multiple of 8 octets*/
};

typedef struct reaphdr_ka reaphdr_ka;

/*REAP messages types*/
#define REAP_TYPE_KEEPALIVE           66
#define REAP_TYPE_PROBE               67


/* Maximum number of probe reports in the sent or recvd part
 * Currently it is 15, the maximum allowed by the size of
 * the precvd field in the probe message.
*/
#define MAX_SENT_PROBES_REPORT        15
#define MAX_RECVD_PROBES_REPORT       15


#define MAX_CTL_LEN 1280 /*Max length for shim6 ctl pkts, including IPv6
			   header and any option between the IPv6 header and
			   the shim6 header - section 5.1*/
#define MIN_PROBE_LEN 56 /*A probe with only one probe report (at least
			   one sent probe report is mandatory, and is the 
			   probe currently sent)*/


#endif /*_LINUX_SHIM6_H*/
