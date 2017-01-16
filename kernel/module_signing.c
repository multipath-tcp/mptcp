/* Module signature checker
 *
 * Copyright (C) 2012 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public Licence
 * as published by the Free Software Foundation; either version
 * 2 of the Licence, or (at your option) any later version.
 */

#include <linux/kernel.h>
#include <linux/errno.h>
#include <keys/system_keyring.h>
#include <crypto/public_key.h>
#include "module-internal.h"

/*
 * Module signature information block.
 *
 * The constituents of the signature section are, in order:
 *
 *	- Signer's name
 *	- Key identifier
 *	- Signature data
 *	- Information block
 */
struct module_signature {
	u8	algo;		/* Public-key crypto algorithm [0] */
	u8	hash;		/* Digest algorithm [0] */
	u8	id_type;	/* Key identifier type [PKEY_ID_PKCS7] */
	u8	signer_len;	/* Length of signer's name [0] */
	u8	key_id_len;	/* Length of key identifier [0] */
	u8	__pad[3];
	__be32	sig_len;	/* Length of signature data */
};

/*
 * Verify the signature on a module.
 */
int mod_verify_sig(const void *mod, unsigned long *_modlen)
{
	struct module_signature ms;
	size_t modlen = *_modlen, sig_len;

	pr_devel("==>%s(,%zu)\n", __func__, modlen);

	if (modlen <= sizeof(ms))
		return -EBADMSG;

	memcpy(&ms, mod + (modlen - sizeof(ms)), sizeof(ms));
	modlen -= sizeof(ms);

	sig_len = be32_to_cpu(ms.sig_len);
	if (sig_len >= modlen)
		return -EBADMSG;
	modlen -= sig_len;
	*_modlen = modlen;

	if (ms.id_type != PKEY_ID_PKCS7) {
		pr_err("Module is not signed with expected PKCS#7 message\n");
		return -ENOPKG;
	}

	if (ms.algo != 0 ||
	    ms.hash != 0 ||
	    ms.signer_len != 0 ||
	    ms.key_id_len != 0 ||
	    ms.__pad[0] != 0 ||
	    ms.__pad[1] != 0 ||
	    ms.__pad[2] != 0) {
		pr_err("PKCS#7 signature info has unexpected non-zero params\n");
		return -EBADMSG;
	}

	return system_verify_data(mod, modlen, mod + modlen, sig_len,
				  VERIFYING_MODULE_SIGNATURE);
}
