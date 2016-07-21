/*
 * Copyright (C) 2013 Matthew Garrett <matthew.garrett at nebula.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

FILE_LICENCE ( GPL2_OR_LATER );

#include <errno.h>
#include <realmode.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <ipxe/command.h>
#include <ipxe/parseopt.h>
#include <ipxe/image.h>
#include <ipxe/crypto.h>
#include <ipxe/sha1.h>
#include <usr/imgmgmt.h>

#undef ERRFILE
#define ERRFILE ERRFILE_tpm

/** @file
 *
 * TPM commands
 *
 */

/** "tpm" options */
struct tpm_options {};

/** "tpm" option list */
static struct option_descriptor tpm_opts[] = {};

/** "tpm" command descriptor */
static struct command_descriptor tpm_cmd =
	COMMAND_DESC ( struct tpm_options, tpm_opts, 2, 2,
		       "<image> <pcr>" );

static uint8_t __data16_array ( tcg_buffer, [0x2a] );
#define tcg_buffer __use_data16 ( tcg_buffer )

int tpm_present ( void ) {
	uint32_t tcg_ret = 0;

	__asm__ __volatile__ ( REAL_CODE ( "int $0x1a\n\t" )
			       : "=a" ( tcg_ret )
			       : "a" ( 0xbb00 ),
				 "b" ( 0x41504354 )
			       : "%esi", "%edi", "%ecx");
	if (tcg_ret == 0)
		return 1;

	return 0;
}

int update_pcr ( unsigned int pcr, uint8_t *digest ) {
	unsigned int i;
	uint16_t tcg_ret = 0;

	// Input Parameter Block

	tcg_buffer[0x0] = 0x2a;
	tcg_buffer[0x1] = 0x0; // 0x002a ibl +8
	tcg_buffer[0x2] = 0x0;
	tcg_buffer[0x3] = 0x0; // 0x0000
	tcg_buffer[0x4] = 0x22;
	tcg_buffer[0x5] = 0x0; // 0x0022 obl +4
	tcg_buffer[0x6] = 0x0;
	tcg_buffer[0x7] = 0x0; // 0x0000

	// TCG Command

	tcg_buffer[0x8] = 0x0;
	tcg_buffer[0x9] = 0xc1; // 0x00c1 tag
	tcg_buffer[0xA] = 0x0;
	tcg_buffer[0xB] = 0x0;
	tcg_buffer[0xC] = 0x0;
	tcg_buffer[0xD] = 0x22; // 0x00000022 length
	tcg_buffer[0xE] = 0x0;
	tcg_buffer[0xF] = 0x0;
	tcg_buffer[0x10] = 0x0;
	tcg_buffer[0x11] = 0x14; // 0x00000014 command ordinal
	tcg_buffer[0x12] = 0;
	tcg_buffer[0x13] = 0;
	tcg_buffer[0x14] = 0;
	tcg_buffer[0x15] = pcr;

	for ( i = 0; i < sha1_algorithm.digestsize; i++ ) {
		tcg_buffer[0x16+i] = digest[i];
	}

	__asm__ __volatile__ ( REAL_CODE ( "int $0x1a\n\t" )
			       : "=a" ( tcg_ret )
			       : "a" ( 0xbb02 ),
				 "b" ( 0x41504354 ),
				 "c" ( 0 ),
				 "d" ( 0 ),
				 "D" ( ( __from_data16( tcg_buffer ) ) ),
				 "S" ( ( __from_data16( tcg_buffer ) ) ) );

	if (tcg_ret) {
		DBG ( "Received error code from TPM: %x\n", tcg_ret );
		return -EIO;
	}

	return 0;
}

/**
 * Generate a sha1 hash an image
 *
 * @v image		Image to hash
 * @v digest_out	Output buffer. Must be at least 20 bytes long.
 */
void hash_image ( struct image *image, uint8_t *digest_out ) {
	struct digest_algorithm *digest = &sha1_algorithm;
	uint8_t digest_ctx[digest->ctxsize];
	uint8_t buf[128];
	size_t offset;
	size_t len;
	size_t frag_len;

	offset = 0;
	len = image->len;

	/* calculate digest */
	digest_init ( digest, digest_ctx );
	while ( len ) {
		frag_len = len;
		if ( frag_len > sizeof ( buf ) )
			frag_len = sizeof ( buf );
		copy_from_user ( buf, image->data, offset, frag_len );
		digest_update ( digest, digest_ctx, buf, frag_len );
		len -= frag_len;
		offset += frag_len;
	}
	digest_final ( digest, digest_ctx, digest_out );
}
/**
 * The "tpm" command
 *
 * @v argc		Argument count
 * @v argv		Argument list
 * @ret rc		Return status code
 */
static int tpm_exec ( int argc, char **argv) {
	struct tpm_options opts;
	struct image *image;
	int rc;
	int pcr;
	char *end;
	uint8_t digest[sha1_algorithm.digestsize];

	if ( ! tpm_present () )
	{
		printf ( "TPM not present\n");
		return -ENODEV;
	}

	/* Parse options */
	if ( ( rc = parse_options ( argc, argv, &tpm_cmd, &opts ) ) != 0 ) {
		printf ( "Unable to parse options: %d\n", rc );
		return rc;
	}

	/* Acquire image */
	unsigned long timeout = 60;
	if ( ( rc = imgacquire ( argv[1], timeout, &image ) ) != 0 ) {
		printf ( "Unable to acquire image: %d\n", rc );
		return rc;
	}

	hash_image ( image, digest );

	pcr = strtoul( argv[2], &end, 10 );

	if ( *end || pcr < 8 || pcr > 15) {
		printf ( "Invalid PCR \"%s\"\n", argv[2] );
		return -EINVAL;
	}

	return update_pcr ( pcr, digest );
}

struct command tpm_command __command = {
	.name = "tpm",
	.exec = tpm_exec,
};

