#ifndef _IPXE_TPM_H
#define _IPXE_TPM_H

FILE_LICENCE ( GPL2_OR_LATER );

#include <config/general.h>

int tpm_present ( void );
int update_pcr ( unsigned int pcr, uint8_t *digest );
void hash_image (struct image *image, uint8_t *digest );

#endif /* _IPXE_TPM_H */
