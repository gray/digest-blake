#define PERL_NO_GET_CONTEXT

#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"
#include "ppport.h"

#include "src/sha3nist.c"
#include "src/blake.c"

typedef hashState *Digest__BLAKE;

MODULE = Digest::BLAKE    PACKAGE = Digest::BLAKE

PROTOTYPES: ENABLE

SV *
blake_224 (...)
ALIAS:
    blake_224 = 224
    blake_256 = 256
    blake_384 = 384
    blake_512 = 512
PREINIT:
    hashState ctx;
    int i;
    unsigned char *data;
    unsigned char *result;
    STRLEN len;
CODE:
    if (Init(&ctx, ix) != SUCCESS)
        XSRETURN_UNDEF;
    for (i = 0; i < items; i++) {
        data = (unsigned char *)(SvPV(ST(i), len));
        if (Update(&ctx, data, len << 3) != SUCCESS)
            XSRETURN_UNDEF;
    }
    Newx(result, ix >> 3, unsigned char);
    if (Final(&ctx, result) != SUCCESS)
        XSRETURN_UNDEF;
    RETVAL = newSVpv(result, ix >> 3);
    Safefree(result);
OUTPUT:
    RETVAL

Digest::BLAKE
new (class, hashsize)
    SV *class
    int hashsize
CODE:
    Newx(RETVAL, 1, hashState);
    if (Init(RETVAL, hashsize) != SUCCESS)
        XSRETURN_UNDEF;
OUTPUT:
    RETVAL

Digest::BLAKE
clone (self)
    Digest::BLAKE self
CODE:
    Newx(RETVAL, 1, hashState);
    Copy(self, RETVAL, 1, hashState);
OUTPUT:
    RETVAL

int
hashsize(self)
    Digest::BLAKE self
ALIAS:
    algorithm = 1
CODE:
    RETVAL = self->hashbitlen;
OUTPUT:
    RETVAL

void
add (self, ...)
    Digest::BLAKE self
PREINIT:
    int i;
    unsigned char *data;
    STRLEN len;
PPCODE:
    for (i = 1; i < items; i++) {
        data = (unsigned char *)(SvPV(ST(i), len));
        if (Update(self, data, len << 3) != SUCCESS)
            XSRETURN_UNDEF;
    }
    XSRETURN(1);

void
_add_bits (self, msg, bitlen)
    Digest::BLAKE self
    SV *msg
    int bitlen
PREINIT:
    int i;
    unsigned char *data;
    STRLEN len;
PPCODE:
    if (! bitlen)
        XSRETURN(1);
    data = (unsigned char *)(SvPV(msg, len));
    if (bitlen > len << 3)
        bitlen = len << 3;
    if (Update(self, data, bitlen) != SUCCESS)
        XSRETURN_UNDEF;
    XSRETURN(1);

SV *
digest (self)
    Digest::BLAKE self
PREINIT:
    unsigned char *result;
CODE:
    Newx(result, self->hashbitlen >> 3, unsigned char);
    if (Final(self, result) != SUCCESS)
        XSRETURN_UNDEF;
    RETVAL = newSVpv(result, self->hashbitlen >> 3);
    Safefree(result);
OUTPUT:
    RETVAL

void
DESTROY (self)
    Digest::BLAKE self
CODE:
    Safefree(self);
