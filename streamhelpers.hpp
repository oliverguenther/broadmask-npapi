#ifndef H_STREAMHELPER
#define H_STREAMHELPER

#include <fstream>

// resolves gmp c++ related linking errors
// 'declaration of C function 'std::ostream& operator<<(std::ostream&, const __mpq_struct*)' conflicts with ..'

#include <gmpxx.h>

extern "C" {
#include "PBC_bes/pbc_bes.h"
}

#define AES_IV_LENGTH 12


/**
 * @typedef private key struct
 */

typedef struct bes_privkey_s {
    int id;
    element_t privkey;
}* bes_privkey_t;

/**
 * @typedef Ciphertext struct
 */
typedef struct bes_ciphertext_s {
    int num_receivers;
    int ct_length;
    int* receivers;
    element_t* HDR;
    unsigned char* iv;
    unsigned char* ct;
}* bes_ciphertext_t;

/**
 * @typedef Shared-Key ciphertext struct
 */
typedef struct sk_ciphertext_s {
    int ct_length;
    unsigned char* iv;
    unsigned char* ct;
}* sk_ciphertext_t;

/**
 * constant Type A parameters
 */
static const char* params = 
"type a\n"
"q 8780710799663312522437781984754049815806883199414208211028653399266475630880222957078625179422662221423155858769582317459277713367317481324925129998224791\n"
"h 12016012264891146079388821366740534204802954401251311822919615131047207289359704531102844802183906537786776\n"
"r 730750818665451621361119245571504901405976559617\n"
"exp2 159\n"
"exp1 107\n"
"sign1 1\n"
"sign0 1";

    
void element_from_stream(element_t el, bes_global_params_t gbs, std::istream& is, int numbytes);
void element_to_stream(element_t el, std::ostream& is);

void ciphertext_from_stream(bes_ciphertext_t *ct, bes_global_params_t gbs, std::istream& is);
void ciphertext_to_stream(bes_ciphertext_t ct, bes_global_params_t gbs, std::ostream& os);

void sk_ciphertext_from_stream(sk_ciphertext_t *skt_ct, std::istream& is);
void sk_ciphertext_to_stream(sk_ciphertext_t sk_ct, std::ostream& os);

void public_key_from_stream(pubkey_t *pubkey_p, bes_global_params_t gbs, std::istream& is, int element_size);
void public_key_to_stream(pubkey_t pk, bes_global_params_t gbs, std::ostream& os);

void private_key_from_stream(bes_privkey_t *sk, bes_global_params_t gbs, std::istream& is, int element_size);
void private_key_to_stream(bes_privkey_t sk, std::ostream& os);

void free_sk_ciphertext(sk_ciphertext_t ct);
void free_bes_ciphertext(bes_ciphertext_t ct, bes_global_params_t gbs);
void free_bes_privkey(bes_privkey_t sk);

//void debug_ciphertext(bes_ciphertext_t ct);
//void debug_key(unsigned char* key, int keylen);

#endif
