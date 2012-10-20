#ifndef H_STREAMHELPER
#define H_STREAMHELPER

/**
 * @file   streamhelpers.hpp
 * @Author Oliver Guenther (mail@oliverguenther.de)
 * @date   September 2012
 * @brief  Provides helper methods for (de-)serializing BM-BE structures
 */

#include <fstream>
#include "BDEM/ae_wrapper.hpp"

// resolves gmp c++ related linking errors
// 'declaration of C function 'std::ostream& operator<<(std::ostream&, const __mpq_struct*)' conflicts with ..'

#include <gmpxx.h>

extern "C" {
#include "PBC_BKEM/bkem.h"
}

/**
 * @typedef private key struct
 * @brief Stores a BM-BE private key (pseudonym, key)
 */
typedef struct bes_privkey_s {
    /** The integer pseudonym */
    int id;
    /** The PBC element_t private key */
    element_t privkey;
}* bes_privkey_t;

/**
 * @typedef BM-BE Ciphertext struct
 * @brief Stores a BM-BE ciphertext
 */
typedef struct bes_ciphertext_s {
    
    /** elements in the receivers int[] */
    int num_receivers;
    /** receivers integer array */
    int* receivers;
    /** The HDR element in the BGW BES scheme */
    element_t* HDR;
    /** An AE-encrypted (belonging to BM-BE DEM) ciphertext */
    AE_Ciphertext *ae_ct;
}* bes_ciphertext_t;


/**
 * constant PBC Type A parameters
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


/**
 * @fn element_from_stream
 * @brief Restore an element_t from stream
 * @param[out] el The element_t to write to
 * @param[in] gbs the BKEM global parameters
 * @param[in] is The input stream to read from
 * @param[in] numbytes The number of bytes to read from is
 */
void element_from_stream(element_t el, bkem_global_params_t gbs, std::istream& is, int numbytes);

/**
 * @fn element_to_stream
 * @brief Write an element_t to stream
 * @param el The element_t to serialize
 * @param os The output stream to write to
 */
void element_to_stream(element_t el, std::ostream& is);

/**
 * @fn ciphertext_from_stream
 * @brief Restore an bes_ciphertext_t from stream
 * @param[out] ct The bes_ciphertext_t to write to
 * @param[in] gbs the BKEM global parameters
 * @param[in] is The input stream to read from
 */
void ciphertext_from_stream(bes_ciphertext_t *ct, bkem_global_params_t gbs, std::istream& is);

/**
 * @fn ciphertext_to_stream
 * @brief Write an bes_ciphertext_t to stream
 * @param el The bes_ciphertext_t to serialize
 * @param gbs the BKEM global parameters
 * @param os The output stream to write to
 */
void ciphertext_to_stream(bes_ciphertext_t ct, bkem_global_params_t gbs, std::ostream& os);

/**
 * @fn encryption_header_to_bytes
 * @brief Write an BM-BE BKEM encryption header to stream
 * @param buf The HDR serialized data to write to
 * @param HDR The encryption Header to serialize
 * @param size The size of the encryption header (no. of elements in HDR)
 */
size_t encryption_header_to_bytes(unsigned char** buf, element_t* HDR, int size);

/**
 * @fn sk_ciphertext_from_stream
 * @brief Restore an AE_Ciphertext from stream
 * @param[out] skt_ct The AE_Ciphertext to write to
 * @param[in] is The input stream to read from
 */
void sk_ciphertext_from_stream(AE_Ciphertext** skt_ct, std::istream& is);

/**
 * @fn sk_ciphertext_to_stream
 * @brief Write an AE_Ciphertext to stream
 * @param sk_ct The AE_Ciphertext to read from
 * @param os The output stream to write to
 */
void sk_ciphertext_to_stream(AE_Ciphertext* sk_ct, std::ostream& os);

/**
 * @fn public_key_from_stream
 * @brief Restore an pubkey_t from stream
 * @param[out] pubkey_p The pubkey_t to write to
 * @param[in] gbs the BKEM global parameters
 * @param[in] is The input stream to read from
 * @param[in] element_size The size of an element_t in this system
 */
void public_key_from_stream(pubkey_t *pubkey_p, bkem_global_params_t gbs, std::istream& is, int element_size);

/**
 * @fn public_key_to_stream
 * @brief Write an pubkey_t to stream
 * @param pk The pubkey_t to read from
 * @param gbs the BKEM global parameters
 * @param os The output stream to write to
 */
void public_key_to_stream(pubkey_t pk, bkem_global_params_t gbs, std::ostream& os);

/**
 * @fn private_key_from_stream
 * @brief Restore an bes_privkey_t from stream
 * @param[out] pubkey_p The bes_privkey_t to write to
 * @param[in] gbs the BKEM global parameters
 * @param[in] is The input stream to read from
 * @param[in] element_size The size of an element_t in this system
 */
void private_key_from_stream(bes_privkey_t *sk, bkem_global_params_t gbs, std::istream& is, int element_size);

/**
 * @fn private_key_to_stream
 * @brief Write an bes_privkey_t to stream
 * @param pk The bes_privkey_t to read from
 * @param os The output stream to write to
 */
void private_key_to_stream(bes_privkey_t sk, std::ostream& os);

/**
 * @fn bes_ciphertext_t
 * @brief Free a bes_ciphertext_t struct
 * @param ct The bes_ciphertext_t to clear
 * @param gbs the BKEM global parameters
 */
void free_bes_ciphertext(bes_ciphertext_t ct, bkem_global_params_t gbs);

/**
 * @fn free_bes_privkey
 * @brief Free a bes_privkey_t struct
 * @param sk The bes_privkey_t to clear
 */
void free_bes_privkey(bes_privkey_t sk);

//void debug_ciphertext(bes_ciphertext_t ct);
//void debug_key(unsigned char* key, int keylen);

#endif
