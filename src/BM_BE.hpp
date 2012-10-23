#ifndef H_BM_BE
#define H_BM_BE

/**
 * @file   BM_BE.hpp
 * @Author Oliver Guenther (mail@oliverguenther.de)
 * @date   September 2012
 * @brief  Implements the BM-BE receiving instance
 *
 *
 */

#include <map>
#include "Instance.hpp"
#include "streamhelpers.hpp"

#include <gmpxx.h>

extern "C" {
#include "PBC_BKEM/bkem.h"
}

// serialization
#include <boost/archive/text_oarchive.hpp>
#include <boost/archive/text_iarchive.hpp>
#include <boost/serialization/vector.hpp>
#include <boost/serialization/map.hpp>
#include <boost/serialization/base_object.hpp>
#include <boost/serialization/export.hpp>

/**
 * @class BM_BE BM_BE.hpp
 * @brief Implements the BM-BE receiving instance
 *
 *
 */
class BM_BE : public Instance  {
    
public:
    
    /**
     * @brief Initialize a BM_BE instance, given BM-BE PK and SK structs
     *
     * This constructor is mainly used when initializing a (receiving)
     * BM-BE instance from the profile owner.
     */
    BM_BE(std::string groupid, int max_users, pubkey_t& pk, bes_privkey_t& sk) :         Instance(groupid), N(max_users), SK(sk), PK(pk) {}
    
    /**
     * @brief Initialize a BM_BE instance, given serialized BM-BE PK and SK structs
     *
     * This constructor is mainly used when initializing a new receiving
     */
    BM_BE(std::string groupid, int N, std::string public_data, std::string private_key);
    ~BM_BE();
    
    ae_error_t encrypt_comment(AE_Ciphertext** ae_cts, bes_ciphertext_t& cts, AE_Plaintext* pts);
    ae_error_t decrypt_comment(AE_Plaintext** recovered_pts, bes_ciphertext_t& cts, AE_Ciphertext* ae_cts);
    
    instance_types type() { return BROADMASK_INSTANCE_BM_BE; }
    
    /**
     * Decrypt using Broadcast system
     * @param recovered_pts recovered plaintext struct
     * @param cts bes_ciphertext_t
     *
     * @return decrypted plain text or empty vector
     */
    ae_error_t bes_decrypt(AE_Plaintext** recovered_pts, bes_ciphertext_t& ct);
    
    /**
     * Store BES state to internal state string
     */
    void store();
    
    /**
     * Restores saved BES state
     */
    void restore();
    
    
    /**
     * BES public global params
     */
    bkem_global_params_t gbs;
    
    int max_users() {
        return N;
    }
    
protected:
    
    /**
     * Max users
     */
    int N;
    
    /**
     * This receivers private key
     */
    bes_privkey_t SK;
    
    
    /**
     * This receivers public key
     */
    pubkey_t PK;
    
    /*
     * Keylen of symmetric key sk
     */
    int keylen;
    
    /**
     * Stores internal (SK,PK) state
     */
    std::string stored_state;
    
    
    /**
     * Uses BKEM to derive symmetric key sk
     */
    int derivate_decryption_key(unsigned char *key, element_t raw_key);
    
    
    //
    // Boost class serialization, independent from BES serialization
    //
    
    // Default constructor, required for De-Serialization
    BM_BE() : Instance() {}
    
    
    friend class boost::serialization::access;
    template<class Archive>
    void serialize(Archive & ar, const unsigned int version)
    {
        ar & boost::serialization::make_nvp( BOOST_PP_STRINGIZE(*this),boost::serialization::base_object<Instance>(*this));
        ar & keylen;
        ar & N;
        ar & stored_state;
    }
    
};

#endif
