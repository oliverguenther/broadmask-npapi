#ifndef H_BES_RECEIVER
#define H_BES_RECEIVER

#include <map>
#include "Instance.hpp"
#include "streamhelpers.hpp"
#include "variant_map.h"

#include <gmpxx.h>

extern "C" {
#include "PBC_bes/pbc_bes.h"
}

// serialization
#include <boost/archive/text_oarchive.hpp>
#include <boost/archive/text_iarchive.hpp>
#include <boost/serialization/vector.hpp>
#include <boost/serialization/map.hpp>
#include <boost/serialization/base_object.hpp>


class BES_receiver : public Instance  {
    
public: 
    // Required for De-Serialization
    BES_receiver() : Instance() {}
    BES_receiver(std::string groupid, int N, std::string public_data, std::string private_key);
    
    BES_receiver(const BES_receiver&);

    ~BES_receiver();
    
    instance_types type() { return BROADMASK_INSTANCE_BES_RECEIVER; }
    
    /**
     * Decrypt using Broadcast system
     * @param cts bes_ciphertext_t
     *
     * @return decrypted plain text or empty vector
     */
    FB::VariantMap bes_decrypt(bes_ciphertext_t& ct);
    
    
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
    bes_global_params_t gbs;
    
private:
    
    
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
     * Uses BKEM to derive symmetric key sk
     */ 
    int derivate_decryption_key(unsigned char *key, element_t raw_key);
    
    /**
     * Stores internal (SK,PK) state
     */
    std::string stored_state;
    
    
    //
    // Boost class serialization, independent from BES serialization
    //
    friend class boost::serialization::access;
    template<class Archive>
    void serialize(Archive & ar, const unsigned int version)
    {
        ar & boost::serialization::make_nvp( BOOST_PP_STRINGIZE(*this),boost::serialization::base_object<Instance>(*this));
        ar & N;
        ar & gid;
        ar & members;
        ar & keylen;
        ar & stored_state;
    }
    
};

#endif
