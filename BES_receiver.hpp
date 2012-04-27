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
    
    /**
     * Decrypt using Broadcast system
     * @param cts bes_ciphertext_t
     *
     * @return decrypted plain text or empty vector
     */
    FB::VariantMap bes_decrypt(bes_ciphertext_t& ct);
    
    
    /**
     * Store BES state to its instance file
     */
    int store();
    
    /**
     * Restores saved BES state
     * @return 0 if successful, 1 otherwise
     */
    int restore();
    
    std::string instance_file();

    /**
     * BES public global params
     */
    bes_global_params_t gbs;
    
private:
    
    
    /**
     * Max users
     */
    int N;
    
    bes_privkey_t SK;
    
    pubkey_t PK;
    
    int keylen;

    int derivate_decryption_key(unsigned char *key, element_t raw_key);
    
    
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
    }
    
};

#endif
