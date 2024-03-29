#ifndef H_SHARED_INSTANCE
#define H_SHARED_INSTANCE

/**
 * @file   BM_SK.hpp
 * @Author Oliver Guenther (mail@oliverguenther.de)
 * @date   September 2012
 * @brief  Implements the BM-SK instance
 *
 *
 */

#include <set>
#include <vector>
#include "Instance.hpp"
#include "JSAPIAuto.h"
#include "JSObject.h"
#include "variant_map.h"
#include "streamhelpers.hpp"

// serialization
#include <boost/archive/text_oarchive.hpp>
#include <boost/archive/text_iarchive.hpp>
#include <boost/serialization/base_object.hpp>
#include <boost/serialization/vector.hpp>
#include <boost/serialization/export.hpp>

// AE wrapper
#include "BDEM/ae_wrapper.hpp"


/**
 * @class  BM_SK BM_SK.hpp
 * @brief  Implements the BM-SK instance
 *
 * The BM-SK instance uses AES-GCM for shared-key encryption,
 * it does not introduce an upper limitation to users at the cost
 * of significant key (management) overhead.
 */
class BM_SK : public Instance  {
    
public:
    /**
     * @fn BM_SK::BM_SK
     * @brief Initialize a BM-SK instance, generating a 256bit AES-GCM key
     * @param groupid the globally unique group identifier
     *
     * Use this constructor for new BM-SK instances ('sender' instances)
     * (i.e., this is called from the profile owner
     */
    BM_SK(std::string groupid);
    
    /**
     * @fn BM_SK::BM_SK
     * @brief Initialize a BM-SK instance, given a 256bit AES-GCM key
     * @param groupid the globally unique group identifier
     * @param key_b64 the AES-GCM key
     *
     * Use this constructor for receiving instances, where a shared
     * key has already been generated for the group id.
     */
    BM_SK(std::string groupid, std::string key_b64);
    ~BM_SK();
    
    instance_types type() { return BROADMASK_INSTANCE_SK; }

    
    /**
     * @fn BM_SK::encrypt
     * @brief Encrypt data using the shared key
     * @param[out] cts The ciphertext struct returned from this encryption operation (or NULL on error)
     * @param[in] pts A plaintext struct pointer, containing the plaintext to encrypt
     * @return an ae_error_t with error set to true if an encryption error occured
     */
    ae_error_t encrypt(AE_Ciphertext** cts, AE_Plaintext* pts);
    
    /**
     * @fn BM_SK::decrypt
     * @brief Decrypt ciphertext data using the shared key
     * @param[out] pts The plaintext struct returned from this decryption operation (or NULL on error)
     * @param[in] sk_ct A ciphertext struct pointer, containing the ciphertext to decrypt
     * @return an ae_error_t with error set to true if an encryption error occured
     *
     */
    ae_error_t decrypt(AE_Plaintext** pts, AE_Ciphertext* sk_ct);
    
    
    /**
     * @fn BM_SK::get_symmetric_key
     * @return Returns the shared key
     */
    std::vector<unsigned char> get_symmetric_key();
    
    /*
     * BM-SK requires no additional internal state
     */
    void store() {}
    void restore() {}
    
private:
    
    std::vector<unsigned char> key;
        
    //
    // Boost class serialization
    //
    
    // Default Constructor, required for De-Serialization
    BM_SK() : Instance() {}
    
    friend class boost::serialization::access;
    template<class Archive>
    void serialize(Archive & ar, const unsigned int version)
    {
        ar & boost::serialization::make_nvp( BOOST_PP_STRINGIZE(*this),boost::serialization::base_object<Instance>(*this));
        ar & gid;
        ar & members;
        ar & key;
    }
    
};

#endif
