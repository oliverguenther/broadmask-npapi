#ifndef H_PGP_STORAGE_WRAPPER
#define H_PGP_STORAGE_WRAPPER

// serialization
#include <boost/archive/text_oarchive.hpp>
#include <boost/archive/text_iarchive.hpp>
#include <boost/serialization/map.hpp>

// JSAPI
#include "JSAPIAuto.h"
#include "APITypes.h"
#include "JSObject.h"
#include "variant_map.h"

// GPGME
#include <gpgme.h>


class PGPStorageWrapper  {
    
public: 
    PGPStorageWrapper();
    ~PGPStorageWrapper();
    
    /**
     * @fn PGPStorageWrapper::encrypt_for
     * @brief Tries to encrypt data with PGP key corresponding to user id
     * @param data Data to encrypt
     * @param user_id user id
     * @return JS object with op results
     */
    FB::VariantMap encrypt_for(std::string data, std::string user_id);
    
    /**
     * @fn PGPStorageWrapper::encrypt_with
     * @brief Tries to encrypt data with PGP key key_id
     * @param data Data to encrypt
     * @param key_id key identifier or fingerprint
     * @return JS object with op results
     */
    FB::VariantMap encrypt_with(std::string data, std::string key_id);
    
    /**
     * @fn PGPStorageWrapper::decrypt
     * @brief Tries to decrypt payload with a key from keyring
     * @param data Data to decrypt
     * @return JS object with op results
     */
    FB::VariantMap decrypt(std::string data);
    
    
    /**
     * @fn PGPStorageWrapper::setPGPKey
     * @brief Adds a PGP public key id for user id
     * @param user_id the user id the keyid belongs to
     * @param key_id the key_id to add
     */
    void setPGPKey(std::string user_id, std::string keyid);
    
    
    /**
     * @fn PGPStorageWrapper::getPGPKey
     * @brief Retrieves the Key ID for user_id, if existant
     * @param user_id the user id the keyid belongs to
     * @return JS object with op results
     */    
    FB::VariantMap getPGPKey(std::string user_id);

    /**
     * @fn PGPStorageWrapper::associatedKeys
     * @brief Retrieves the association of user ids to key ids / fingerprints
     * @return JS object with op results
     */    
    FB::VariantMap associatedKeys();

    
private:
    
    // Storage for known user ids <-> gpg keys
    std::map<std::string, std::string> keymap;
    std::string version;
    
    
    // GPGME helpers
    
    // Create new context
    gpgme_ctx_t create_gpg_context();
    std::string get_validity_str (gpgme_validity_t& v);
    std::string PGPStorageWrapper::get_status_str (gpgme_error_t& e);


    
    
    // GPGME error helpers
    FB::VariantMap gpgme_error (gpgme_error_t& err);
    
    //
    // Boost class serialization, independent from BES serialization
    //
    friend class boost::serialization::access;
    template<class Archive>
    void serialize(Archive & ar, const unsigned int version)
    {
        ar & keymap;
    }
};

#endif
