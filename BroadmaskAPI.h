#ifndef H_BroadmaskAPI
#define H_BroadmaskAPI

#include <string>
#include <sstream>
#include <map>
#include <boost/weak_ptr.hpp>
#include "JSAPIAuto.h"
#include "JSObject.h"
#include "variant_map.h"
#include "variant_list.h"
#include "variant.h"

#include "BrowserHost.h"
#include "Broadmask.h"
#include "Instance.hpp"
#include "BES_sender.hpp"
#include "BES_receiver.hpp"
#include "Base64.h"
#include "UserStorage.hpp"
#include "InstanceStorage.hpp"


#include <boost/filesystem/path.hpp>



class BroadmaskAPI : public FB::JSAPIAuto {
public:
    BroadmaskAPI(const BroadmaskPtr& plugin, const FB::BrowserHostPtr& host);
    virtual ~BroadmaskAPI() {};
    BroadmaskPtr getPlugin();
    
    
    /**
     * @fn BroadmaskAPI::start_sender_instance
     * @brief Create or resume a sender broadcast encryption system for the given groupid
     * 
     * @return [N,PK,HDR] as base64 encoded binary to be used on receiving side
     */
    std::string create_sender_instance(std::string gid, std::string name, int N);
    
    FB::VariantMap sk_encrypt_b64(std::string gid, std::string data, bool image);
    FB::VariantMap sk_decrypt_b64(std::string gid, std::string params, bool image);

    
    /**
     * @fn BroadmaskAPI::start_receiver_instance
     * @brief Create or resume a receiver decryption system for the given groupid
     */
    void create_receiver_instance(std::string gid, std::string name, int N, std::string params, std::string private_key);
    
    void create_shared_instance(std::string gid, std::string name);

    
    /**
     * @fn BroadmaskAPI::get_member_sk
     * @brief Tries to retrieve member key for user with sysid
     * @param gid Group instance id
     * @param sysid User id
     * @return base64 encoded private_key_t
     */
    std::string get_member_sk(std::string gid, std::string sysid);
    
    /**
     * @fn BroadmaskAPI::get_member_sk_gpg
     * @brief Tries to retrieve member key for user with sysid. user with sysid needs
     * to be registered a PGP key using gpg_store_keyid
     * @param gid Group instance id
     * @param sysid User id
     * @return gpg encrypted private_key_t with keyid
     */
    FB::VariantMap get_member_sk_gpg(std::string gid, std::string sysid);
    
    FB::VariantMap get_instance_members(std::string gid);
    
    int add_member(std::string gid, std::string sysid);

    FB::VariantMap add_members(std::string gid, std::vector<std::string> idvector);
    
    FB::VariantMap get_bes_public_params(std::string gid);

    
    void remove_member(std::string gid, std::string sysid);
    
    FB::VariantMap get_instance_descriptor(std::string id);


    /** 
     * @fn BroadmaskAPI::encrypt_b64
     * @brief Encrypt a base64 encoded string
     *
     * @param gid instance id
     * @param receivers Space-separated string of receiver id's
     * @param data base64 encoded string
     * @param image true if data should be wrapped as a image after encryption
     *
     * @return encrypted binary data, base64 encoded
     */
    FB::VariantMap encrypt_b64(std::string gid, const std::vector<std::string>& receivers, std::string data, bool image);
    
    /** 
     * @fn BroadmaskAPI::decrypt_b64
     * @brief Decrypt base64 encoded binary data
     * 
     * @param gid instance id
     * @param receivers Space-separated string of receiver id's
     * @param data base64 encoded binary data
     * @param image true if data should be unwrapped prior to decryption
     *
     * @return plaintext binary data, base64 encoded
     */    
    FB::VariantMap decrypt_b64(std::string gid, std::string ct_data, bool image);
    
    void test(const FB::JSObjectPtr &callback);
    void testsuite(const FB::JSObjectPtr &callback);
    
    
    /**
     * @fn BroadmaskAPI::gpg_store_keyid
     * @brief Stores a PGP key id or fingerprint for the user user_id
     * @param user_id 
     * @param key_id PGP key fingerprint/keyid
     */
    void gpg_store_keyid(std::string user_id, std::string key_id);
    
    /**
     * @fn BroadmaskAPI::gpg_remove_key
     * @brief Deletes the key associated with user_id
     * @param user_id 
     */
    void gpg_remove_key(std::string user_id);

    
    /**
     * @fn BroadmaskAPI::gpg_get_keyid
     * @brief Tries to retrieve a PGP key id or fingerprint for the user user_id
     * @param user_id 
     * return FB::VariantMap containing user key or error if unsuccessful
     */
    FB::VariantMap gpg_get_keyid(std::string user_id);
    
    /**
     * @fn BroadmaskAPI::gpg_encrypt_for
     * @brief Encrypt data for the registered key belonging to user_id
     * @param data message body to be encrypted
     * @param user_id 
     * @return FB::VariantMap containing GPG-Message
     */
    FB::VariantMap gpg_encrypt_for(std::string data, std::string user_id);
    
    /**
     * @fn BroadmaskAPI::gpg_encrypt_with
     * @brief Encrypt data with key_id
     * @param data message body to be encrypted
     * @param key_id fingerprint of keyid of PGP key to encrypt for
     * @return FB::VariantMap containing GPG-Message
     */
    FB::VariantMap gpg_encrypt_with(std::string data, std::string key_id);
    
    /**
     * @fn BroadmaskAPI::gpg_decrypt
     * @brief Tries to decrypt PGP message data
     * @param data PGP ascii armored message
     * @return FB::VariantMap plaintext if user possesses private key, error otherwise
     */
    FB::VariantMap gpg_decrypt(std::string data);
    
    /**
     * @fn BroadmaskAPI::gpg_associatedKeys
     * @brief Retrieve a map of userid => keyid with all registered PGP keys
     * @return FB::VariantMap
     */
    FB::VariantMap gpg_associatedKeys();
    
    /**
     * @fn BroadmaskAPI::gpg_import_key
     * @brief Import the key_id or key block
     * @param data Key data (id/fingerprint or block)
     * @param iskeyblock set to true if data is a key block
     * @return FB::VariantMap
     */
    FB::VariantMap gpg_import_key(std::string data, bool iskeyblock);
    
    /**
     * @fn BroadmaskAPI::get_stored_instances
     * @brief Return stored instances
     */     
    FB::VariantMap get_stored_instances();
    
    void remove_instance(std::string id);

    
    
private:
    BroadmaskWeakPtr m_plugin;
    FB::BrowserHostPtr m_host;
    
    
    UserStorage *ustore;
    InstanceStorage *istore;

};

#endif // H_BroadmaskAPI

