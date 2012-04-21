/**********************************************************\

  Auto-generated BroadmaskAPI.h

\**********************************************************/

#include <string>
#include <sstream>
#include <map>
#include <boost/weak_ptr.hpp>
#include "JSAPIAuto.h"
#include "JSObject.h"
#include "variant_map.h"

#include "BrowserHost.h"
#include "Broadmask.h"
#include "BES_base.h"
#include "BES_sender.h"
#include "BES_receiver.h"
#include "Base64.h"
#include "UserStorage.h"


#include <boost/filesystem/path.hpp>



#ifndef H_BroadmaskAPI
#define H_BroadmaskAPI


class BroadmaskAPI : public FB::JSAPIAuto
{
public:
    BroadmaskAPI(const BroadmaskPtr& plugin, const FB::BrowserHostPtr& host);

    ///////////////////////////////////////////////////////////////////////////////
    /// @fn BroadmaskAPI::~BroadmaskAPI()
    ///
    /// @brief  Destructor.  Remember that this object will not be released until
    ///         the browser is done with it; this will almost definitely be after
    ///         the plugin is released.
    ///////////////////////////////////////////////////////////////////////////////
    virtual ~BroadmaskAPI() {};

    BroadmaskPtr getPlugin();
    
    
    /**
     * @fn BroadmaskAPI::start_sender_instance
     * @brief Create or resume a sender broadcast encryption system for the given groupid
     * 
     * @return [N,PK,HDR] as base64 encoded binary to be used on receiving side
     */
    std::string start_sender_instance(std::string gid, int N);
    
    std::string sk_encrypt_b64(std::string data, bool image);

    
    /**
     * @fn BroadmaskAPI::start_receiver_instance
     * @brief Create or resume a receiver decryption system for the given groupid
     */
    void start_receiver_instance(std::string gid, int N, std::string params, std::string private_key);
    
    /**
     * @fn BroadmaskAPI::restore_instances
     * @brief Tries to reload all stored (sender, receiving) instances
     */
    void restore_instances();
    
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
    
    int add_member(std::string gid, std::string sysid);
    
    void remove_member(std::string gid, std::string sysid);

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
    std::string encrypt_b64(std::string gid, const std::vector<std::string>& receivers, std::string data, bool image);
    
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
    std::string decrypt_b64(std::string gid, std::string ct_data, bool image);
    
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

    
    
private:
    BroadmaskWeakPtr m_plugin;
    FB::BrowserHostPtr m_host;
    
    std::map<std::string, BES_sender> sending_groups;
    std::map<std::string, BES_receiver> receiving_groups;
    
    BES_base* load_instance(boost::filesystem::path p);
    template <class T>
    void storeInstance(T *bci);

    BES_sender* get_sender_instance(std::string gid);
    BES_receiver* get_receiver_instance(std::string gid);
    
    UserStorage *gpg;
    void store_storage_wrapper();

};

#endif // H_BroadmaskAPI

