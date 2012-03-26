/**********************************************************\

  Auto-generated BroadmaskAPI.h

\**********************************************************/

#include <string>
#include <sstream>
#include <map>
#include <boost/weak_ptr.hpp>
#include "JSAPIAuto.h"
#include "BrowserHost.h"
#include "Broadmask.h"
#include "BES_base.h"
#include "BES_sender.h"
#include "BES_receiver.h"
#include "Base64.h"

#include <boost/filesystem/path.hpp>



#ifndef H_BroadmaskAPI
#define H_BroadmaskAPI


class BroadmaskAPI : public FB::JSAPIAuto
{
public:
    ////////////////////////////////////////////////////////////////////////////
    /// @fn BroadmaskAPI::BroadmaskAPI(const BroadmaskPtr& plugin, const FB::BrowserHostPtr host)
    ///
    /// @brief  Constructor for your JSAPI object.
    ///         You should register your methods, properties, and events
    ///         that should be accessible to Javascript from here.
    ///
    /// @see FB::JSAPIAuto::registerMethod
    /// @see FB::JSAPIAuto::registerProperty
    /// @see FB::JSAPIAuto::registerEvent
    ////////////////////////////////////////////////////////////////////////////
    BroadmaskAPI(const BroadmaskPtr& plugin, const FB::BrowserHostPtr& host) :
        m_plugin(plugin), m_host(host)
    {
        registerMethod("start_sender_instance", make_method(this, &BroadmaskAPI::start_sender_instance));
        registerMethod("start_receiver_instance", make_method(this, &BroadmaskAPI::start_receiver_instance));
        registerMethod("encrypt_b64", make_method(this, &BroadmaskAPI::encrypt_b64));
        registerMethod("decrypt_b64", make_method(this, &BroadmaskAPI::decrypt_b64));

    }

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
    std::string encrypt_b64(std::string gid, std::string receivers, std::string data, bool image);
    
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
    
    
private:
    BroadmaskWeakPtr m_plugin;
    FB::BrowserHostPtr m_host;
    
    std::map<std::string, BES_sender> sending_groups;
    std::map<std::string, BES_receiver> receiving_groups;
    
    CBase64 b64;
    
    
    BES_base* load_instance(boost::filesystem::path p);
    void storeInstance(BES_base *bci, std::string type);


};

#endif // H_BroadmaskAPI

