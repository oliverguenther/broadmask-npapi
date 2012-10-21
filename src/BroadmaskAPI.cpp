/**********************************************************\
 
 Auto-generated BroadmaskAPI.cpp
 
 \**********************************************************/

#include <iostream>
#include <fstream>
#include <sstream>
#include <cmath>
#include <iomanip>

#include <boost/timer.hpp>
#include <boost/filesystem/operations.hpp>
#include <boost/filesystem/path.hpp>
#include <boost/filesystem/fstream.hpp> 
#include <boost/static_assert.hpp>
#include <boost/thread.hpp>

#include <boost/format.hpp>
using boost::format;

// FB JSAPI
#include "JSObject.h"
#include "variant_list.h"
#include "DOM/Document.h"
#include "DOM/Window.h"
#include "global/config.h"


#include "BroadmaskAPI.h"

// Profiles
#include "ProfileManager.hpp"
#include "Profile.hpp"

// Instances
#include "Instance.hpp"
#include "BM_BE_sender.hpp"
#include "BM_BE.hpp"

#include "utils.h"
#include "gnupg_wrapper.hpp"
#include "BitmapWrapper.h"
#include "streamhelpers.hpp"

using namespace std;
#define M_INIT_AND_UNLOCK_PROFILE \
profile_ptr profile_sp = pm->unlock_profile(m_host->getDOMWindow(), active_profile); \
Profile *p = profile_sp.get(); \
FB::VariantMap result; \
if (!p) { \
    result["error"] = true; \
    format fmter = format("Could not unlock profile %1%") % active_profile; \
    result["error_msg"] = fmter.str(); \
    return result; \
} \


///////////////////////////////////////////////////////////////////////////////
/// Instance Management 

#pragma mark -
#pragma mark Instance Management

FB::VariantMap BroadmaskAPI::create_sender_instance(std::string gid, std::string name, int N) {
    M_INIT_AND_UNLOCK_PROFILE
    
    result["result"] = p->start_sender_instance(gid, name, N);
    result["error"] = false;    
    return result;
}

FB::VariantMap BroadmaskAPI::create_receiver_instance(std::string gid, std::string name, int N, std::string pubdata_b64, std::string private_key_b64) {
    M_INIT_AND_UNLOCK_PROFILE
    
    p->start_receiver_instance(gid, name, N, pubdata_b64, private_key_b64);
    result["error"] = false;
    return result;
}

FB::VariantMap BroadmaskAPI::create_shared_instance(std::string gid, std::string name) {
    M_INIT_AND_UNLOCK_PROFILE
    
    
    p->start_shared_instance(gid, name);
    result["error"] = false;
    return result;
}

FB::VariantMap BroadmaskAPI::create_shared_instance_withkey(std::string gid, std::string name, std::string key_b64) {
    M_INIT_AND_UNLOCK_PROFILE
    
    p->start_shared_instance_withkey(gid, name, key_b64);
    result["error"] = false;
    return result;
}

FB::VariantMap BroadmaskAPI::get_instance_descriptor(std::string id) {

    M_INIT_AND_UNLOCK_PROFILE
    return p->instance_description(id);
}

FB::VariantMap BroadmaskAPI::remove_instance(std::string id) {
    
    M_INIT_AND_UNLOCK_PROFILE
    p->remove_instance(id);
    result["error"] = false;
    return result;
}

FB::VariantMap BroadmaskAPI::get_stored_instances() {
    M_INIT_AND_UNLOCK_PROFILE
    return p->get_stored_instances();
}

///////////////////////////////////////////////////////////////////////////////
/// Instance Member API
#pragma mark -
#pragma mark Instance Member Management

FB::VariantMap BroadmaskAPI::add_member(std::string gid, std::string id) {
    
    M_INIT_AND_UNLOCK_PROFILE    
    
    Instance *instance = p->load_instance(gid);
    
    if (!instance) {
        result["error"] = true;
        format fmter = format("Instance with gid '%1%' not found") % gid;
        result["error_msg"] = fmter.str();
        return result;
    }
    
    int sys_id = instance->add_member(id);
    
    result["result"] = sys_id;
    return result;
    
}

FB::VariantMap BroadmaskAPI::add_members(std::string gid, std::vector<std::string> idvector) {
    
    M_INIT_AND_UNLOCK_PROFILE

    Instance *instance = p->load_instance(gid);    
    
    if (!instance) {
        result["error"] = true;
        format fmter = format("Instance with gid '%1%' not found") % gid;
        result["error_msg"] = fmter.str();
        return result;
    }
    
    for (std::vector<std::string>::iterator it = idvector.begin(); 
         it != idvector.end(); ++it) {

        int sys_id = instance->add_member(*it);
        result[*it] = sys_id;

        
    }
    
    instance->store();
    return result;
}

FB::VariantMap BroadmaskAPI::remove_member(std::string gid, std::string id) {
    
    M_INIT_AND_UNLOCK_PROFILE
    
    BM_BE_Sender *bci = dynamic_cast<BM_BE_Sender*>(p->load_instance(gid));
    if (!bci) {
        result["error"] = true;
        format fmter = format("Instance with gid '%1%' not found") % gid;
        result["error_msg"] = fmter.str();
        return result;
    }
    
    bci->remove_member(id);
    bci->store();
    result["error"] = false;
    return result;
}

FB::VariantMap BroadmaskAPI::get_instance_members(std::string gid) {
    
    M_INIT_AND_UNLOCK_PROFILE

    Instance* instance = p->load_instance(gid);
    
    if (!instance) {
        result["error"] = true;
        format fmter = format("Instance with gid '%1%' not found") % gid;
        result["error_msg"] = fmter.str();
        return result;
    }

    std::map<std::string, int> members = instance->instance_members();
    for (std::map<std::string, int>::iterator it = members.begin();
         it != members.end(); ++it) {
        if (it->first != "myself")
        result[it->first] = it->second;
    }
    
    return result;

}

///////////////////////////////////////////////////////////////////////////////
/// BES specifics

#pragma mark -
#pragma mark BES specifics

FB::VariantMap BroadmaskAPI::get_bes_public_params(std::string gid) {
    
    M_INIT_AND_UNLOCK_PROFILE
    
    BM_BE_Sender *sender = dynamic_cast<BM_BE_Sender*>(p->load_instance(gid));
    if (!sender) {
        result["error"] = true;
        format fmter = format("Instance with gid '%1%' not found") % gid;
        result["error_msg"] = fmter.str();
        
        instance_types type = p->instance_type(gid);
        if (type != ERR_NO_INSTANCE)
            result["type"] = type;
        
        return result;
    }
    
    stringstream ss;
    sender->public_params_to_stream(ss);
    result["result"] = base64_encode(ss.str());
    return result;
    
}

///////////////////////////////////////////////////////////////////////////////
/// SK specifics
FB::VariantMap BroadmaskAPI::get_symmetric_key(std::string gid) {
    
    M_INIT_AND_UNLOCK_PROFILE
    BM_SK *ski = dynamic_cast<BM_SK*>(p->load_instance(gid));
    
    if (!ski) {
        result["error"] = true;
        format fmter = format("BES-SK Instance with gid '%1%' not found") % gid;
        result["error_msg"] = fmter.str();
        return result;
    }
    
    std::vector<unsigned char> key = ski->get_symmetric_key();
    result["error"] = false;
    result["result"] = base64_encode(key);    
    return result;
    
}

///////////////////////////////////////////////////////////////////////////////
/// Instance key retrieval

#pragma mark -
#pragma mark Instance key retrieval

FB::VariantMap BroadmaskAPI::get_member_sk(std::string gid, std::string id) {
    
    M_INIT_AND_UNLOCK_PROFILE
    BM_BE_Sender *bci = dynamic_cast<BM_BE_Sender*>(p->load_instance(gid));
    
    if (!bci) {
        result["error"] = true;
        format fmter = format("BM-BE instance with gid '%1%' not found") % gid;
        result["error_msg"] = fmter.str();
        return result;
    }
    
    bes_privkey_t sk = NULL;
    bci->get_private_key(&sk, id);
    if (!sk) {
        result["error"] = true;
        format fmter = format("BM-BE instance %2%. Could not retrieve private key for user %1%") % id % gid;
        result["error_msg"] = fmter.str();
        return result;
    }
    
    std::stringstream oss;
    private_key_to_stream(sk, oss);
    delete sk;
    result["result"] = base64_encode(oss.str());
    result["error"] = false;
    
    return result;
    
}

///////////////////////////////////////////////////////////////////////////////
/// Encryption/Decryption API

#pragma mark -
#pragma mark Encryption, Decryption

FB::VariantMap BroadmaskAPI::encrypt_b64(std::string gid, std::string data, bool image) {
    
    M_INIT_AND_UNLOCK_PROFILE
    
    instance_types type = p->instance_type(gid);

    switch (type) {
        case BROADMASK_INSTANCE_BM_BE_SENDER:
        {
            BM_BE_Sender *instance = dynamic_cast<BM_BE_Sender*>(p->load_instance(gid));
            if (!instance) {
                result["error"] = true;
                format fmter = format("Could not load BM-BE sender instance with group id'%1%'") % gid;
                result["error_msg"] = fmter.str();
                return result;
            }
            std::map<std::string, int> members = instance->instance_members();
            vector<std::string> receivers;
            for(map<std::string, int>::iterator it = members.begin(); it != members.end(); ++it) {
                receivers.push_back(it->first);
            }

            return bes_encrypt_b64(gid, receivers, data, image);
            break;
        }
        case BROADMASK_INSTANCE_BM_BE:
        {
            result["error"] = true;
            format fmter = format("Encryption with BM-BE receiver instance '%1%' not possible") % gid;
            result["error_msg"] = fmter.str();
            break;
        }
        case BROADMASK_INSTANCE_SK:
        {
            return sk_encrypt_b64(gid, data, image);
            break;
        }
        default:
        {
            result["error"] = true;
            format fmter = format("Instance with gid '%1%' not found") % gid;
            result["error_msg"] = fmter.str();
            break;
        }
    }
    
    return result;
    
}


FB::VariantMap BroadmaskAPI::decrypt_b64(std::string gid, std::string data, bool image) {
    
    M_INIT_AND_UNLOCK_PROFILE
    
    instance_types type = p->instance_type(gid);
    
    switch (type) {
        case BROADMASK_INSTANCE_BM_BE_SENDER:
        case BROADMASK_INSTANCE_BM_BE:
        {
            return bes_decrypt_b64(gid, data, image);
        }
        case BROADMASK_INSTANCE_SK:
        {
            return sk_decrypt_b64(gid, data, image);
            break;
        }
        default:
        {
            result["error"] = true;
            format fmter = format("Instance with gid '%1%' not found") % gid;
            result["error_msg"] = fmter.str();
            break;
        }
    }
    
    return result;
    
}

FB::VariantMap BroadmaskAPI::bes_encrypt_b64(std::string gid, const std::vector<std::string>& receivers, std::string data, bool image) {
    
    M_INIT_AND_UNLOCK_PROFILE
    
    BM_BE_Sender *bci = dynamic_cast<BM_BE_Sender*>(p->load_instance(gid));
    
    if (!bci) {
        result["error"] = true;
        format fmter = format("BM-BE sender instance with gid '%1%' not found") % gid;
        result["error_msg"] = fmter.str();
        return result;
    }

    bes_ciphertext_t ct;
    bci->bes_encrypt(&ct, receivers, data);
    
    std::stringstream ctos;
    ciphertext_to_stream(ct, bci->gbs, ctos);    
    std::string ct_str = ctos.str();

    
    if (image) {
        // wrap in BMP, then base64 encode
        vector<unsigned char> ct_vec(ct_str.begin(), ct_str.end());
        vector<unsigned char> ct_wrapped = encodeImage(ct_vec);
        result["ciphertext"] = base64_encode(ct_wrapped);

    } else {
        // return base64 encoded ciphertext
        result["ciphertext"] = base64_encode(ct_str);
    }
    free_bes_ciphertext(ct, bci->gbs);
    return result;
}


FB::VariantMap BroadmaskAPI::bes_decrypt_b64(std::string gid, std::string ct_data, bool image) {
    
    M_INIT_AND_UNLOCK_PROFILE
    
    instance_types type = p->instance_type(gid);
    if (type != BROADMASK_INSTANCE_BM_BE_SENDER && type != BROADMASK_INSTANCE_BM_BE) {
        FB::VariantMap result;
        result["error"] = true;
        format fmter = format("BM-BE instance with gid '%1%' not found") % gid;
        result["error_msg"] = fmter.str();
        return result;
        
    }
     
    std::string ct_str;
    if (image) {
        // Unwrap from BMP
        vector<unsigned char> ct_wrapped, ct_unwrapped;
        ct_wrapped = base64_decode_vec(ct_data);
        ct_unwrapped = decodeImage(ct_wrapped);
        ct_str = std::string(reinterpret_cast<char*>(ct_unwrapped.data()), ct_unwrapped.size());
        
    } else {
        // Decode from Base64
        ct_str = base64_decode(ct_data);
    }
    
    // Read params into struct
    bes_ciphertext_t ct;
    std::stringstream ctss(ct_str);
    switch (type) {
        case BROADMASK_INSTANCE_BM_BE_SENDER:
        case BROADMASK_INSTANCE_BM_BE:
        {
            BM_BE* bci = dynamic_cast<BM_BE*>(p->load_instance(gid));
            ciphertext_from_stream(&ct, bci->gbs, ctss);    
            AE_Plaintext *pts;
            ae_error_t r = bci->bes_decrypt(&pts, ct);
            ae_error_to_map(result, r);
            if (!r.error) {
                result["plaintext"] = std::string(reinterpret_cast<char*>(pts->plaintext), pts->len);
                delete pts;
            }  
            free_bes_ciphertext(ct, bci->gbs);
            break;
        }
        default:
        {
            result["error"] = true;
            format fmter = format("BM-BE instance with gid '%1%' not found") % gid;
            result["error_msg"] = fmter.str();
            break;
        }
    }

    return result;
}

FB::VariantMap BroadmaskAPI::sk_encrypt_b64(std::string gid, std::string data, bool image) {
    M_INIT_AND_UNLOCK_PROFILE
    
    BM_SK *ski = dynamic_cast<BM_SK*>(p->load_instance(gid));

    if (!ski) {
        result["error"] = true;
        format fmter = format("BM-SK instance with gid '%1%' not found") % gid;
        result["error_msg"] = fmter.str();
        return result;
    }
    
    AE_Ciphertext *cts;
    AE_Plaintext *pts = new AE_Plaintext;
    pts->plaintext = new unsigned char[data.size()];
    pts->len = data.size();
    memcpy(pts->plaintext, data.data(), data.size());
    
    ae_error_t r = ski->encrypt(&cts, pts);
    delete pts;
    
    ae_error_to_map(result, r);
    
    if (r.error) {
        return result;
    }
    
    // convert ciphertext struct to base64 string
    std::ostringstream oss;
    sk_ciphertext_to_stream(cts, oss);
    std::string cts_string = oss.str();
    delete cts;
    if (image) {
        // Encode as bitmap
        std::vector<unsigned char> ct_vec = std::vector<unsigned char>(cts_string.begin(), cts_string.end());
        std::vector<unsigned char> ct_wrapped = encodeImage(ct_vec);
        result["ciphertext"] = base64_encode(ct_wrapped);
    } else {
        result["ciphertext"] = base64_encode(cts_string);
    }
    

    return result;

}

FB::VariantMap BroadmaskAPI::sk_decrypt_b64(std::string gid, std::string ct_b64, bool image) {
    
    M_INIT_AND_UNLOCK_PROFILE
    
    BM_SK *ski = dynamic_cast<BM_SK*>(p->load_instance(gid));
    if (!ski) {
        result["error"] = true;
        format fmter = format("BM-SK instance with gid '%1%' not found") % gid;
        result["error_msg"] = fmter.str();
        return result;
    }

    // remove base64 encoding
    std::string sk_ct_str = base64_decode(ct_b64);

    
    if (image) {
        // unwrap from bmp
        vector<unsigned char> ct_wrapped (sk_ct_str.begin(), sk_ct_str.end());
        std::vector<unsigned char> ct_unwrapped = decodeImage(ct_wrapped);
        
        // ct_unwrapped contains ct struct
        sk_ct_str = std::string(reinterpret_cast<char*>(ct_unwrapped.data()), ct_unwrapped.size());
 
    }
    AE_Ciphertext* ct;
    stringstream ss(sk_ct_str);
    sk_ciphertext_from_stream(&ct, ss);
    AE_Plaintext *pts;
    ae_error_t r = ski->decrypt(&pts, ct);
    
    ae_error_to_map(result, r);
    
    if (r.error) {
        return result;
    }
    
    result["plaintext"] = std::string(reinterpret_cast<char*>(pts->plaintext), pts->len);
    
    delete pts;
    delete ct;
    return result;
}
 


///////////////////////////////////////////////////////////////////////////////
/// GPGME wrappers for Profile GPG features

#pragma mark -
#pragma mark GnuPG wrapper

FB::VariantMap BroadmaskAPI::gpg_store_keyid(std::string user_id, std::string key_id) {
    
    M_INIT_AND_UNLOCK_PROFILE

    p->setPGPKey(user_id, key_id);
    result["error"] = false;
    return result;
}

FB::VariantMap BroadmaskAPI::gpg_get_keyid(std::string user_id) {
    M_INIT_AND_UNLOCK_PROFILE
    return p->getPGPKey(user_id);
}

FB::VariantMap BroadmaskAPI::gpg_remove_key(std::string user_id) {
    M_INIT_AND_UNLOCK_PROFILE
    p->removePGPKey(user_id);
    result["error"] = false;
    return result;
}

FB::VariantMap BroadmaskAPI::gpg_encrypt_for(std::string data, std::string user_id) {
    M_INIT_AND_UNLOCK_PROFILE
    return p->encrypt_for(data, user_id);
}

FB::VariantMap BroadmaskAPI::gpg_associatedKeys() {
    M_INIT_AND_UNLOCK_PROFILE
    return p->associatedKeys();
}

FB::VariantMap BroadmaskAPI::get_member_sk_gpg(std::string gid, std::string sysid) {
    
    M_INIT_AND_UNLOCK_PROFILE
    FB::VariantMap user_sk = get_member_sk(gid, sysid);
    
    if (user_sk.find("result") == user_sk.end()) {
        return user_sk;
    }
    std::string sk_str;
    try {
        sk_str = user_sk["result"].convert_cast<std::string>();
        if (sk_str.size() > 0) {
            return gpg_encrypt_for(sk_str, sysid);
        } else {
            result["error"] = true;
            format fmter = format("No user %1% exists for instance %2%") % sysid % gid;
            result["error_msg"] = fmter.str();
            return result;
        }
    } catch (std::exception& e) {
        result["error"] = true;
        format fmter = format("Cannot retrieve member sk. Error was: %1%") % e.what();
        result["error_msg"] = fmter.str();
        return result;
    }

}

///////////////////////////////////////////////////////////////////////////////
/// GPGME wrapper, for generic use
#pragma mark -
#pragma mark Profile independent GPGME helpers

FB::VariantMap BroadmaskAPI::gpg_encrypt_with(std::string data, std::string key_id, std::string sign_key_id) {
    return gpgme_encrypt_with(data, key_id, sign_key_id);
}

FB::VariantMap BroadmaskAPI::gpg_decrypt(std::string data) {
    return gpgme_decrypt(data);
}

FB::VariantMap BroadmaskAPI::gpg_import_key(std::string data, bool iskeyblock) {
    if (iskeyblock)
        return gpgme_import_key_block(data);
    else
        return gpgme_search_key(data, 0);
}

FB::VariantMap BroadmaskAPI::gpg_search_keys(std::string filter, int private_keys) {
    return gpgme_search_key(filter, private_keys);
}



///////////////////////////////////////////////////////////////////////////////
/// Profile Management API

#pragma mark -
#pragma mark Profile Management

FB::VariantMap BroadmaskAPI::get_stored_profiles() {
    return pm->get_stored_profiles();
}

void BroadmaskAPI::add_profile(std::string profilename, std::string key) {
    pm->add_profile(profilename, key);
    ProfileManager::archive(pm);
}

FB::VariantMap BroadmaskAPI::unlock_profile(std::string profilename) {

    profile_ptr profile_sp = pm->unlock_profile(m_host->getDOMWindow(), profilename);
    Profile *p = profile_sp.get();
    FB::VariantMap result;
    if (!p) {
        result["error"] = true;
        format fmter = format("Could not unlock profile named '%1%'") % profilename;
        result["error_msg"] = fmter.str();
        return result;
    }

    // Cache active profile name
    active_profile = profilename;
    
    result["error"] = false;
    return result;
}


FB::VariantMap BroadmaskAPI::store_profile(std::string profilename) {

    M_INIT_AND_UNLOCK_PROFILE
    
    pm->store_profile(profilename, profile_sp);
    result["error"] = false;
    return result;
}

FB::VariantMap BroadmaskAPI::delete_profile(std::string profilename) {
    return pm->delete_profile(m_host->getDOMWindow(), profilename);
}

#pragma mark -
#pragma mark Internals

///////////////////////////////////////////////////////////////////////////////
BroadmaskPtr BroadmaskAPI::getPlugin()
{
	BroadmaskPtr plugin(m_plugin.lock());
	if (!plugin) {
		throw FB::script_error("The plugin is invalid");
	}
	return plugin;
}

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
BroadmaskAPI::BroadmaskAPI(const BroadmaskPtr& plugin, const FB::BrowserHostPtr& host) :
m_plugin(plugin), m_host(host) {
    registerMethod("create_sender_instance", make_method(this, &BroadmaskAPI::create_sender_instance));
    registerMethod("create_receiver_instance", make_method(this, &BroadmaskAPI::create_receiver_instance));
    registerMethod("create_shared_instance", make_method(this, &BroadmaskAPI::create_shared_instance));
    registerMethod("create_shared_instance_withkey", make_method(this, &BroadmaskAPI::create_shared_instance_withkey));
    registerMethod("get_bes_public_params", make_method(this, &BroadmaskAPI::get_bes_public_params));
    registerMethod("get_stored_instances", make_method(this, &BroadmaskAPI::get_stored_instances));
    registerMethod("get_instance_descriptor", make_method(this, &BroadmaskAPI::get_instance_descriptor));
    registerMethod("get_instance_members", make_method(this, &BroadmaskAPI::get_instance_members));
    registerMethod("remove_instance", make_method(this, &BroadmaskAPI::remove_instance));    
    registerMethod("add_member", make_method(this, &BroadmaskAPI::add_member));
    registerMethod("add_members", make_method(this, &BroadmaskAPI::add_members));
    registerMethod("remove_member", make_method(this, &BroadmaskAPI::remove_member));        
    registerMethod("get_symmetric_key", make_method(this, &BroadmaskAPI::get_symmetric_key));        
    registerMethod("get_member_sk", make_method(this, &BroadmaskAPI::get_member_sk));        
    registerMethod("get_member_sk_gpg", make_method(this, &BroadmaskAPI::get_member_sk_gpg));
    registerMethod("encrypt_b64", make_method(this, &BroadmaskAPI::encrypt_b64));
    registerMethod("decrypt_b64", make_method(this, &BroadmaskAPI::decrypt_b64));
    registerMethod("bes_encrypt_b64", make_method(this, &BroadmaskAPI::bes_encrypt_b64));
    registerMethod("bes_decrypt_b64", make_method(this, &BroadmaskAPI::bes_decrypt_b64));
    registerMethod("sk_encrypt_b64", make_method(this, &BroadmaskAPI::sk_encrypt_b64));
    registerMethod("sk_decrypt_b64", make_method(this, &BroadmaskAPI::sk_decrypt_b64));
    registerMethod("gpg_store_keyid", make_method(this, &BroadmaskAPI::gpg_store_keyid));
    registerMethod("gpg_search_keys", make_method(this, &BroadmaskAPI::gpg_search_keys));
    registerMethod("gpg_get_keyid", make_method(this, &BroadmaskAPI::gpg_get_keyid));
    registerMethod("gpg_encrypt_for", make_method(this, &BroadmaskAPI::gpg_encrypt_for));
    registerMethod("gpg_encrypt_with", make_method(this, &BroadmaskAPI::gpg_encrypt_with));
    registerMethod("gpg_decrypt", make_method(this, &BroadmaskAPI::gpg_decrypt));
    registerMethod("gpg_associatedKeys", make_method(this, &BroadmaskAPI::gpg_associatedKeys));
    registerMethod("gpg_import_key", make_method(this, &BroadmaskAPI::gpg_import_key));
    registerMethod("gpg_remove_key", make_method(this, &BroadmaskAPI::gpg_remove_key));
    registerMethod("add_profile", make_method(this, &BroadmaskAPI::add_profile));    
    registerMethod("get_stored_profiles", make_method(this, &BroadmaskAPI::get_stored_profiles));
    registerMethod("unlock_profile", make_method(this, &BroadmaskAPI::unlock_profile));
    registerMethod("store_profile", make_method(this, &BroadmaskAPI::store_profile));
    registerMethod("delete_profile", make_method(this, &BroadmaskAPI::delete_profile));
    
    
    // Register active profile property
    registerProperty("active_profile",  make_property(this, &BroadmaskAPI::get_active_profile));
    
    // Restore ProfileManager
    pm = ProfileManager::unarchive();

}

#pragma mark -
#pragma mark Utils

void BroadmaskAPI::ae_error_to_map(FB::VariantMap& result, ae_error_t& r) {
    result["error"] = r.error;
    if (r.error) {
        result["error_msg"] = r.error_msg;
    }    
}

BroadmaskAPI::~BroadmaskAPI() {
    if (pm)
        delete pm;
}