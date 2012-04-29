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



#include "JSObject.h"
#include "variant_list.h"
#include "DOM/Document.h"
#include "global/config.h"
#include "BroadmaskAPI.h"
#include "BitmapWrapper.h"

#include "utils.h"

#include <cryptopp/filters.h>
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;

#include <cryptopp/aes.h>
using CryptoPP::AES;

#include <cryptopp/modes.h>
using CryptoPP::CFB_Mode;

#include <cryptopp/cryptlib.h>
using CryptoPP::Exception;

#include <cryptopp/osrng.h>
using CryptoPP::AutoSeededRandomPool;

using namespace std;
namespace fs = boost::filesystem;


std::string BroadmaskAPI::create_sender_instance(std::string gid, std::string name, int N) {
    return istore->start_sender_instance(gid, name, N);
}

void BroadmaskAPI::create_receiver_instance(std::string gid, std::string name, int N, std::string pubdata_b64, std::string private_key_b64) {
    istore->start_receiver_instance(gid, name, N, pubdata_b64, private_key_b64);
}

void BroadmaskAPI::create_shared_instance(std::string gid, std::string name) {
    istore->start_shared_instance(gid, name);
}

FB::VariantMap BroadmaskAPI::get_instance_descriptor(std::string id) {
    return istore->instance_description(id);
}

void BroadmaskAPI::remove_instance(std::string id) {
    istore->remove_instance(id);
}

std::string BroadmaskAPI::get_member_sk(std::string gid, std::string id) {
    BES_sender *bci = istore->load_instance<BES_sender>(gid);
    if (!bci) {
        cout << "Sender instance " << gid << " not found" << endl;
        return "";
    }
    
    bes_privkey_t sk = NULL;
    bci->get_private_key(&sk, id);
    if (!sk) {
        return "";
    }
    
    std::stringstream oss;
    private_key_to_stream(sk, oss);
    return base64_encode(oss.str());
    
}

int BroadmaskAPI::add_member(std::string gid, std::string id) {
    int type = istore->instance_type(gid);
    
    Instance *instance = NULL;
    switch (type) {
        case BROADMASK_INSTANCE_BES_SENDER:
            instance = istore->load_instance<BES_sender>(gid);
            break;
        case BROADMASK_INSTANCE_BES_RECEIVER:
            instance = istore->load_instance<BES_receiver>(gid);
            break;
        case BROADMASK_INSTANCE_SK:
            instance = istore->load_instance<SK_Instance>(gid);
            break;
        default:
            break;
    }
        
    if (!instance) {
        return -1;
    }
    
    int sys_id = instance->add_member(id);
    instance->store();
    return sys_id;
    
}

FB::VariantMap BroadmaskAPI::add_members(std::string gid, std::vector<std::string> idvector) {

    Instance *instance = istore->load_unknown(gid);    
    FB::VariantMap result;
    
    if (!instance) {
        result["error"] = true;
        result["error_msg"] = "Instance not found";
        return result;
    }
    
    for (std::vector<std::string>::iterator it = idvector.begin(); 
         it != idvector.end(); ++it) {

        int sys_id = instance->add_member(*it);
        cout << "add_members " << *it <<  " mapped to " << sys_id << endl;
        result[*it] = sys_id;

        
    }
    
    istore->store_unknown(gid, instance);
    return result;
}

void BroadmaskAPI::remove_member(std::string gid, std::string id) {
    BES_sender *bci = istore->load_instance<BES_sender>(gid);
    if (bci) {
        bci->remove_member(id);
        bci->store();
    }
}

FB::VariantMap BroadmaskAPI::get_bes_public_params(std::string gid) {
    int type = istore->instance_type(gid);
    
    FB::VariantMap result;
    
    if (type != BROADMASK_INSTANCE_BES_SENDER) {
        result["error"] = true;
        result["error_msg"] = "Invalid Instance type";
        result["instance_type"] = type;
        return result;
    }
    
    BES_sender *sender = istore->load_instance<BES_sender>(gid);
    
    stringstream ss;
    sender->public_params_to_stream(ss);
    result["result"] = base64_encode(ss.str());
    return result;
    
}

FB::VariantMap BroadmaskAPI::get_instance_members(std::string gid) {
    
    int type = istore->instance_type(gid);
    
    Instance *instance = NULL;
    switch (type) {
        case BROADMASK_INSTANCE_BES_SENDER:
            instance = istore->load_instance<BES_sender>(gid);
            break;
        case BROADMASK_INSTANCE_BES_RECEIVER:
            instance = istore->load_instance<BES_receiver>(gid);
            break;
        case BROADMASK_INSTANCE_SK:
            instance = istore->load_instance<SK_Instance>(gid);
            break;
        default:
            break;
    }
    
    FB::VariantMap result;

    if (!instance)
        return result;     // No instance available

    std::map<std::string, int> members = instance->instance_members();
    for (std::map<std::string, int>::iterator it = members.begin();
         it != members.end(); ++it) {
        cout << it->first << " " << it->second << endl;
        result[it->first] = it->second;
    }
    
    return result;

}

FB::VariantMap BroadmaskAPI::encrypt_b64(std::string gid, std::string data, bool image) {
    
    int type = istore->instance_type(gid);
    
    FB::VariantMap result;
    
    switch (type) {
        case BROADMASK_INSTANCE_BES_SENDER:
        {
            BES_sender *instance = istore->load_instance<BES_sender>(gid);
            if (!instance) {
                result["error"] = true;
                result["error_msg"] = "Couldn't load sender instance";
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
        case BROADMASK_INSTANCE_BES_RECEIVER:
        {
            result["error"] = true;
            result["error_msg"] = "Can't encrypt with a receiver instance";
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
            result["error_msg"] = "Unknown instance";
            break;
        }
    }
    
    return result;
    
}

FB::VariantMap BroadmaskAPI::decrypt_b64(std::string gid, std::string data, bool image) {
    
    int type = istore->instance_type(gid);
    
    FB::VariantMap result;
    
    switch (type) {
        case BROADMASK_INSTANCE_BES_SENDER:
        {
            result["error"] = true;
            result["error_msg"] = "Can't decrypt with a receiver instance";
            break;
        }
        case BROADMASK_INSTANCE_BES_RECEIVER:
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
            result["error_msg"] = "Unknown instance";
            break;
        }
    }
    
    return result;
    
}

FB::VariantMap BroadmaskAPI::bes_encrypt_b64(std::string gid, const std::vector<std::string>& receivers, std::string data, bool image) {
    BES_sender *bci = istore->load_instance<BES_sender>(gid);
    
    FB::VariantMap result;
    if (!bci) {
        result["error"] = true;
        result["error_msg"] = "Sender Instance not found";
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
    
    return result;
}


FB::VariantMap BroadmaskAPI::bes_decrypt_b64(std::string gid, std::string ct_data, bool image) {
    BES_receiver *bci = istore->load_instance<BES_receiver>(gid);
    
    if (!bci) {
        FB::VariantMap result;
        result["error"] = true;
        result["error_msg"] = "Receiver instance not found";
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
    ciphertext_from_stream(&ct, bci->gbs, ctss);
    
    return bci->bes_decrypt(ct);
}

FB::VariantMap BroadmaskAPI::sk_encrypt_b64(std::string gid, std::string data, bool image) {
    SK_Instance *ski = istore->load_instance<SK_Instance>(gid);

    FB::VariantMap result;

    if (!ski) {
        cout << "Shared Instance " << gid << " not found ";
        result["error"] = true;
        result["error_msg"] = "Instance not found";
        return result;
    }
    
    result = ski->encrypt(data);
    
    if (result.find("error") != result.end())
        return result;
    
    std::string ct_str = result["ciphertext"].convert_cast<std::string>();
    if (image) {
        std::vector<unsigned char> ct_vec (ct_str.begin(), ct_str.end());
        std::vector<unsigned char> ct_wrapped = encodeImage(ct_vec);
        result["ciphertext"] = base64_encode(ct_wrapped);
    } else {
        result["ciphertext"] = base64_encode(ct_str);
    }
    
    return result;
    
    
    
}

FB::VariantMap BroadmaskAPI::sk_decrypt_b64(std::string gid, std::string ct_b64, bool image) {
    SK_Instance *ski = istore->load_instance<SK_Instance>(gid);
    
    FB::VariantMap result;
    
    if (!ski) {
        cout << "Shared Instance " << gid << " not found ";
        result["error"] = true;
        result["error_msg"] = "Instance not found";
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
    sk_ciphertext_t ct;
    stringstream ss(sk_ct_str);
    sk_ciphertext_from_stream(&ct, ss);
    return ski->decrypt(ct);
}
 


/*
 * Instance Management
 */

FB::VariantMap BroadmaskAPI::get_stored_instances() {
    return istore->get_stored_instances();
}

/*
 * GPG API
 */


void BroadmaskAPI::gpg_store_keyid(std::string user_id, std::string key_id) {
    ustore->setPGPKey(user_id, key_id);
    UserStorage::archive(ustore);
}

FB::VariantMap BroadmaskAPI::gpg_get_keyid(std::string user_id) {
    return ustore->getPGPKey(user_id);
}

void BroadmaskAPI::gpg_remove_key(std::string user_id) {
    ustore->removePGPKey(user_id);
    UserStorage::archive(ustore);
}

FB::VariantMap BroadmaskAPI::gpg_encrypt_for(std::string data, std::string user_id) {
    return ustore->encrypt_for(data, user_id);
}

FB::VariantMap BroadmaskAPI::gpg_encrypt_with(std::string data, std::string key_id) {
    return ustore->encrypt_with(data, key_id);
}

FB::VariantMap BroadmaskAPI::gpg_decrypt(std::string data) {
    return ustore->decrypt(data);
}

FB::VariantMap BroadmaskAPI::gpg_associatedKeys() {
    return ustore->associatedKeys();
}

FB::VariantMap BroadmaskAPI::gpg_import_key(std::string data, bool iskeyblock) {
    if (iskeyblock)
        return ustore->import_key_block(data);
    else
        return ustore->search_key(data);
}

FB::VariantMap BroadmaskAPI::get_member_sk_gpg(std::string gid, std::string sysid) {
    std::string user_sk = get_member_sk(gid, sysid);
    
    FB::VariantMap result;
    if (user_sk.size() > 0) {
        result = gpg_encrypt_for(user_sk, sysid);
    } else {
        result["error"] = true;
        result["error_msg"] = "No SK for userid";
    }
    return result;
}



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
    registerMethod("get_bes_public_params", make_method(this, &BroadmaskAPI::get_bes_public_params));
    registerMethod("get_stored_instances", make_method(this, &BroadmaskAPI::get_stored_instances));
    registerMethod("get_instance_descriptor", make_method(this, &BroadmaskAPI::get_instance_descriptor));
    registerMethod("get_instance_members", make_method(this, &BroadmaskAPI::get_instance_members));
    registerMethod("remove_instance", make_method(this, &BroadmaskAPI::remove_instance));    
    registerMethod("add_member", make_method(this, &BroadmaskAPI::add_member));
    registerMethod("add_members", make_method(this, &BroadmaskAPI::add_members));
    registerMethod("remove_member", make_method(this, &BroadmaskAPI::remove_member));        
    registerMethod("get_member_sk", make_method(this, &BroadmaskAPI::get_member_sk));        
    registerMethod("get_member_sk_gpg", make_method(this, &BroadmaskAPI::get_member_sk_gpg));
    registerMethod("encrypt_b64", make_method(this, &BroadmaskAPI::encrypt_b64));
    registerMethod("decrypt_b64", make_method(this, &BroadmaskAPI::decrypt_b64));
    registerMethod("bes_encrypt_b64", make_method(this, &BroadmaskAPI::bes_encrypt_b64));
    registerMethod("bes_decrypt_b64", make_method(this, &BroadmaskAPI::bes_decrypt_b64));
    registerMethod("test", make_method(this, &BroadmaskAPI::test));
    registerMethod("sk_encrypt_b64", make_method(this, &BroadmaskAPI::sk_encrypt_b64));
    registerMethod("sk_decrypt_b64", make_method(this, &BroadmaskAPI::sk_decrypt_b64));
    registerMethod("gpg_store_keyid", make_method(this, &BroadmaskAPI::gpg_store_keyid));
    registerMethod("gpg_get_keyid", make_method(this, &BroadmaskAPI::gpg_get_keyid));
    registerMethod("gpg_encrypt_for", make_method(this, &BroadmaskAPI::gpg_encrypt_for));
    registerMethod("gpg_encrypt_with", make_method(this, &BroadmaskAPI::gpg_encrypt_with));
    registerMethod("gpg_decrypt", make_method(this, &BroadmaskAPI::gpg_decrypt));
    registerMethod("gpg_associatedKeys", make_method(this, &BroadmaskAPI::gpg_associatedKeys));
    registerMethod("gpg_import_key", make_method(this, &BroadmaskAPI::gpg_import_key));
    registerMethod("gpg_remove_key", make_method(this, &BroadmaskAPI::gpg_remove_key));


    // (Re-)start User Storage
    ustore = UserStorage::unarchive();
    
    // (Re-)start Instance Storage
    istore = InstanceStorage::unarchive();
}


/*
 * TESTS
 */
void gen_random(char *s, const int len) {
    static const char alphanum[] =
    "0123456789"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz";
    
    for (int i = 0; i < len; ++i) {
        s[i] = alphanum[rand() % (sizeof(alphanum) - 1)];
    }
    
    s[len] = 0;
}


void BroadmaskAPI::test(const FB::JSObjectPtr &callback) {
    boost::thread t(boost::bind(&BroadmaskAPI::testsuite,
                                this, callback));
}


void BroadmaskAPI::testsuite(const FB::JSObjectPtr &callback) {
    cout << "starting testcase" << endl;
    create_sender_instance("foo",  "testsuite_instance", 256);

    BES_sender *sender = istore->load_instance<BES_sender>("foo");       
    if (!sender) {
        cout << "Sender instance foo should have been started, but wasn't" << endl;
        return;
    }
    
    int add1 = add_member("foo", "1");
    int add2 = add_member("foo", "1");
    
    if (add1 != add2) {
        cout << "Inserted IDs were " << add1 << " and " << add2 << " , which are not equal" << endl;
        return;
    }
    
    
    remove_member("foo", "1");
    int add3 = add_member("foo", "23");
    if (add1 == add3)
        cout << "New ID should not be old value " << add1 << endl;
    
    if (sender->member_id("23") != 1)
        cout << "Member id should have been 1" << endl;
    
     if (sender->member_id("1") != -1)
         cout << "Member '1' was not removed" << endl;
    
    istore->remove_instance("foo");
    sender = istore->load_instance<BES_sender>("foo");
    if (sender != NULL)
        cout << "sender instance not deleted" << endl;
    
    boost::timer total;
    std::string foo_pub_params = create_sender_instance("test", "test_instance", 256);
    cout << "Setup phase: " << total.elapsed() << endl;

    vector<std::string> s;
    for (int i = 0; i < 256; ++i) {
        std::string user = boost::lexical_cast<std::string>(i);
        add_member("test", user);
        s.push_back(user);
        
        std::string privkey = get_member_sk("test", user);
        create_receiver_instance(user, "test_user", 256, foo_pub_params, privkey);       
    }
    
    
    int size = 100000;
    char *random = new char[size];
    std::string rec_message_j;
    std::string ct_data;
    for (int i = 2; i <= 256; i*=2) {
        vector<std::string> recipients;
        for (int j = 0; j < i; ++j) {
            recipients.push_back(s[j]);
        }
        cout << "System Test with " << i << "/256 recipients" << endl;
        boost::timer round, step;
        
        gen_random(random, size-1);
        std::string message(random);
        step.restart();
        FB::VariantMap enc_result = bes_encrypt_b64("test", recipients, message, false);
        ct_data = enc_result["ciphertext"].convert_cast<std::string>();
        
        cout << "(ENC): " << i << " " << step.elapsed() << endl;
        step.restart();
        
        cout << "(DEC): " << i << " ";
        for (int j = 0; j < i; ++j) {
            FB::VariantMap dec_result = bes_decrypt_b64(s[j], ct_data, false);
            try {
                rec_message_j = dec_result["plaintext"].convert_cast<std::string>();
                if (message.compare(rec_message_j) != 0) {
                    cout << "Decrypting using Receiver " << s[j] << " incorrect: " << endl;
                    return;
                }
            } catch (exception& e) {
                cout << "Decrypting using Receiver " << s[j] << " incorrect: " << endl;
                return;
            }
            cout << step.elapsed() << " ";
            step.restart();
        }
        
        for (int j = i; j < 256; ++j) {
            step.restart();
            FB::VariantMap dec_result = bes_decrypt_b64(s[j], ct_data, false);
            try {
                std::string error = dec_result["error"].convert_cast<std::string>();
                
                if (dec_result.find("plaintext") != dec_result.end()) {
                    cout << "Decrypting using Receiver " << s[j] << " yielded a result, but should not" << endl;
                    return;
                }
            } catch (exception& e) {
                cout << "Decrypting using Receiver " << s[j] << " should yield an error, but seems like there wasn't: " << e.what() << endl;
                return;
            }
            cout << step.elapsed() << " ";
        }
        cout << endl;
        
        cout << "Round " << i << ": " << round.elapsed() << endl;
        round.restart();
    }
    delete[] random;
                          
    
    cout << "Total time elapsed: " << total.elapsed() << endl;
    
    istore->remove_instance("test");
    sender = istore->load_instance<BES_sender>("test");
    if (sender != NULL)
        cout << "sender instance not deleted" << endl;
    
    for (int i = 0; i < 256; ++i) {
        std::string receiver = boost::lexical_cast<std::string>(i);
        istore->remove_instance(receiver);
        
        if(istore->load_instance<BES_sender>(receiver))
            cout << "Receiver instance " << receiver << " not deleted " << endl;
        
    }

    
    callback->InvokeAsync("", FB::variant_list_of("it worked"));

}
