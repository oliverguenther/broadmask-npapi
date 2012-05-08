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
#include "streamhelpers.hpp"

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

void BroadmaskAPI::create_shared_instance_withkey(std::string gid, std::string name, std::string key_b64) {
    istore->start_shared_instance_withkey(gid, name, key_b64);
}



FB::VariantMap BroadmaskAPI::get_instance_descriptor(std::string id) {
    return istore->instance_description(id);
}

void BroadmaskAPI::remove_instance(std::string id) {
    istore->remove_instance(id);
}

std::string BroadmaskAPI::get_symmetric_key(std::string gid) {
    SK_Instance *ski = istore->load_instance<SK_Instance>(gid);
    
    if (!ski) {
        cout << "Sender instance " << gid << " not found" << endl;
        return "";   
    }
    
    std::vector<unsigned char> key = ski->get_symmetric_key();
    return base64_encode(key);

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
    free_bes_privkey(sk);
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
    free_bes_ciphertext(ct, bci->gbs);
    return result;
}


FB::VariantMap BroadmaskAPI::bes_decrypt_b64(std::string gid, std::string ct_data, bool image) {
    
    int type = istore->instance_type(gid);
    if (type != BROADMASK_INSTANCE_BES_SENDER && type != BROADMASK_INSTANCE_BES_RECEIVER) {
        FB::VariantMap result;
        result["error"] = true;
        result["error_msg"] = "BES instance not found";
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
    FB::VariantMap result;
    switch (type) {
        case BROADMASK_INSTANCE_BES_SENDER:
        {
            BES_sender* bci = istore->load_instance<BES_sender>(gid);
            ciphertext_from_stream(&ct, bci->gbs, ctss);    
            result = bci->bes_decrypt(ct);
            free_bes_ciphertext(ct, bci->gbs);
            break;
        }
        case BROADMASK_INSTANCE_BES_RECEIVER:
        {
            BES_receiver* bci = istore->load_instance<BES_receiver>(gid);
            ciphertext_from_stream(&ct, bci->gbs, ctss);    
            result = bci->bes_decrypt(ct);
            free_bes_ciphertext(ct, bci->gbs);
            break;
        }
        default:
        {
            result["error"] = true;
            result["error_msg"] = "BES instance not found";
            break;
        }
    }

    return result;
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
    result = ski->decrypt(ct);
    free_sk_ciphertext(ct);
    return result;
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
    registerMethod("gpg_get_keyid", make_method(this, &BroadmaskAPI::gpg_get_keyid));
    registerMethod("gpg_encrypt_for", make_method(this, &BroadmaskAPI::gpg_encrypt_for));
    registerMethod("gpg_encrypt_with", make_method(this, &BroadmaskAPI::gpg_encrypt_with));
    registerMethod("gpg_decrypt", make_method(this, &BroadmaskAPI::gpg_decrypt));
    registerMethod("gpg_associatedKeys", make_method(this, &BroadmaskAPI::gpg_associatedKeys));
    registerMethod("gpg_import_key", make_method(this, &BroadmaskAPI::gpg_import_key));
    registerMethod("gpg_remove_key", make_method(this, &BroadmaskAPI::gpg_remove_key));
    registerMethod("run_benchmark", make_method(this, &BroadmaskAPI::run_benchmark));
    

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

void BroadmaskAPI::run_benchmark(std::string target_folder, int max_receivers, int passes, const FB::JSObjectPtr &callback) {
    boost::thread t(boost::bind(&BroadmaskAPI::test,
                                this, target_folder, max_receivers, passes, callback));
}


void BroadmaskAPI::test(std::string target_folder, int max_receivers, int passes, const FB::JSObjectPtr &callback) {
    
    int sizes[6] = {10, 100, 1000, 5000, 10000, 50000};
    for (int i = 0; i < 6; ++i) {
        run_bes_benchmark(target_folder, max_receivers, sizes[i], false, passes);
        cout << "completed BES benchmark, 256 receivers, Plaintext sized: " << sizes[i] << endl;
        callback->InvokeAsync("", FB::variant_list_of("completed BES benchmark, 256 receivers, Plaintext sized: " + sizes[i]));
        run_bes_benchmark(target_folder, max_receivers, sizes[i], true, passes);
        cout << "completed BES benchmark, 256 receivers, BMP wrapped Plaintext sized: " << sizes[i] << endl;        
        callback->InvokeAsync("", FB::variant_list_of("completed BES benchmark, 256 receivers, BMP wrapped Plaintext sized: " + sizes[i]));
        run_sk_benchmark(target_folder, max_receivers, sizes[i], false, passes);
        cout << "completed SK benchmark, 256 receivers, Plaintext sized: " << sizes[i] << endl;
        callback->InvokeAsync("", FB::variant_list_of("completed SK benchmark, 256 receivers, Plaintext sized: " + sizes[i]));
        run_sk_benchmark(target_folder, max_receivers, sizes[i], true, passes);
        cout << "completed SK benchmark, 256 receivers, BMP wrapped Plaintext sized: " << sizes[i] << endl;
        callback->InvokeAsync("", FB::variant_list_of("completed SK benchmark, 256 receivers, BMP wrapped Plaintext sized: " + sizes[i]));
    }
    callback->InvokeAsync("", FB::variant_list_of());
}

void BroadmaskAPI::run_sk_benchmark(std::string output_folder, int max_users, int file_size, bool as_image, int passes) {
   
    // Output streams
    boost::filesystem::path folder(output_folder);
    
    if (!boost::filesystem::exists(folder))
        boost::filesystem::create_directories(folder);
    
    
    std::string target_file = "SK_";
    target_file += boost::lexical_cast<std::string>(file_size);
    if (as_image)
        target_file += "_asimage";
    target_file += ".data";
    
    boost::filesystem::path target (folder / target_file);
    ofstream os (target.string().c_str());
    
    cout << "BroadMask SK benchmark using " << file_size << " KB random plaintext. " << (as_image ? " (wrapped as Bitmap) " : "") << "  averaged over " << passes << " # of passes " << endl;
    os << "# BroadMask SK benchmark using " << file_size << " KB random plaintext. " << (as_image ? " (wrapped as Bitmap) " : "") << "  averaged over " << passes << " # of passes " << endl;
    os << "# Columns: <user size> <encryption_average> <decryption_average> <ciphertext_size>" << endl;
    
    // setup
    boost::timer timer;
    for (int size = 4; size <= max_users; size *= 4) {
        
        double enc_avg = 0, dec_avg = 0, ct_size = 0;

        for (int i = 0; i < passes; ++i) {
            cout << "[PASS " << i+1 << "/" << passes << "]" << endl;
            create_shared_instance("sk_benchmark_sender", "SK test sending instance");
            std::string key = get_symmetric_key("sk_benchmark_sender");
            
            // encryption phase
            char *buffer = new char[(1000 * file_size) + 1];
            gen_random(buffer, (1000 * file_size));            
            std::string message(buffer);
            delete[] buffer;
            
            timer.restart();
            FB::VariantMap enc_result = sk_encrypt_b64("sk_benchmark_sender", message, as_image);
            enc_avg += timer.elapsed();
            cout << "-> encryption " << timer.elapsed() << endl;

            
            std::string ct_data;
            try {
                ct_data = enc_result["ciphertext"].convert_cast<std::string>();
                ct_size += ct_data.size();
            } catch (exception &e) {
                cerr << "Error on encryption op: " << e.what() << endl;
            }
            
            timer.restart();
            
            sk_decrypt_b64("sk_benchmark_sender", ct_data, as_image);
            dec_avg += timer.elapsed();
            cout << "-> Decryption "<< timer.elapsed() << endl;
            
            
            // compute decrypt passes using first receiver
            create_shared_instance_withkey("sk_benchmark_receiver", "receiver sk test", key);
            std::string rec_key = get_symmetric_key("sk_benchmark_sender");
                
            if (key.compare(rec_key) != 0) {
                cout << "KEYS are not identical" << endl;
                cout << "**** " << key << "****" << endl;
                cout << "**** " << rec_key << "****" << endl;
                return;
            }
                
                
            timer.restart();
            FB::VariantMap dec_result = sk_decrypt_b64("sk_benchmark_receiver", ct_data, as_image);
            dec_avg += timer.elapsed();
            dec_avg /= 2;
                
            try {
                std::string rec_message = dec_result["plaintext"].convert_cast<std::string>();
                if (message.compare(rec_message) != 0) {
                    throw "Plaintext were not equal";
                }
                
            } catch (exception& e) {
                std::string error = dec_result["error_msg"].convert_cast<std::string>();
                cerr << "ERROR for decrypting instance: No recovered message found - Error was: " << e.what() << " - " << error << endl;
            }
            
            // remove receiver instance
            remove_instance("sk_benchmark_receiver");

            
            
        }
        
        enc_avg /= passes;
        dec_avg /= passes;
        ct_size /= passes;

        cout << size << " " << enc_avg << " " << dec_avg << " " << ct_size / 1000 << endl;
        os << size << " " << enc_avg << " " << dec_avg << " " << ct_size / 1000<< endl;

        
        remove_instance("sk_benchmark_sender");
        
        
    }

}

void BroadmaskAPI::run_bes_benchmark(std::string output_folder, int max_users, int file_size, bool as_image, int passes) {
    
    // setup max receivers once
    std::vector<std::string> receiving_instances;
    for (int i = 1; i < max_users; i++) {
        std::string user = boost::lexical_cast<std::string>(i);
        receiving_instances.push_back(user);
    }
    
    // Output streams
    boost::filesystem::path folder(output_folder);
    
    if (!boost::filesystem::exists(folder))
        boost::filesystem::create_directories(folder);

    
    std::string target_file = "BES_";
    target_file += boost::lexical_cast<std::string>(file_size);
    if (as_image)
        target_file += "_asimage";
    target_file += ".data";
    
    
    boost::filesystem::path target (folder / target_file);
    if (!boost::filesystem::exists(target))
        boost::filesystem::remove(target);
    ofstream os (target.string().c_str());

    cout << "BroadMask benchmark using " << file_size << " KB random plaintext. " << (as_image ? " (wrapped as Bitmap) " : "") << "  averaged over " << passes << " # of passes " << endl;
    os << "# BroadMask benchmark using " << file_size << " KB random plaintext. " << (as_image ? " (wrapped as Bitmap) " : "") << "  averaged over " << passes << " # of passes " << endl;
    os << "# Columns: <user size> <setup_average> <receiver_setup_average> <encryption_average> <decryption_average> <publickey-size> <ciphertext_size>" << endl;

    
    // setup
    for (int size = 4; size <= max_users; size *= 4) {

        bes_setup_times *s = new bes_setup_times[passes];
        bes_encryption_times *e = new bes_encryption_times[passes];
        
        std::vector<std::string> receivers (receiving_instances.begin(), receiving_instances.begin() + (size -1));

        double setup_avg = 0, rsetup_avg = 0;
        double enc_avg = 0, dec_avg = 0;
        double pk_size_avg = 0, ct_size_avg = 0;
        for (int i = 0; i < passes; ++i) {
            
            cout << "[PASS " << i+1 << "/" << passes << "]" << endl;
            // remove old instances
            remove_instance("bes_benchmark_sender");
            for (std::vector<std::string>::iterator it = receivers.begin(); it != receivers.end(); ++it) {
                remove_instance(*it);
            }
            
            // setup phase
            s[i] = run_bes_setup("bes_benchmark_sender", size, receivers, false);
            
            pk_size_avg += s[i].public_key_size;
            setup_avg += s[i].setup_time;
            
            // add receiver times (sender, receiver) + average
            double r_pass_avg = 0;
            for (std::vector<double>::iterator it = s[i].receiver_setup_times.begin(); 
                 it != s[i].receiver_setup_times.end(); ++it) {
                r_pass_avg += *it;
            }
            rsetup_avg += (r_pass_avg / s[i].receiver_setup_times.size());
            
            // encryption phase
            cout << "-> encryption " << endl;
            char *buffer = new char[(1000 * file_size) + 1];
            gen_random(buffer, (1000 * file_size));
            
            std::string message(buffer);
            //cout << "Running bes encryption with " << receivers.size() + 1 << " / " << receiving_instances.size() + 1 << " and message size " << message.size() << endl;
            e[i] = run_bes_encryption("bes_benchmark_sender", receivers, receivers.at(0), message, as_image);

            delete[] buffer;
            message.erase();
            
            enc_avg += e[i].enc_time;                
            double dec_pass_avg = 0;
            for (std::vector<double>::iterator it = e[i].dec_times.begin(); 
                 it != e[i].dec_times.end(); ++it) {
                dec_pass_avg += *it;
            }
            dec_avg += (dec_pass_avg / e[i].dec_times.size());
            
            ct_size_avg +=e[i].ciphertext_size;

            
        }
        setup_avg /= passes;
        rsetup_avg /= passes;
        enc_avg /= passes;
        dec_avg /= passes;
        pk_size_avg /= passes;
        ct_size_avg /= passes;
        cout << size << " " << setup_avg << " " << rsetup_avg << " " << enc_avg << " " << dec_avg << " " << pk_size_avg / 1000 << " " << ct_size_avg / 1000 << endl;
        os << size << " " << setup_avg << " " << rsetup_avg << " " << enc_avg << " " << dec_avg << " " << pk_size_avg / 1000 << " " << ct_size_avg / 1000 << endl;
        
        
        delete[] s;
        delete[] e;
    }
    
    // remove instances after benchmark succeeded
    remove_instance("bes_benchmark");
    for (std::vector<std::string>::iterator it = receiving_instances.begin();
         it != receiving_instances.end(); ++it) {
        remove_instance(*it);
    }
    
    
    
}

bes_setup_times BroadmaskAPI::run_bes_setup(std::string sender_instance, int N, std::vector<std::string>& decrypt_instances, bool remove_after) {
    bes_setup_times times;
    
    boost::timer timer;
    std::string public_params = create_sender_instance(sender_instance, "benchmark instance", N);
    times.setup_time = timer.elapsed();
    times.public_key_size = public_params.size();
    cout << "-> Setup " << times.setup_time << endl;
    cout << "Adding receiver ";
    for (std::vector<std::string>::iterator it = decrypt_instances.begin(); it != decrypt_instances.end(); ++it) {
        cout << *it << " ";
        add_member(sender_instance, *it);
        timer.restart();
        std::string sk = get_member_sk(sender_instance, *it);
        create_receiver_instance(*it, "benchmark receiver", N, public_params, sk);
        double rsetup_time = timer.elapsed();
        cout << "(" << rsetup_time << "s) ";
        times.receiver_setup_times.push_back(rsetup_time);
        if (remove_after)
            remove_instance(*it);
    }
    cout << endl;
    
    if (remove_after)
        remove_instance(sender_instance);
    
    return times;
    
}

bes_encryption_times BroadmaskAPI::run_bes_encryption(std::string sender_instance, std::vector<std::string>& receivers, std::string receiver_instance, std::string& message, bool asImage) {
    
    bes_encryption_times times;
    
    boost::timer timer;
    FB::VariantMap enc_result = bes_encrypt_b64(sender_instance, receivers, message, asImage);
    times.enc_time = timer.elapsed();
    cout << "-> sender encryption " << times.enc_time << endl;

    
    
    std::string ct_data;
    try {
        ct_data = enc_result["ciphertext"].convert_cast<std::string>();
        times.ciphertext_size = ct_data.size();
    } catch (exception &e) {
        cerr << "Error on encryption op: " << e.what() << endl;
    }
    
    
    // test sender decryption
    timer.restart();
    cout << "-> sender decryption " << endl;
    FB::VariantMap dec_result = bes_decrypt_b64(sender_instance, ct_data, asImage);
    times.dec_times.push_back(timer.elapsed());
    // Should be able to decrpyt
    try {
        std::string rec_message = dec_result["plaintext"].convert_cast<std::string>();
        if (message.compare(rec_message) != 0) {
            throw "Plaintext were not equal";
        }
        
    } catch (exception& e) {
        std::string error = dec_result["error_msg"].convert_cast<std::string>();
        cerr << "ERROR for decrypting with sender instance " << sender_instance << ". No recovered message found - Error was: " << e.what() << " - " << error << endl;
    }
    
    // decrypt using one receiver
    timer.restart();
    dec_result = bes_decrypt_b64(receiver_instance, ct_data, asImage);
    double rec_time = timer.elapsed();
    times.dec_times.push_back(rec_time);
    cout << "-> receiver decryption " << rec_time<< endl;

    try {
    std::string rec_message = dec_result["plaintext"].convert_cast<std::string>();
        if (message.compare(rec_message) != 0) {
            throw "Plaintext were not equal";
        }

    } catch (exception& e) {
        std::string error = dec_result["error_msg"].convert_cast<std::string>();
        cerr << "ERROR for decrypting instance " << receiver_instance << ". No recovered message found - Error was: " << e.what() << " - " << error << endl;
    }
    
    return times;
    
}
