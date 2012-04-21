/**********************************************************\
 
 Auto-generated BroadmaskAPI.cpp
 
 \**********************************************************/

#include <iostream>
#include <fstream>
#include <sstream>
#include <cmath>

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


BES_sender* BroadmaskAPI::get_sender_instance(string gid) {
    map<string,BES_sender>::iterator it = sending_groups.find(gid);
    if (it != sending_groups.end())
        return &(it->second);
    else
        return NULL;
}

BES_receiver* BroadmaskAPI::get_receiver_instance(string gid) {
    map<string,BES_receiver>::iterator it = receiving_groups.find(gid);
    if (it != receiving_groups.end())
        return &(it->second);
    else
        return NULL;
}

/** Load the BES instance with the GID or create one if non-existant
 *
 * @param gid Group identifier
 * @param N User count
 */
string BroadmaskAPI::start_sender_instance(string gid, int N) {
    map<string,BES_sender>::iterator it = sending_groups.find(gid);
    fs::path bcfile = get_instance_file(gid, "bes_sender");
    stringstream params;

    
    if (it != sending_groups.end()) {
        cout << "Sending Instance " << gid << " is already loaded" << endl;
        it->second.public_params_to_stream(params);
        return base64_encode(params.str());
    }
    
    BES_sender *instance;
    if (fs::is_regular_file(bcfile)) {
        instance = dynamic_cast<BES_sender*>(load_instance(bcfile));        
    } else {
        instance = new BES_sender(gid, N);
        sending_groups.insert(pair<string, BES_sender> (gid, *instance));

        // Store BES system
        instance->store(true);
        
        // Store Instance 
        string classpath(bcfile.string());
        classpath += "_serialized";
        
        std::ofstream ofs(classpath.c_str());
        boost::archive::text_oarchive oa(ofs);
        oa << *(instance);
    }
    
    if (instance == NULL) {
        cout << "Instance " << gid << " couldn't be loaded" << endl;
        return "";
    }
    instance->public_params_to_stream(params);    
    return base64_encode(params.str());
    
}

void BroadmaskAPI::start_receiver_instance(string gid, int N, string pubdata_b64, string private_key_b64) {
    map<string,BES_receiver>::iterator it = receiving_groups.find(gid);
    fs::path bcfile = get_instance_file(gid, "bes_receiver");
    
    if (it != receiving_groups.end()) {
        cout << "Receiving Instance " << gid << " is already loaded" << endl;
    } else if (fs::is_regular_file(bcfile)) {
        load_instance(bcfile);
    } else {
        string public_params = base64_decode(pubdata_b64);
        string private_key = base64_decode(private_key_b64);
        
        BES_receiver *instance = new BES_receiver(gid, N, public_params, private_key);
        receiving_groups.insert(pair<string, BES_receiver> (gid,*instance));
        
        // Store BES system
        instance->store(true);
        
        // Store Instance 
        string classpath(bcfile.string());
        classpath += "_serialized";
        
        std::ofstream ofs(classpath.c_str());
        boost::archive::text_oarchive oa(ofs);
        oa << *(instance);  
    }
    
}

BES_base* BroadmaskAPI::load_instance(fs::path path) {
    if (!fs::is_regular_file(path)) {
        cout << "Couldn't load instance " << path.string() << endl;
        return NULL;
    }
    
    if (path.filename() == "bes_receiver") {
        BES_receiver *instance = new BES_receiver;
        
        cout << "Loading receiver instance " << path.string() << endl;
        
        string classpath(path.string());
        classpath += "_serialized";
        
        std::ifstream ifs(classpath.c_str(), std::ios::in);
        boost::archive::text_iarchive ia(ifs);
        ia >> *(instance);
        
        instance->restore();
        receiving_groups.insert(pair<string, BES_receiver> (instance->groupid(),*instance));
        
        return (BES_base*) instance;
    } else if (path.filename() == "bes_sender") {
        BES_sender *instance = new BES_sender;
        
        cout << "Loading sender instance " << path.string() << endl;
        
        string classpath(path.string());
        classpath += "_serialized";
        
        std::ifstream ifs(classpath.c_str(), std::ios::in);
        boost::archive::text_iarchive ia(ifs);
        try {
            cout << "Input stream is good? " << ifs.good() << " is eof?" << ifs.eof() << endl;
            ia >> *instance;
            instance->restore();
            sending_groups.insert(pair<string, BES_sender> (instance->groupid(),*instance));
            
            return (BES_base*) instance;
        } catch (exception& e) {
            cout << e.what() << endl;
            return NULL;
        }
    } else {
        cout << "Couldn't determine instance type " << path.string() << endl;
        return NULL;
    }
}

void BroadmaskAPI::restore_instances() {
    pair< vector<string>, vector<string> > instances = stored_instances();
    
    for (vector<string>::iterator it = instances.first.begin(); it!=instances.first.end(); ++it) {
        load_instance(fs::path(*it));
    }

    for (vector<string>::iterator it = instances.second.begin(); it!=instances.second.end(); ++it) {
        load_instance(fs::path(*it));
    }
    
}

template <class T>
void BroadmaskAPI::storeInstance(T *bci) {
    // Only derived classes of BES_base
    (void)static_cast<BES_base*>((T*)0);
        
    // Store BES system
    bci->store(true);
    
    // Store Instance 
    string classpath = bci->instance_file();
    classpath += "_serialized";
    
    std::ofstream ofs(classpath.c_str());
    boost::archive::text_oarchive oa(ofs);
    oa << *(bci);
    
}


std::string BroadmaskAPI::get_member_sk(string gid, string id) {
    BES_sender *bci = get_sender_instance(gid);
    if (!bci) {
        cout << "Sender instance " << gid << " not found" << endl;
        return "";
    }
    
    bes_privkey_t sk = NULL;
    bci->get_private_key(&sk, id);
    if (!sk) {
        return "";
    }
    
    stringstream oss;
    bci->private_key_to_stream(sk, oss);
    return base64_encode(oss.str());
    
}

int BroadmaskAPI::add_member(string gid, string id) {
    BES_sender *bci = get_sender_instance(gid);
    if (!bci) {
        cout << "Sender instance " << gid << " not found" << endl;
        return -1;
    }

    int sys_id = bci->add_member(id);
//    bci->store(true);
    return sys_id;
    
}

void BroadmaskAPI::remove_member(std::string gid, std::string id) {
    BES_sender *bci = get_sender_instance(gid);
    if (bci) {
        bci->remove_member(id);
        bci->store(true);
    }
}

string BroadmaskAPI::encrypt_b64(std::string gid, const std::vector<std::string>& receivers, std::string data, bool image) {
    BES_sender *bci = get_sender_instance(gid);
    
    if (!bci) {
        cout << "Sender instance " << gid << " not found" << endl;
        return "";
    }

    bes_ciphertext_t ct;
    bci->bes_encrypt(&ct, receivers, data);
    
    stringstream ctos;
    string ct_b64;
    bci->ciphertext_to_stream(ct, ctos);    
    // Encode to Base64
    ct_b64 = base64_encode(ctos.str());
    
    if (image) {
        vector<unsigned char> b64data, b64padded;
        vector_from_string(b64data, ct_b64);
        b64padded = encodeImage(b64data);
        ofstream os;
        os.open("/Users/oliver/Desktop/encoded.bmp", ios::binary);
        ostreambuf_iterator<char> os_it(os);
        copy (b64padded.begin(), b64padded.end(), os_it);
        os.close();
        return base64_encode(b64padded);

    }
    return ct_b64;
}

string BroadmaskAPI::sk_encrypt_b64(std::string data, bool image) {
    unsigned char key[32];
    unsigned char iv[AES::BLOCKSIZE];
    
    AutoSeededRandomPool prng;
    
	prng.GenerateBlock(key, sizeof(key));
	prng.GenerateBlock(iv, sizeof(iv));
    
    try {
		CFB_Mode< AES >::Encryption enc;
		enc.SetKeyWithIV(key, sizeof(key), iv, AES::BLOCKSIZE);
        string cipher;
		StringSource(data, true, new StreamTransformationFilter(enc, new StringSink(cipher)));
        
        stringstream json;
        stringstream b64os;
        json << "{";
        json << "\"iv\": \"";
        for (int i = 0; i < AES::BLOCKSIZE; ++i) {
            b64os << iv[i];
        }
        json << base64_encode(b64os.str());
        b64os.clear();
        b64os.str(std::string());
        json << "\",\"key\": \"";
        for (int i = 0; i < 32; ++i) {
            b64os << key[i];
        }
        json << base64_encode(b64os.str());
        json << "\", \"ct\": \"";
        json << base64_encode(cipher);
        json << "\"}";
        
        
        return json.str();

	} catch(const CryptoPP::Exception& e) {
		cerr << e.what() << endl;
        return "{}";
	}
}
 
string BroadmaskAPI::decrypt_b64(string gid, string ct_data, bool image) {
    BES_receiver *bci = get_receiver_instance(gid);
    
    if (!bci) {
        cout << "Sender instance " << gid << " not found" << endl;
        return "";
    }
    
    string ct_str = ct_data;
    if (image) {
        vector<unsigned char> b64padded,b64data;
        vector_from_string(b64padded, ct_data);
        b64data = decodeImage(b64data);
        ct_str = string(b64data.begin(), b64data.end());
        
    }
    ct_str = base64_decode(ct_str);
    stringstream ctss(ct_str);
            
    bes_ciphertext_t ct;
    bci->ciphertext_from_stream(&ct, ctss);
    
    return bci->bes_decrypt(ct);
}

/*
 * GPG API
 */

void BroadmaskAPI::gpg_store_keyid(std::string user_id, std::string key_id) {
    gpg->setPGPKey(user_id, key_id);
    // store wrapper again
    fs::path gpgfile = broadmask_root() / "pgpstorage";
    
    std::ofstream ofs(gpgfile.string().c_str(), std::ios::out);
    boost::archive::text_oarchive oa(ofs);
    
    try {
        oa << *gpg;
    } catch (exception& e) {
        cout << e.what() << endl;
    }
}

FB::VariantMap BroadmaskAPI::gpg_get_keyid(std::string user_id) {
    return gpg->getPGPKey(user_id);
}

FB::VariantMap BroadmaskAPI::gpg_encrypt_for(std::string data, std::string user_id) {
    return gpg->encrypt_for(data, user_id);
}

FB::VariantMap BroadmaskAPI::gpg_encrypt_with(std::string data, std::string key_id) {
    return gpg->encrypt_with(data, key_id);
}

FB::VariantMap BroadmaskAPI::gpg_decrypt(std::string data) {
    return gpg->decrypt(data);
}

FB::VariantMap BroadmaskAPI::gpg_associatedKeys() {
    return gpg->associatedKeys();
}

FB::VariantMap BroadmaskAPI::gpg_import_key(string data, bool iskeyblock) {
    if (iskeyblock)
        return gpg->import_key_block(data);
    else
        return gpg->search_key(data);
}

FB::VariantMap BroadmaskAPI::get_member_sk_gpg(string gid, string sysid) {
    string user_sk = get_member_sk(gid, sysid);
    
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
    registerMethod("start_sender_instance", make_method(this, &BroadmaskAPI::start_sender_instance));
    registerMethod("add_member", make_method(this, &BroadmaskAPI::add_member));
    registerMethod("remove_member", make_method(this, &BroadmaskAPI::remove_member));        
    registerMethod("get_member_sk", make_method(this, &BroadmaskAPI::get_member_sk));        
    registerMethod("get_member_sk_gpg", make_method(this, &BroadmaskAPI::get_member_sk_gpg));
    registerMethod("start_receiver_instance", make_method(this, &BroadmaskAPI::start_receiver_instance));
    registerMethod("encrypt_b64", make_method(this, &BroadmaskAPI::encrypt_b64));
    registerMethod("decrypt_b64", make_method(this, &BroadmaskAPI::decrypt_b64));
    registerMethod("test", make_method(this, &BroadmaskAPI::test));
    registerMethod("sk_encrypt_b64", make_method(this, &BroadmaskAPI::sk_encrypt_b64));
    registerMethod("gpg_store_keyid", make_method(this, &BroadmaskAPI::gpg_store_keyid));
    registerMethod("gpg_get_keyid", make_method(this, &BroadmaskAPI::gpg_get_keyid));
    registerMethod("gpg_encrypt_for", make_method(this, &BroadmaskAPI::gpg_encrypt_for));
    registerMethod("gpg_encrypt_with", make_method(this, &BroadmaskAPI::gpg_encrypt_with));
    registerMethod("gpg_decrypt", make_method(this, &BroadmaskAPI::gpg_decrypt));
    registerMethod("gpg_associatedKeys", make_method(this, &BroadmaskAPI::gpg_associatedKeys));
    registerMethod("gpg_import_key", make_method(this, &BroadmaskAPI::gpg_import_key));
    
    // Restart PGP Wrapper
    gpg = new PGPStorageWrapper();
    fs::path gpgfile = broadmask_root() / "pgpstorage";
    if (fs::is_regular_file(gpgfile)) {
        std::ifstream ifs(gpgfile.string().c_str(), std::ios::in);
        boost::archive::text_iarchive ia(ifs);
        
        try {
            ia >> *gpg;
        } catch (exception& e) {
            cout << e.what() << endl;
        }
    }
    
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
    start_sender_instance("foo", 256);

    BES_sender *sender = get_sender_instance("foo");       
    if (!sender)
        cout << "Sender instance foo should have been started, but wasn't" << endl;
    
    int add1 = add_member("foo", "1");
    int add2 = add_member("foo", "1");
    
    if (add1 != add2) {
        cout << "Inserted IDs were " << add1 << " and " << add2 << " , which are not equal" << endl;
    }
    
    
    remove_member("foo", "1");
    int add3 = add_member("foo", "23");
    if (add1 == add3)
        cout << "New ID should not be old value " << add1 << endl;
    
    if (sender->member_id("23") != 1)
        cout << "Member id should have been 1" << endl;
    
     if (sender->member_id("1") != -1)
         cout << "Member '1' was not removed" << endl;
    
    boost::timer total;
    string foo_pub_params = start_sender_instance("test", 256);
    cout << "Setup phase: " << total.elapsed() << endl;

    vector<string> s;
    for (int i = 0; i < 256; ++i) {
        string user = boost::lexical_cast<string>(i);
        add_member("test", user);
        s.push_back(user);
        
        string privkey = get_member_sk("test", user);
        start_receiver_instance(user, 256, foo_pub_params, privkey);       
    }
    
    
    int size = 100000;
    char *random = new char[size];
    string rec_message_j;
    string ct_data;
    for (int i = 2; i <= 256; i*=2) {
        vector<string> recipients;
        for (int j = 0; j < i; ++j) {
            recipients.push_back(s[j]);
        }
        cout << "System Test with " << i << "/256 recipients" << endl;
        boost::timer round, step;
        
        gen_random(random, size-1);
        string message(random);
        step.restart();
        ct_data = encrypt_b64("test", recipients, message, false);
        
        cout << "(ENC): " << i << " " << step.elapsed() << endl;
        step.restart();
        
        cout << "(DEC): " << i << " ";
        for (int j = 0; j < i; ++j) {
            rec_message_j = decrypt_b64(s[j], ct_data, false);        
            if (message.compare(rec_message_j) != 0)
                cout << "Decrypting using Receiver " << s[j] << " incorrect: " << endl;
            
//            cout << "Decrypt [receiver " << s[j] << "]: " << step.elapsed() << endl;
            cout << step.elapsed() << " ";
            step.restart();
        }
        
        for (int j = i; j < 256; ++j) {
            step.restart();
            rec_message_j = decrypt_b64(s[j], ct_data, false);    
            cout << step.elapsed() << " ";
            if (message.compare(rec_message_j) == 0) {
                cout << "Decrypting using Receiver " << s[j] << " should have been unsuccessful!: " << endl;
            }
        }
        cout << endl;
        
        cout << "Round " << i << ": " << round.elapsed() << endl;
        round.restart();
    }
    delete[] random;
                          
    
    cout << "Total time elapsed: " << total.elapsed() << endl;
    
    
    storeInstance(sender);
    sending_groups.erase("test");
    
    sender = get_sender_instance("test");
    if (sender != NULL)
        cout << "sender instance not deleted" << endl;
    
    
    callback->InvokeAsync("", FB::variant_list_of("it worked"));

}
