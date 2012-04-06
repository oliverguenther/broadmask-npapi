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



#include "JSObject.h"
#include "variant_list.h"
#include "DOM/Document.h"
#include "global/config.h"
#include "BroadmaskAPI.h"
#include "BitmapWrapper.h"

#include "utils.h"

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
    ostringstream params;

    
    if (it != sending_groups.end()) {
        cout << "Sending Instance " << gid << " is already loaded" << endl;
        it->second.public_params_to_stream(params);
        return params.str();
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
    return params.str();
    
}

void BroadmaskAPI::start_receiver_instance(string gid, int N, string public_data, string private_key) {
    map<string,BES_receiver>::iterator it = receiving_groups.find(gid);
    fs::path bcfile = get_instance_file(gid, "bes_receiver");
    
    if (it != receiving_groups.end()) {
        cout << "Receiving Instance " << gid << " is already loaded" << endl;
    } else if (fs::is_regular_file(bcfile)) {
        load_instance(bcfile);
    } else {        
        BES_receiver *instance = new BES_receiver(gid, N, public_data, private_key);
        receiving_groups.insert(pair<string, BES_receiver> (gid,*instance));
        
//        // Store BES system
//        instance->store(true);
//        
//        // Store Instance 
//        string classpath(bcfile.string());
//        classpath += "_serialized";
//        
//        std::ofstream ofs(classpath.c_str());
//        boost::archive::text_oarchive oa(ofs);
//        oa << *(instance);  
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
    
    bes_privkey_t sk;
    bci->get_private_key(&sk, id);
    if (!sk) {
        return "";
    }
    
    ostringstream oss;
    bci->private_key_to_stream(sk, oss);
    
    element_clear(sk->privkey);
    
    return oss.str();
    
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

string BroadmaskAPI::encrypt_b64(std::string gid, std::vector<std::string> receivers, std::string data, bool image) {
    BES_sender *bci = get_sender_instance(gid);
    
    if (!bci) {
        cout << "Sender instance " << gid << " not found" << endl;
        return "";
    }

    bes_ciphertext_t ct;
    bci->bes_encrypt(&ct, receivers, data);
    
    // Encode to Base64
    stringstream ctos, b64os;
    bci->ciphertext_to_stream(ct, ctos);    
    b64.Encode(ctos, b64os);
    
    if (image) {
        vector<unsigned char> b64data, b64padded;
        vector_from_stream(b64data, b64os);
        b64padded = encodeImage(b64data);
    }        
    return b64os.str();
}
 
string BroadmaskAPI::decrypt_b64(string gid, string ct_data, bool image) {
    BES_receiver *bci = get_receiver_instance(gid);
    
    if (!bci) {
        cout << "Sender instance " << gid << " not found" << endl;
        return "";
    }
    
    if (image) {
        stringstream b64is(ct_data);
        vector<unsigned char> b64padded,b64data;
        vector_from_stream(b64padded, b64is);
        b64data = decodeImage(b64data);
        ct_data = string(b64data.begin(), b64data.end());
        
    }
    istringstream b64is(ct_data);

    
    // Decode from Base64
    stringstream ctss;    
    b64.Decode(b64is, ctss);
        
    bes_ciphertext_t ct;
    bci->ciphertext_from_stream(&ct, ctss);
    
    return bci->bes_decrypt(ct);
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

std::string BroadmaskAPI::testsuite() {
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
    
    
    int size = 1000000;
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
    
    
    return "";
    
}
