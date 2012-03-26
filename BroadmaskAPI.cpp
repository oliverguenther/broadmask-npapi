/**********************************************************\
 
 Auto-generated BroadmaskAPI.cpp
 
 \**********************************************************/

#include <iostream>
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

#include "utils.h"

using namespace std;
namespace fs = boost::filesystem;


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
        storeInstance(instance, "sender");
    }
    
    if (instance == NULL) {
        cout << "Instance " << gid << " couldn't be loaded" << endl;
        return "";
    }
    instance->public_params_to_stream(params);
    delete instance;
    
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
        
        storeInstance(instance, "receiver");
        delete instance;
    }
    
}

BES_base* BroadmaskAPI::load_instance(fs::path path) {
    if (!fs::is_regular_file(path)) {
        cout << "Couldn't load instance " << path.string() << endl;
        return NULL;
    }
    
    if (path.filename() == "receiver") {
        BES_receiver *instance = new BES_receiver;
        
        cout << "Loading receiver instance " << path.string() << endl;
        
        std::ifstream ifs(path.string().c_str());
        boost::archive::text_iarchive ia(ifs);
        ia >> *(instance);
        
        instance->restore();
        receiving_groups.insert(pair<string, BES_receiver> (instance->groupid(),*instance));
        
        return instance;
    } else if (path.filename() == "sender") {
        BES_sender *instance = new BES_sender;
        
        cout << "Loading sender instance " << path.string() << endl;
        
        std::ifstream ifs(path.string().c_str());
        boost::archive::text_iarchive ia(ifs);
        ia >> *(instance);
        
        instance->restore();
        sending_groups.insert(pair<string, BES_sender> (instance->groupid(),*instance));
        
        return instance;
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

void BroadmaskAPI::storeInstance(BES_base *bci, string type) {
        
    // Store BES system
    bci->store(true);
    
    // Store Instance 
    fs::path bcfile = get_instance_file(bci->groupid(), type);
    
    std::ofstream ofs(bcfile.string().c_str());
    boost::archive::text_oarchive oa(ofs);
    oa << *(bci);
    
}


string BroadmaskAPI::encrypt_b64(std::string gid, std::string receivers, std::string data, bool image) {
    map<string,BES_sender>::iterator it = sending_groups.find(gid);
    
    if (it == sending_groups.end()) {
        cout << "Sender instance " << gid << " not found" << endl;
        return "";
    }
    
    BES_sender bci = it->second;
    
    vector<int> v_receivers;
    stringstream ss(receivers);
    
    int num;
    while ( ss >> num)
        v_receivers.push_back(num);

    bes_ciphertext_t ct = bci.bes_encrypt(v_receivers, data);
    
    ostringstream ctos;
    bci.ciphertext_to_stream(ct, ctos);
    
    return ctos.str();
}

string BroadmaskAPI::decrypt_b64(string gid, string receivers, string ct_data, bool image) {
    map<string,BES_receiver>::iterator it = receiving_groups.find(gid);
    
    if (it == receiving_groups.end()) {
        cout << "Receiving instance " << gid << " not found" << endl;
        return "";
    }
    
    BES_receiver bci = it->second;
    
    vector<int> v_receivers;
    stringstream ss(receivers);
    
    int num;
    while ( ss >> num)
        v_receivers.push_back(num);
    
    
    // Decode from Base64
    istringstream b64is(ct_data);
    stringstream ctss;    
    b64.Decode(b64is, ctss);
    
    
    
    bes_ciphertext_t ct;
    bci.ciphertext_from_stream(&ct, ctss);
    
    return "";
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
