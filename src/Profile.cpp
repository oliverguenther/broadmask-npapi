/*
 * Profile Entry
 * 
 * Broadmask is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * Broadmask is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with Broadmask.  If not, see <http://www.gnu.org/licenses/>.
 * 
 * Oliver Guenther
 * mail@oliverguenther.de
 *
 * 
 * Profile.cpp
 */

#include "Profile.hpp"
#include "Base64.h"
#include <fstream>

#ifndef NO_PLUGIN
#include <DOM/Window.h>
namespace fs = boost::filesystem;
#endif

Profile::Profile(std::string profile_name, std::string key_id) {
    name = profile_name;
    pgp_keyid = key_id;
}

Profile::~Profile() {
    instances.clear();
    loaded_instances.clear();
}

#ifndef NO_PLUGIN
FB::VariantMap Profile::get_stored_instances() {
    FB::VariantMap keys;
    for (boost::ptr_map<std::string,InstanceStore>::iterator it = instances.begin(); it != instances.end(); ++it) {
        FB::VariantMap instmap;
        InstanceStore *inst = it->second;
        instmap["id"] = inst->id;
        instmap["name"] = inst->name;
        instmap["type"] = inst->type;
        
        if (inst->type == BROADMASK_INSTANCE_BES_SENDER 
            || inst->type == BROADMASK_INSTANCE_BES_RECEIVER)
            instmap["max_users"] = inst->max_users;        
        keys[it->first] = instmap;
    }
    
    return keys;
}
#endif


std::string Profile::start_sender_instance(string id, string name, int N) {
    
    BES_sender* instance = dynamic_cast<BES_sender*>(load_instance(id));
    stringstream params;
    
    
    // check for cached instance
    if (!instance) {
        
        // create and store instance
        instance = new BES_sender(id, N);
        
        // Record this instance with a new storage
        InstanceStore *store = new InstanceStore(name, instance);
        
        // Insert the record to known instances
        instances.insert(id, store);
        
        // Keep the instances loaded
        loaded_instances.insert(id,instance);
    }
    
    instance->public_params_to_stream(params);
    
    return base64_encode(params.str());
    
}

void Profile::add_receiver_instance(BES_receiver *instance) {
    
    std::string id = instance->id();
    
    // Record this instance with a new storage
    InstanceStore *store = new InstanceStore(id, instance);
    
    // Insert the record to known instances
    instances.insert(id, store);
    
    // Keep the instances loaded
    loaded_instances.insert(id,instance);
}

void Profile::start_receiver_instance(string id, string name, int N, string pubdata_b64, string private_key_b64) {
    
    instance_types stored_type = instance_type(id);
    
    // Return if instance is already loaded as a sender, or as a receiver
    if (stored_type == BROADMASK_INSTANCE_BES_SENDER || stored_type == BROADMASK_INSTANCE_BES_RECEIVER)
        return;
    
    // decode params
    string public_params = base64_decode(pubdata_b64);
    string private_key = base64_decode(private_key_b64);
    
    // Create and store instance
    BES_receiver *instance = new BES_receiver(id, N, public_params, private_key);  
    add_receiver_instance(instance);
}

void Profile::start_shared_instance(std::string id, std::string name) {
    SK_Instance* instance = dynamic_cast<SK_Instance*>(load_instance(id));
    
    if (instance) {
        return;
    }
    
    // Create shared instance, initializes new shared key
    instance = new SK_Instance(id);
    
    // Record this instance with a new storage
    InstanceStore *store = new InstanceStore(name, instance);
    
    // Insert the record to known instances
    instances.insert(id, store);
    
    // Keep the instances loaded
    loaded_instances.insert(id,instance);
    
}

void Profile::start_shared_instance_withkey(std::string id, std::string name, std::string key_b64) {
    SK_Instance* instance = dynamic_cast<SK_Instance*>(load_instance(id));
    
    if (instance) {
        // remove instance
        remove_instance(id);
    }
    
    instance = new SK_Instance(id, key_b64);
    
    // Record this instance with a new storage
    InstanceStore *store = new InstanceStore(name, instance);
    
    // Insert the record to known instances
    instances.insert(id, store);
    
    // Keep the instances loaded
    loaded_instances.insert(id,instance);
    
}


#ifndef NO_PLUGIN
FB::VariantMap Profile::instance_description(std::string id) {
    InstanceStore* inst = instance_struct(id);
    FB::VariantMap result;
    if (inst) {
        result["id"] = inst->id;
        result["name"] = inst->name;
        result["type"] = inst->type;
        result["max_users"] = inst->max_users;
    } else {
        result["error"] = true;
        result["error_msg"] = "Instance not found";
    }
    return result;
}
#endif

InstanceStore* Profile::instance_struct(std::string id) {
    boost::ptr_map<string, InstanceStore>::iterator it = instances.find(id);
    
    if (it != instances.end())
        return it->second;
    else 
        return NULL;
}

instance_types Profile::instance_type(std::string id) {
    InstanceStore* s = instance_struct(id);
    
    if(s)
        return s->type;
    else
        return ERR_NO_INSTANCE;
    
}

void Profile::update_stores() {
    // Update state for all loaded instances
    for (boost::ptr_map<std::string,InstanceStore>::iterator it = instances.begin(); it != instances.end(); ++it) {
        
        // If this instance is loaded
        boost::ptr_map<std::string,Instance>::iterator lit = loaded_instances.find(it->first);
        if (lit != loaded_instances.end()) {
            
            Instance *instance = lit->second;
            InstanceStore *istore = it->second;
            istore->store(instance);
        }
        
    }
}


void Profile::unload_instances() {
    loaded_instances.clear();
}


#ifndef NO_PLUGIN
////////////////////////////////////////////////////////////////////////////////////////////
// UserStorage
FB::VariantMap Profile::associatedKeys() {
    FB::VariantMap keys;
    for (map<string,string>::iterator it = keymap.begin(); it != keymap.end(); ++it) {
        keys[it->first] = it->second;
    }
    
    return keys;
}



void Profile::setPGPKey(string& user_id, string& keyid) {
    keymap.insert(pair<string,string>(user_id, keyid));
}

FB::VariantMap Profile::getPGPKey(string& user_id) {
    FB::VariantMap result;
    result["userid"] = user_id;
    
    map<string,string>::iterator it = keymap.find(user_id);
    
    if (it != keymap.end()) {
        result["keyid"] = it->second;
        result["found"] = true;
    } else {
        result["found"] = false;
    }
    
    return result;    
}

FB::VariantMap Profile::encrypt_for(std::string& data, std::string& user_id) {
    std::map<std::string, std::string>::iterator it = keymap.find(user_id);
    
    if (it != keymap.end()) {
        return gpgme_encrypt_with(data, it->second, pgp_keyid);
    } else {
        FB::VariantMap output;
        output["error"] = true;
        output["key_missing"] = true;
        output["error_msg"] = "User has no corresponding key";
        return output;
    }
    
}

void Profile::removePGPKey(string& user_id) {
    keymap.erase(user_id);
}
#endif


profile_ptr Profile::load(std::istream& is) {
    profile_ptr p = profile_ptr();
    if (is.bad()) {
        cerr << "[BroadMask] Error Loading Profile: Bad input stream" << endl;
        return p;
    }
    
    try {
        Profile* istore;
        boost::archive::text_iarchive ia(is);
        ia >> istore;
        p.reset(istore);
        return p;
    } catch (exception& e) {
        cerr << "[BroadMask] Error Loading Profile:" << e.what() << endl;
        return p;
    }
}


void Profile::store(profile_ptr p, ostream& os) { 
    
    // get profile ptr
    Profile *istore = p.get();
    
    if (!p) {
        cerr << "Can't store empty profile pointer" << endl;
        return;
    }
    
    
    // update stores
    istore->update_stores();
    
    // clear loaded instances
    istore->unload_instances();
    
    try {
        boost::archive::text_oarchive oa(os);
        oa << istore;
        
    } catch (exception& e) {
        cerr << e.what() << endl;
    }
}