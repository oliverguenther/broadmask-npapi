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
#include <DOM/Window.h>
namespace fs = boost::filesystem;

Profile::Profile(std::string profile_name) {
    name = profile_name;
    ustore = new UserStorage();
}

Profile::~Profile() {
    instances.clear();
    loaded_instances.clear();
    delete ustore;
}

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

Instance* Profile::load_unknown(std::string id) {
    // Check if instance has been cached
    boost::ptr_map<std::string, Instance>::iterator it;
    it = loaded_instances.find(id);
    
    if (it != loaded_instances.end())
        return it->second;
    // Check storage for active record
    InstanceStore* store = instance_struct(id);
    
    if (!store)
        return NULL;
    
    Instance *instance = NULL;
    switch (store->type) {
        case BROADMASK_INSTANCE_BES_SENDER:
            instance = store->restore<BES_sender>();
            break;
        case BROADMASK_INSTANCE_BES_RECEIVER:
            instance = store->restore<BES_receiver>();
            break;
        case BROADMASK_INSTANCE_SK:
            instance = store->restore<SK_Instance>();
            break;
        default:
            break;
    }
    
    return instance;
}


std::string Profile::start_sender_instance(string id, string name, int N) {
    
    BES_sender* instance = load_instance<BES_sender>(id);
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
    
    // Record this instance with a new storage
    InstanceStore *store = new InstanceStore(name, instance);
    
    // Insert the record to known instances
    instances.insert(id, store);
    
    // Keep the instances loaded
    loaded_instances.insert(id,instance);
    
}

void Profile::start_shared_instance(std::string id, std::string name) {
    SK_Instance* instance = load_instance<SK_Instance>(id);
    
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
    SK_Instance* instance = load_instance<SK_Instance>(id);
    
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


Profile* Profile::load(istream& is) {
    if (!is.good()) {
        cerr << "[BroadMask] Error Loading Profile: Faulty input stream" << endl;
        return NULL;
    }
    
    Profile *istore = new Profile();
    try {
        boost::archive::text_iarchive ia(is);
        ia >> *istore;
        return istore;
    } catch (exception& e) {
        cerr << "[BroadMask] Error Loading Profile:" << e.what() << endl;
        delete istore;
        return NULL;
    }
}


void Profile::store(Profile* istore, ostream& os) { 
    
    // Update state for all loaded instances
    for (boost::ptr_map<std::string,InstanceStore>::iterator it = instances.begin(); it != instances.end(); ++it) {
        
        // If this instance is loaded
        boost::ptr_map<std::string,InstanceStore>::iterator loaded = loaded_instances.find(it->first);
        if (loaded != loaded_instances.end()) {
            
            Instance *loaded = loaded->second;
        }
        
    }
            
    // clear loaded instances
    loaded_instances.clear();
    
    try {
        boost::archive::text_oarchive oa(os);
        oa << *istore;
    } catch (exception& e) {
        cerr << e.what() << endl;
    }    
}