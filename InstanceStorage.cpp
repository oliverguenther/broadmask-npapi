/*
 * Instance Storage Wrapper
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
 * InstanceStorage.cpp
 */

#include "InstanceStorage.hpp"
#include "Base64.h"


#include <fstream>
#include <DOM/Window.h>


using namespace std;
namespace fs = boost::filesystem;




InstanceStorage::~InstanceStorage() {
    instances.clear();
    loaded_instances.clear();
}

FB::VariantMap InstanceStorage::get_stored_instances() {
    FB::VariantMap keys;
    for (boost::ptr_map<string,string>::iterator it = instances.begin(); it != instances.end(); ++it) {
        FB::VariantMap instmap;
        InstanceDescriptor *inst = instance_struct(it->first);
        instmap["id"] = inst->id;
        instmap["name"] = inst->name;
        instmap["type"] = inst->type;
        instmap["path"] = inst->path;
        instmap["max_users"] = inst->max_users;        
        keys[it->first] = instmap;
    }
    
    return keys;
}


void InstanceStorage::store_instance(FB::JSObjectPtr params) {
    
    string id = params->GetProperty("id").convert_cast<std::string>();
    string name = params->GetProperty("name").convert_cast<std::string>();
    int type = params->GetProperty("type").convert_cast<int>();
    int max_users = params->GetProperty("max_users").convert_cast<int>();
    
    InstanceDescriptor* instance = new InstanceDescriptor(id, name, type, max_users);
    instances.insert(id, instance);
    InstanceStorage::archive(this);
}

void InstanceStorage::remove_instance(string id) {
    
    // Remove loaded instance
    loaded_instances.erase(id);
    
    InstanceDescriptor *s = instance_struct(id);
    
    if (s) {
        
        string instance_path = s->path;
        fs::path instance_file = fs::path(instance_path);
        fs::path serialized_file = fs::path(instance_path + "_serialized");
        fs::remove(instance_file);
        fs::remove(serialized_file);
        
        // Remove instance descriptor
        instances.erase(id);
        
        InstanceStorage::archive(this);
    }
    
}

template<typename InstanceType>
InstanceType* InstanceStorage::load_instance(std::string id) {
    boost::ptr_map<string, Instance>::iterator it = loaded_instances.find(id);
    
    // test if instance is loaded already
    if (it != loaded_instances.end())
        return dynamic_cast<InstanceType*>(it->second);
    
    // else load instance, if existant
    InstanceDescriptor* s = instance_struct(id);
    
    Instance *instance = NULL;
    if (s && fs::is_regular_file(s->path)) {
        string serialized_class = s->path + "_serialized";
        std::ifstream ifs(serialized_class.c_str(), std::ios::in);
        boost::archive::text_iarchive ia(ifs);
        

        switch (s->type) {
            case BROADMASK_INSTANCE_BES_SENDER:                
                // Restore instance class itself
                instance = new BES_sender;
                ia >> *((BES_sender*)instance);
                
                // Restore BES structs
                instance->restore();
                
                // Cache instance
                loaded_instances.insert(s->id, instance);
                
                break;
            case BROADMASK_INSTANCE_BES_RECEIVER:
                // Restore instance class itself
                ia >> *((BES_receiver*)instance);
                
                // Restore BES structs
                instance->restore();
                
                // Cache instance
                loaded_instances.insert(s->id, instance);
                break;
            default: 
                cerr << "Unknown InstanceDescriptor type" << s << endl;
                break;
        }
    }
    return dynamic_cast<InstanceType*>(instance);
}

template<typename InstanceType>
void InstanceStorage::storeInstance(InstanceType *instance) {
    
    // Only derived classes of Instance
    (void)static_cast<Instance*>((InstanceType*)0);
    
    // Store BES system
    instance->store();
    
    // Store Instance 
    string classpath = instance->instance_file();
    classpath += "_serialized";
    
    std::ofstream ofs(classpath.c_str());
    boost::archive::text_oarchive oa(ofs);
    oa << *(instance);
    
}

string InstanceStorage::start_sender_instance(string id, string name, int N) {
    
    BES_sender* instance = load_instance<BES_sender>(id);
    stringstream params;
    
    
    // check for cached instance
    if (instance) {
        cout << "Sending Instance " << id << " is already loaded" << endl;
        instance->public_params_to_stream(params);
        return base64_encode(params.str());
    }
    
    // record instance
    InstanceDescriptor *desc = new InstanceDescriptor(id, name, BROADMASK_INSTANCE_BES_SENDER, N);
    instances.insert(id, desc);
    
    // create and store instance
    instance = new BES_sender(id, N);
    loaded_instances.insert(id, instance);        
    storeInstance<BES_sender>(instance);
    InstanceStorage::archive(this);

    instance->public_params_to_stream(params);

    return base64_encode(params.str());
    
}

void InstanceStorage::start_receiver_instance(string id, string name, int N, string pubdata_b64, string private_key_b64) {
    BES_receiver* instance = load_instance<BES_receiver>(id);
    
    // check for cached instance
    if (instance) {
        cout << "Receiving Instance " << id << " is already loaded" << endl;
        return;
    }
    
    // record instance
    InstanceDescriptor *desc = new InstanceDescriptor(id, name, BROADMASK_INSTANCE_BES_RECEIVER, N);
    instances.insert(id, desc);
    
    // decode params
    string public_params = base64_decode(pubdata_b64);
    string private_key = base64_decode(private_key_b64);
    
    // Create and store instance
    instance = new BES_receiver(id, N, public_params, private_key);    
    loaded_instances.insert(id, instance);    
    storeInstance<BES_receiver>(instance);
    InstanceStorage::archive(this);
    
}




FB::VariantMap InstanceStorage::instance_description(std::string id) {
    InstanceDescriptor* inst = instance_struct(id);
    FB::VariantMap result;
    if (inst) {
        result["id"] = inst->id;
        result["name"] = inst->name;
        result["type"] = inst->type;
        result["path"] = inst->path;
    } else {
        result["error"] = true;
        result["error_msg"] = "Instance not found";
    }
    return result;
}

InstanceDescriptor* InstanceStorage::instance_struct(std::string id) {
    boost::ptr_map<string, InstanceDescriptor>::iterator it = instances.find(id);
    
    if (it != instances.end())
        return it->second;
    else 
        return NULL;
}

int InstanceStorage::instance_type(std::string id) {
    InstanceDescriptor* s = instance_struct(id);
    
    if(s)
        return s->type;
    else
        return 0;

}


void InstanceStorage::archive(InstanceStorage *is) {
    fs::path storage = broadmask_root() / "instancestorage";
    std::ofstream ofs(storage.string().c_str(), std::ios::out);
    boost::archive::text_oarchive oa(ofs);
    
    try {
        oa << *is;
    } catch (exception& e) {
        cout << e.what() << endl;
    }    
}

InstanceStorage* InstanceStorage::unarchive() {
    fs::path storage = broadmask_root() / "instancestorage";
    InstanceStorage *is = new InstanceStorage();

    if (fs::is_regular_file(storage)) {
        std::ifstream ifs(storage.string().c_str(), std::ios::in);
        boost::archive::text_iarchive ia(ifs);
        
        try {
            ia >> *is;
            return is;
        } catch (exception& e) {
            cout << e.what() << endl;
        }
    }
    return is;
}