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

void InstanceStorage::store_instance(FB::JSObjectPtr params) {
    
    string id = params->GetProperty("id").convert_cast<std::string>();
    string name = params->GetProperty("name").convert_cast<std::string>();
    int type = params->GetProperty("type").convert_cast<int>();
    int max_users = params->GetProperty("max_users").convert_cast<int>();
    
    InstanceDescriptor* instance = new InstanceDescriptor(id, name, type, max_users);
    instances.insert(id, instance);
}

template<typename InstanceType>
InstanceType* InstanceStorage::load_instance(std::string id) {
    boost::ptr_map<string, BES_base>::iterator it = loaded_instances.find(id);
    
    // test if instance is loaded already
    if (it != loaded_instances.end())
        return dynamic_cast<InstanceType*>(it->second);
    
    // else load instance, if existant
    InstanceDescriptor* s = instance_struct(id);
    
    if (s && fs::is_regular_file(s->path)) {
        string serialized_class = s->path + "_serialized";
        std::ifstream ifs(serialized_class.c_str(), std::ios::in);
        boost::archive::text_iarchive ia(ifs);
        
        BES_base *instance;
        
        switch (s->type) {
            case BROADMASK_INSTANCE_SENDER:                
                // Restore instance class itself
                instance = new BES_sender;
                ia >> *((BES_sender*)instance);
                
                // Restore BES structs
                instance->restore();
                
                // Cache instance
                loaded_instances.insert(s->id, instance);
                
                return dynamic_cast<InstanceType*>(instance);
                break;
            case BROADMASK_INSTANCE_RECEIVER:
                // Restore instance class itself
                ia >> *((BES_receiver*)instance);
                
                // Restore BES structs
                instance->restore();
                
                // Cache instance
                loaded_instances.insert(s->id, instance);
                return dynamic_cast<InstanceType*>(instance);
                break;
            default: 
                cerr << "Unknown InstanceDescriptor type" << s << endl;
                return NULL;
                break;
        }
    } else {
        return NULL;
    }
    
}

FB::VariantMap InstanceStorage::start_sender_instance(string id, string name, int N) {
    
    BES_sender* instance = load_instance<BES_sender>(id);
    stringstream params;
    FB::VariantMap result;
    
    
    // check for cached instance
    if (instance) {
        cout << "Sending Instance " << id << " is already loaded" << endl;
        instance->public_params_to_stream(params);
        result["parameters"] = base64_encode(params.str());
        result["is_cached"] = true;
        return result;
    }
    
    // start new instance
    InstanceDescriptor *desc = new InstanceDescriptor(id, name, BROADMASK_INSTANCE_SENDER, N);
    instance = new BES_sender(id, N);
    loaded_instances.insert(id, instance);
        
    // Store BES system
    instance->store(true);
    
    // Store Instance 
    string classpath(desc->path);
    classpath += "_serialized";
    
    std::ofstream ofs(classpath.c_str());
    boost::archive::text_oarchive oa(ofs);
    oa << *(instance);
    
    instance->public_params_to_stream(params);

    result["parameters"] = base64_encode(params.str());
    result["is_cached"] = false;
    return result;
    
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
    return &(instances.at(id));    
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
    if (fs::is_regular_file(storage)) {
        std::ofstream ofs(storage.string().c_str(), std::ios::out);
        boost::archive::text_oarchive oa(ofs);
        
        try {
            oa << *is;
        } catch (exception& e) {
            cout << e.what() << endl;
        }    
    }
}

InstanceStorage* InstanceStorage::unarchive() {
    fs::path storage = broadmask_root() / "instancestorage";
    if (fs::is_regular_file(storage)) {
        std::ifstream ifs(storage.string().c_str(), std::ios::in);
        boost::archive::text_iarchive ia(ifs);
        
        try {
            InstanceStorage *is = new InstanceStorage();
            ia >> *is;
            return is;
        } catch (exception& e) {
            cout << e.what() << endl;
            return NULL;
        }
    } else {
        return NULL;
    }
}