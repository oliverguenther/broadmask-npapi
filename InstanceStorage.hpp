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
 * InstanceStorage.hpp
 */

#ifndef H_INSTANCE_STORAGE
#define H_INSTANCE_STORAGE

#include <iostream>
#include <map>

#include "utils.h"

// Instance types
#include "Instance.hpp"
#include "BES_receiver.hpp"
#include "BES_sender.hpp"
#include "SK_Instance.hpp"


// ptr
#include <boost/ptr_container/ptr_map.hpp>
#include <boost/ptr_container/serialize_ptr_map.hpp>

// filesystem
#include <boost/filesystem/operations.hpp>
#include <boost/filesystem/path.hpp>

// serialization
#include <boost/archive/text_oarchive.hpp>
#include <boost/archive/text_iarchive.hpp>
#include <boost/serialization/map.hpp>
#include <boost/serialization/vector.hpp>


// JSAPI
#include "JSAPIAuto.h"
#include "APITypes.h"
#include "JSObject.h"
#include "variant_map.h"


/* The available types */
#define BROADMASK_INSTANCE_BES_SENDER 1
#define BROADMASK_INSTANCE_BES_RECEIVER 2
#define BROADMASK_INSTANCE_SK 4

/**
 * @struct instance_s
 * @brief Descriptor for an instance file
 */
struct InstanceDescriptor {
    
    // Default constructor for serialization
    InstanceDescriptor() {}
    InstanceDescriptor(std::string id, std::string name, int type, int max_users) 
        : id(id), name(name), type(type), max_users(max_users) {
            
            string type_str = type == BROADMASK_INSTANCE_BES_SENDER ? "bes_sender" : 
            type == BROADMASK_INSTANCE_BES_RECEIVER ? "bes_receiver" : "sk";
         boost::filesystem::path instance_path = get_instance_path(type_str, id);
        path = instance_path.string();
    }
    
    // Instance identifier
    std::string id;
    
    // Instance name -- private
    std::string name;
    
    // Instance type
    int type;
    
    // relative path to stored instance file
    std::string path;
    
    // Instance max. number of users
    int max_users;
    
    template<class Archive>
    void serialize(Archive &ar, const unsigned int file_version) {
        
        ar & id;
        ar & name;
        ar & type;
        ar & path;
        ar & max_users;
        
    }
};


class InstanceStorage  {
    
public: 
    ~InstanceStorage();
    
    /**
     * @fn InstanceStorage::get_stored_instances
     * @brief Get all stored instances
     * return FB::VariantMap instance, JS object containing instances
     * [id, name, type, path, max_users]
     */
    FB::VariantMap get_stored_instances();
    
    /**
     * @fn InstanceStorage::store_instance_descriptor
     * @brief Store an instance descriptor and creates instance
     * @param FB::VariantMap instance, JS object containing keys
     * [id, name, type, path, max_users]
     */
    void store_instance_descriptor(FB::JSObjectPtr instance);
    
    void remove_instance(string id);
    
    /**
     * @fn InstanceStorage::instance_description
     * @brief Retrieve an instance descriptor
     * @param identifier of instance
     * @return JS object with [id, name, type, path, max_users] keys
     */
    FB::VariantMap instance_description(std::string id);
    
    /**
     * @fn InstanceStorage::instance_type
     * @brief Return the instance type value
     * @param identifier of instance
     * @return BROADMASK_INSTANCE_SENDER or BROADMASK_INSTANCE_RECEIVER
     */
    int instance_type(std::string id);
    
    /**
     * @fn InstanceStorage::load_instance
     * @brief Retrieve an instance
     * @param identifier of instance
     * @return Pointer to BES_{receiver,sender} instance or NULL if non-existant
     */
    template<typename InstanceType>
    InstanceType* load_instance(std::string id);
    
    Instance* load_unknown(std::string gid);
    void store_unknown(std::string gid, Instance *base_instance);
    
    template<typename InstanceType>
    void store_instance(InstanceType* instance);
    
    std::string start_sender_instance(std::string id, std::string name, int N);
    void start_receiver_instance(std::string id, std::string name, int N, std::string pubdata_b64, std::string private_key_b64);
    void start_shared_instance(std::string id, std::string name);
    void start_shared_instance_withkey(std::string id, std::string name, std::string key_b64);
    
    static void archive(InstanceStorage *storage);
    static InstanceStorage* unarchive();
    
    // New stream storage accessors
    static InstanceStorage* load(istream& is);
    static void store(InstanceStorage* istore, ostream& os);

 
    
private:
    
    // Storage for known instances
    boost::ptr_map<std::string, InstanceDescriptor> instances;

    // Loaded instances
    boost::ptr_map<std::string, Instance> loaded_instances;
    
    // get internal instance description
    InstanceDescriptor* instance_struct(std::string id);
    
    //
    // Boost class serialization, independent from BES serialization
    //
    friend class boost::serialization::access;
    template<class Archive>
    void serialize(Archive & ar, const unsigned int version)
    {
        ar & instances;
    }
};

#endif