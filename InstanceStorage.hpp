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

// BES types
#include "BES_base.h"
#include "BES_receiver.h"
#include "BES_sender.h"

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

// JSAPI
#include "JSAPIAuto.h"
#include "APITypes.h"
#include "JSObject.h"
#include "variant_map.h"


/* The available types */
#define BROADMASK_INSTANCE_SENDER 1
#define BROADMASK_INSTANCE_RECEIVER 2

/**
 * @struct instance_s
 * @brief Descriptor for an instance file
 */
struct InstanceDescriptor {
    
    // Default constructor for serialization
    InstanceDescriptor() {}
    InstanceDescriptor(std::string id, std::string name, int type, int max_users) 
        : id(id), name(name), type(type), max_users(max_users) {
            
         string type_str = type == BROADMASK_INSTANCE_SENDER ? "sender" : "receiver";
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
     * @fn InstanceStorage::store_instance
     * @brief Store an instance descriptor and creates instance
     * @param FB::VariantMap instance, JS object containing keys
     * [id, name, type, path, max_users]
     */
    void store_instance(FB::JSObjectPtr instance);
    
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
    
    FB::VariantMap start_sender_instance(string id, string name, int N);
    
    static void archive(InstanceStorage *storage);
    static InstanceStorage* unarchive();
    
    
private:
    
    // Storage for known instances
    boost::ptr_map<std::string, InstanceDescriptor> instances;

    // Loaded instances
    boost::ptr_map<std::string, BES_base> loaded_instances;
    
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