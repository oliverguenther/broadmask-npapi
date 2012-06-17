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
 * Profile.hpp
 */

#ifndef H_PROFILE
#define H_PROFILE

#include <iostream>
#include <map>

#include "UserStorage.hpp"
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


/**
 * @struct instance_s
 * @brief Descriptor for a serialized instance
 */
struct InstanceStore {
    
    // Default constructor for serialization
    InstanceStore() {}
    InstanceStore(std::string name, Instance *instance)
    : name(name) {
        id = instance->id();
        type = instance->type();
        max_users = instance->max_users();
        
        switch (type) {
            case BROADMASK_INSTANCE_BES_SENDER:
                store<BES_sender>(instance);
                break;
            case BROADMASK_INSTANCE_BES_RECEIVER:
                store<BES_receiver>(instance);
                break;
            case BROADMASK_INSTANCE_SK:
                store<SK_Instance>(instance);
                break;
            default:
                break;
        }
    }
    
    // Instance identifier
    std::string id;
    
    // Instance name -- private
    std::string name;
    
    // Instance type
    instance_types type;
    
    // stores serialized instance data
    std::string serialized_data;
    
    // Instance max. number of users
    int max_users;
    
    template<typename InstanceType>
    void store(Instance *instance) {
        
        // Only derived classes of Instance
        (void)static_cast<Instance*>((InstanceType*)0);
        
        // Let instance store internal data
        instance->store();
        
        // Update data 
        std::ostringstream oss;
        boost::archive::text_oarchive oa(oss);
        
        oa << *((InstanceType*) instance);
        
        serialized_data = oss.str();
        oss.clear();
    }
    
    template<typename InstanceType>
    InstanceType* restore() {
        
        // Only derived classes of Instance
        (void)static_cast<Instance*>((InstanceType*)0);
        
        InstanceType *instance = new InstanceType;
        
        // Restore from serialized data
        std::istringstream iss (serialized_data);
        boost::archive::text_iarchive ia(iss);
        
        ia >> *((InstanceType*) instance);
        iss.clear();
        
        // Restore internal data
        instance->restore();
        
        return dynamic_cast<InstanceType*>(instance);
    }
        
    template<class Archive>
    void serialize(Archive &ar, const unsigned int file_version) {
        
        ar & id;
        ar & name;
        ar & type;
        ar & serialized_data;
        ar & max_users;
        
    }
};


class Profile  {
    
public: 
    // Used for Boost serialization
    Profile() {}
    Profile(std::string name);
    
    ~Profile();
    
    /**
     * @fn Profile::get_stored_instances
     * @brief Get all stored instances
     * return FB::VariantMap instance, JS object containing instances
     * [id, name, type, max_users]
     */
    FB::VariantMap get_stored_instances();
    
    /**
     * @fn Profile::remove_instance
     * @brief Delete an instance from the profile
     * @param id std::string Identifier of the instance to be deleted
     */
    void remove_instance(string id) {
        loaded_instances.erase(id);
        instances.erase(id);
    }
    
    /**
     * @fn Profile::load_instance
     * @brief Try to load a specific instance derived object, given it's type
     * @param id std::string Identifier of the instance to be loaded
     * @return A pointer to the object of type InstanceType* or NULL, if either 
     * the instance does not exist, or the type does not match
     */
    template<typename InstanceType>
    InstanceType* load_instance(std::string id) {
        
        // Check if instance has been cached
        boost::ptr_map<std::string, Instance>::iterator it;
        it = loaded_instances.find(id);
        
        if (it != loaded_instances.end())
            return dynamic_cast<InstanceType*>(it->second);
        
        // Check storage for active record
        InstanceStore* store = instance_struct(id);
        
        if (!store)
            return NULL;
        
        return store->restore<InstanceType>();
    }
    
    /**
     * @fn Profile::load_unknown
     * @brief Try to load a instance, regardless its type
     * @param id std::string Identifier of the instance to be loaded
     * @return A pointer to the base type of the instance, or NULL if non-existent
     */
    Instance* load_unknown(std::string id);
    
    /**
     * @fn Profile::instance_description
     * @brief Retrieve an instance descriptor
     * @param identifier of instance
     * @return JS object with [id, name, type, path, max_users] keys
     */
    FB::VariantMap instance_description(std::string id);
       
    /**
     * @fn Profile::instance_type
     * @brief Return the instance type value
     * @param identifier of instance
     * @return an instance_types value, matching the instance found
     */
    instance_types instance_type(std::string id);
    
    
    /**
     * @fn Profile::start_sender_instance
     * @brief Create a new BES sender instance within this profile
     * @param id identifier
     * @param name private name
     * @param N maximum group size
     * @return the BES public key as Base64 encoded string
     */
    std::string start_sender_instance(std::string id, std::string name, int N);
    
    /**
     * @fn Profile::start_receiver_instance
     * @brief Create a new BES receiver instance within this profile
     * @param id identifier
     * @param name private name
     * @param N maximum group size
     * @param pubdata_b64 the BES public key as Base64 encoded string
     * @param private_key_b64 this recipient's private key as Base64 encoded string
     */
    void start_receiver_instance(std::string id, std::string name, int N, std::string pubdata_b64, std::string private_key_b64);
    
    
    /**
     * @fn Profile::start_shared_instance
     * @brief Create a new SK instance within this profile
     * @param id identifier
     * @param name private name
     */
    void start_shared_instance(std::string id, std::string name);
    
    /**
     * @fn Profile::start_shared_instance_withkey
     * @brief Create a SK instance within this profile, given a shared key 
     * as Base64-encoded string
     * @param id identifier
     * @param name private name
     * @param key_b64 the shared key sk as Base64-encoded string
     */
    void start_shared_instance_withkey(std::string id, std::string name, std::string key_b64);

    
    /**
     * @fn Profile::load
     * @brief Restore Profile from ASCII using Boost serialization
     * @param is input stream containing a previously stored Profile from
     * Profile::store
     * @return Pointer to the loaded Profile* or NULL if load failed
     */
    static Profile* load(istream& is);
    
    /**
     * @fn Profile::store
     * @brief Serialize Profile to ASCII using Boost serialization
     * @param os output stream to write to
     */
    static void store(Profile* istore, ostream& os);
    
    
    /**
     * @fn Profile::get_ustore
     * @brief Returns a pointer to the PGP UserStorage
     */
    UserStorage* get_ustore() {
        return ustore;
    }
    
    /**
     * @fn Profile::get_ustore
     * @brief Returns this profile's name
     */
    std::string profilename() {
        return name;
    }
    
    
private:
    
    // Profile name
    std::string name;
    
    // Storage for known instances
    boost::ptr_map<std::string, InstanceStore> instances;
    
    // Cache for loaded instances
    boost::ptr_map<std::string, Instance> loaded_instances;
    
    // User-Key mapping storage
    UserStorage* ustore;
    
    /**
     * @fn Profile::instance_struct
     * @brief Retrieve serialized struct about instance
     * @param id instance identifier
     * @return InstanceStore* to the stored instance or NULL
     */
    InstanceStore* instance_struct(std::string id);

    //
    // Boost class serialization, independent from BES serialization
    //
    friend class boost::serialization::access;
    template<class Archive>
    void serialize(Archive & ar, const unsigned int version)
    {
        ar & name;
        ar & instances;
        ar & ustore;
    }
};

#endif