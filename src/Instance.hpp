#ifndef H_INSTANCE
#define H_INSTANCE

/**
 * @file   Instance.hpp
 * @Author Oliver Guenther (mail@oliverguenther.de)
 * @date   September 2012
 * @brief  Abstract Instance for Instance Management
 *
 *
 */

// serialization
#include <boost/archive/text_oarchive.hpp>
#include <boost/archive/text_iarchive.hpp>
#include <boost/serialization/map.hpp>

/** 
 * @typedef instance_types
 * @brief The available instance types
 *
 * 
 */
typedef enum {
    ERR_NO_INSTANCE = 0,
    BROADMASK_INSTANCE_BES_SENDER = 1,
    BROADMASK_INSTANCE_BES_RECEIVER = 2,
    BROADMASK_INSTANCE_SK = 4 
} instance_types;

/**
 * @class Instance Instance.hpp
 * @brief Abstract Instance for Instance Management
 *
 *
 */
class Instance {
    
public:
    /**
     * Default constructor, needed for Boost::serialization
     */
    Instance() {};
    /**
     * @brief Initializes the Instance, setting gid
     * @param gid A globally unique std::string identifier
     */
    Instance(std::string id) : gid(id) {};
    
    virtual ~Instance() {};
    
    
    inline std::string id() {
        return gid;
    }
    
    /**
     * @brief Returns upper limitation for this instance
     *
     * Defaults to -1, meaning no restriction
     * The Pairing-Based BM-BE instance introduces the upper limit N
     * which is decided upon initialization
     */
    virtual int max_users() {
        return -1; // No restriction
    }
    /**
     * @brief For all derived classes, this returns the instance_types enum value.
     */
    virtual instance_types type() = 0;
    
    /**
     * @brief Store Instance state, if necessary
     * This is to be called before Boost serialization to reduce
     * internal representations (i.e., PBC BE system, keys) into 
     * a format that boost can handle
     */
    virtual void store() = 0;
    
    /**
     * @brief Restore the instance state
     */
    virtual void restore() = 0;
      
    /**
     * @brief return instance members
     */
    virtual std::map<std::string, int> instance_members() {
        return members;
    };
    
    
    /**
     * @brief add member to this instance
     */
    virtual int add_member(std::string id) {
        // default: map all users to 0
        // BM-BE sending instances (BES_sender) override this behavior for pseudonyms
        
        members.insert(std::pair<std::string, int>(id, 0));
        return 0;
    }
    
    /**
     * @brief remove a member from this instance
     * @param id The member to remove
     */
    virtual void remove_member(std::string id) {
        members.erase(id);
    }
    
    
    /**
     * @brief returns internal id associated to member
     * or -1 if id is not a member
     * @param id The member id string
     */
    virtual int get_member_id(std::string id) {
        std::map<std::string, int>::iterator it = members.find(id);
        
        if (it != members.end()) {
            return it->second;
        } else {
            return -1;
        }
    }
    
    /**
     * @brief returns whether this instance comprises
     * a certain member id
     * @param id The member id string
     * @return true if id is a member of this instance, false otherwise
     */
    virtual bool is_member(std::string id) {
        return (get_member_id(id) != -1);
    }
    
    

protected:

    std::string gid;
    std::map<std::string, int> members;
    
    
private:
    
    //
    // Boost class serialization
    //
    friend class boost::serialization::access;
    template<class Archive>
    void serialize(Archive & ar, const unsigned int version) {
        ar & gid;
        ar & members;
    }
};
#endif