#ifndef H_INSTANCE
#define H_INSTANCE

// serialization
#include <boost/archive/text_oarchive.hpp>
#include <boost/archive/text_iarchive.hpp>
#include <boost/serialization/map.hpp>

// filesystem
#include <boost/filesystem/operations.hpp>
#include <boost/filesystem/path.hpp>

class Instance {
    
public:
    // Needed for serialization
    Instance() {};
    Instance(std::string id) : gid(id) {};
    
    virtual ~Instance() {};
    
    
    inline std::string id() {
        return gid;
    }
    
    /**
     * @brief Store this instance to disk
     */
    virtual int store() = 0;
    
    /**
     * @brief Restore this instance
     */
    virtual int restore() = 0;
    
    /**
     * @brief return the instance file path
     */
    virtual std::string instance_file() = 0;
    
    
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
        // BES_sender overrides this behavior for pseuodnyms
        
        members.insert(std::pair<std::string, int>(id, 0));
        return 0;
    }
    
    /**
     * @brief remove a member from this instance
     */
    virtual void remove_member(std::string id) {
        members.erase(id);
    }
    
    
    /**
     * @brief returns internal id associated to member
     * or -1 if id is not a member
     */
    virtual int get_member_id(std::string id) {
        std::map<std::string, int>::iterator it = members.find(id);
        
        if (it != members.end()) {
            return it->second;
        } else {
            return -1;
        }
    }
    
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