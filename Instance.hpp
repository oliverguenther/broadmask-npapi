#ifndef H_INSTANCE
#define H_INSTANCE

// serialization
#include <boost/archive/text_oarchive.hpp>
#include <boost/archive/text_iarchive.hpp>

// filesystem
#include <boost/filesystem/operations.hpp>
#include <boost/filesystem/path.hpp>

class Instance {
    
public:
    // Needed for serialization
    Instance() {};
    Instance(std::string id) : gid(id) {};
    
    
    std::string id() {
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
    
    

protected:

    std::string gid;

    
private:
    
    //
    // Boost class serialization
    //
    friend class boost::serialization::access;
    template<class Archive>
    void serialize(Archive & ar, const unsigned int version)
    {
        ar & gid;
    }
};
#endif