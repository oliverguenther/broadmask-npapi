#ifndef H_SHARED_INSTANCE
#define H_SHARED_INSTANCE

#include <set>
#include <vector>
#include "Instance.hpp"
#include "JSAPIAuto.h"
#include "JSObject.h"
#include "variant_map.h"

// serialization
#include <boost/archive/text_oarchive.hpp>
#include <boost/archive/text_iarchive.hpp>
#include <boost/serialization/set.hpp>
#include <boost/serialization/base_object.hpp>


class SK_Instance : public Instance  {
    
public: 
    // Required for De-Serialization
    SK_Instance() : Instance() {}
    SK_Instance(std::string groupid);
    SK_Instance(std::string groupid, std::string key_b64, int keysize);
    
    ~SK_Instance();
    
    
    bool is_authorized(std::string user_id);
    
    void add_member(std::string user_id);
    
    
    FB::VariantMap encrypt(std::string plaintext);
    FB::VariantMap decrypt(FB::JSObjectPtr params);
    
    /** 
     * storage functions currently not needed
     */
    int store() { return -1; }
    int restore() { return -1; }
    
    std::string instance_file();
    
private:
    
    
    /**
     * Registered users
     */
    
    std::set <std::string> authorized_users;
    
    int keylen;
    
    std::vector<unsigned char> key;
    
    //
    // Boost class serialization
    //
    friend class boost::serialization::access;
    template<class Archive>
    void serialize(Archive & ar, const unsigned int version)
    {
        ar & boost::serialization::make_nvp( BOOST_PP_STRINGIZE(*this),boost::serialization::base_object<Instance>(*this));
        ar & gid;
        ar & keylen;
        ar & authorized_users;
        ar & key;
    }
    
};

#endif