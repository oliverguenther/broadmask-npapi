#ifndef H_SHARED_INSTANCE
#define H_SHARED_INSTANCE

#include <set>
#include <vector>
#include "Instance.hpp"
#include "JSAPIAuto.h"
#include "JSObject.h"
#include "variant_map.h"
#include "streamhelpers.hpp"

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
    SK_Instance(std::string groupid, std::string key_b64);
    
    ~SK_Instance();
    
    instance_types type() { return BROADMASK_INSTANCE_SK; }

    FB::VariantMap encrypt(std::string plaintext);
    FB::VariantMap decrypt(sk_ciphertext_t sk_ct);
    
    
    std::vector<unsigned char> get_symmetric_key();
    
    /** 
     * No internal state needed
     */
    void store() {}
    void restore() {}
    
    std::string instance_file();
    
private:
    
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
        ar & members;
        ar & keylen;
        ar & key;
    }
    
};

#endif
