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
#include <boost/serialization/base_object.hpp>
#include <boost/serialization/vector.hpp>
#include <boost/serialization/export.hpp>

// AE wrapper
#include "BDEM/ae_wrapper.hpp"



class SK_Instance : public Instance  {
    
public: 
    SK_Instance(std::string groupid);
    SK_Instance(std::string groupid, std::string key_b64);
    ~SK_Instance();
    
    instance_types type() { return BROADMASK_INSTANCE_SK; }

    ae_error_t encrypt(AE_Ciphertext** cts, AE_Plaintext* pts);
    ae_error_t decrypt(AE_Plaintext** pts, AE_Ciphertext* sk_ct);
    
    
    std::vector<unsigned char> get_symmetric_key();
    
    /** 
     * No internal state needed
     */
    void store() {}
    void restore() {}
    
private:
    
    std::vector<unsigned char> key;
        
    //
    // Boost class serialization
    //
    
    // Default Constructor, required for De-Serialization
    SK_Instance() : Instance() {}
    
    friend class boost::serialization::access;
    template<class Archive>
    void serialize(Archive & ar, const unsigned int version)
    {
        ar & boost::serialization::make_nvp( BOOST_PP_STRINGIZE(*this),boost::serialization::base_object<Instance>(*this));
        ar & gid;
        ar & members;
        ar & key;
    }
    
};

#endif
