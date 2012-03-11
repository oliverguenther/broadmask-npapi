#ifndef H_BCINSTANCE
#define H_BCINSTANCE

#include <stdexcept>

// serialization
#include <boost/archive/text_oarchive.hpp>
#include <boost/archive/text_iarchive.hpp>
#include <boost/serialization/string.hpp>


// filesystem
#include <boost/filesystem.hpp>
#include <boost/filesystem/operations.hpp>
#include <boost/filesystem/path.hpp>


// resolves gmp c++ related linking errors
// 'declaration of C function 'std::ostream& operator<<(std::ostream&, const __mpq_struct*)' conflicts with ..'

#include <gmpxx.h>

extern "C" {
#include "PBC_bes/pbc_bes.h"
}

class BCException : public std::runtime_error {
public:
    BCException(const std::string& message) 
        : std::runtime_error(message) { };
};

class BCInstance  {
    
public:
	BCInstance(std::string gid, unsigned int N);
	~BCInstance();

	std::string groupid();
    
private:
      
    boost::filesystem::path* instance_path(std::string&);
    
   	std::string gid;
	unsigned int N;
    static const char* params;
       
	// Global system parameters
	bes_global_params_t gbs;
    
    // Broadcast encryption system
    bes_system_t sys;
    
    template<class Archive>
    void element_to_ar(element_t &el, Archive &ar) {
        int len = element_length_in_bytes(el);
        char buf[len];
        
        element_to_bytes(buf, sys->PK->g);

        
        std::string str(buf);
        ar & str;
        
    }
    
    template<class Archive>
    void element_from_ar(element_t &el, Archive &ar) {

        std::string str;
        
        ar & str;
        
        element_from_bytes(el, str.c_str());
        
        return el;
        
    }
    
    
    template<class Archive>
    void save(Archive & ar, const unsigned int version) const {
        // Convert pbc_bes structs to STL containers
        ar & gid;
        ar & N;
        
        // global params
        ar & gbs->A;
        ar & gbs->B;
        
        // Store Public Key
        // g
        element_to_ar(ar, sys->PK->g);
        
        int i;
        // g_i
        for (i = 0; i < 2*gbs->B; ++i) {
            element_to_ar(sys->PK->g_i[i], ar);
        }
        
        // v_i
        for (i = 0; i < gbs->A; ++i) {
            element_to_ar(sys->PK->v_i[i], ar);
        }

        // Store private keys
        for (i = 0; i < N; ++i) {
            element_to_ar(sys->d_i[i], ar);
        }
        
    }
    
    template<class Archive>
    void load(Archive & ar, const unsigned int version) {
        ar & gid;
        ar & N;
        
        // global params
        gbs = pbc_malloc(sizeof(struct bes_global_params_s));
        gbs->N = N;
        ar & gbs->A;
        ar & gbs->B;
                
        // Init pairing
        pairing_init_set_str(gbs->pairing, params);
        
        // System
        sys = pbc_malloc(sizeof(struct bes_system_s));
        
        // Public Key
        sys->PK = pbc_malloc(sizeof(struct pubkey_s));
        element_from_ar(sys->PK->g, ar);
        
        int i;
        // g_i
        sys->PK->g_i = pbc_malloc((2 * gbs->B) * sizeof(element_t));
        for (i = 0; i < 2*gbs->B; ++i) {
            element_from_ar(sys->PK->g_i[i], ar);
        }
        
        // v_i
        sys->PK->v_i = pbc_malloc(gbs->A * sizeof(element_t));
        for (i = 0; i < gbs->A; ++i) {
            element_from_ar(sys->PK->v_i[i], ar);
        }
        
        // Store private keys
        sys->d_i = pbc_malloc(gbs->N * sizeof(element_t));        
        for (i = 0; i < N; ++i) {
            element_from_ar(sys->d_i[i], ar);
        }
        
    }
    
    template<class Archive>
    void serialize(
                   Archive & ar,
                   const unsigned int file_version 
                   ){
        boost::serialization::split_member(ar, *this, file_version);
    }

};



#endif
