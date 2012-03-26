#ifndef H_BES_BASE
#define H_BES_BASE

#include <stdexcept>
#include <vector>
#include <utility>

// serialization
#include <boost/archive/text_oarchive.hpp>
#include <boost/archive/text_iarchive.hpp>

// resolves gmp c++ related linking errors
// 'declaration of C function 'std::ostream& operator<<(std::ostream&, const __mpq_struct*)' conflicts with ..'

#include <gmpxx.h>

extern "C" {
#include "PBC_bes/pbc_bes.h"
}

/**
 * @typedef Ciphertext struct
 */
typedef struct bes_ciphertext_s {
    int num_receivers;
    int ct_length;
    int* receivers;
    element_t* HDR;
    unsigned char* iv;
    unsigned char* ct;
}* bes_ciphertext_t;

class BCException : public std::runtime_error {
public:
    BCException(const std::string& message) 
    : std::runtime_error(message) { };
};

class BES_base  {
    
public: 
    BES_base();
    BES_base(std::string gid, int num_users);
    
	std::string groupid();
    int num_users();

    /**
     * Store BES state to its instance file
     * @param force Forces rewriting instance file
     */
    virtual int store(bool force) = 0;
    
    /**
     * Restores saved BES state
     * @return 0 if successful, 1 otherwise
     */
    virtual int restore() = 0;
    
    void element_from_stream(element_t el, std::istream& is, int numbytes);
    void element_to_stream(element_t el, std::ostream& is);
    
    void ciphertext_from_stream(bes_ciphertext_t *ct, std::istream& is);
    void ciphertext_to_stream(bes_ciphertext_t ct, std::ostream& os);
    
    void public_key_from_stream(pubkey_t *pubkey_p, std::istream& is, int element_size);
    void public_key_to_stream(pubkey_t pk, std::ostream& os);
    
    void private_key_from_stream(std::pair<int, element_t> *sk, std::istream& is, int element_size);
    void private_key_to_stream(std::pair<int, element_t> sk, std::ostream& os);
    
    
protected:
    int N;
   	std::string gid;
    static const char* params;
    
	// Global system parameters
	bes_global_params_t gbs;
    
    
private:
    
    //
    // Boost class serialization, independent from BES serialization
    //
    friend class boost::serialization::access;
    template<class Archive>
    void serialize(Archive & ar, const unsigned int version)
    {
        std::cout << "DESERIALIZING" << std::endl;
        ar & N;
        ar & gid;
    }
};

#endif
