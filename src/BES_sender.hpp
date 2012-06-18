#ifndef H_BES_SENDER
#define H_BES_SENDER

#include <map>
#include <deque>
#include <vector>
#include "Instance.hpp"
#include "streamhelpers.hpp"
#include "variant_map.h"

// serialization
#include <boost/archive/text_oarchive.hpp>
#include <boost/archive/text_iarchive.hpp>
#include <boost/serialization/deque.hpp>
#include <boost/serialization/map.hpp>
#include <boost/serialization/base_object.hpp>
#include <boost/serialization/export.hpp>

// filesystem
#include <boost/filesystem/operations.hpp>
#include <boost/filesystem/path.hpp>


class BES_sender : public Instance  {
    
public: 
    BES_sender(std::string gid, int num_users);            
    ~BES_sender();
    
    instance_types type() { return BROADMASK_INSTANCE_BES_SENDER; }
    
    /**
     * Encrypt using Broadcast system
     * @param S receivers of the message
     * @param data binary data to encrypt
     */
    void bes_encrypt(bes_ciphertext_t *cts, const std::vector<std::string>& S, std::string& data);
    
    /**
     * Decrypt ciphertext using Broadcast system
     */
    FB::VariantMap bes_decrypt(bes_ciphertext_t& cts);
    
    
    /** 
     * Return the keypair (i, d_i) for the userid that is associated with index i
     * @param a struct containing i and d_i
     * @param userID userid to receive key
     */
    void get_private_key(bes_privkey_t* sk_ptr, std::string userID);
    
    /**
     * Return the public params required to create a receiving session
     * for this particular system (i.e., [N, PK])
     */
    void public_params_to_stream(std::ostream& os);
     
    
    /**
     * Adds a member to this system
     * @param id std::string member id
     * @return member id (>= 0) if user was added, -1 otherwise
     */
    int add_member(std::string id);
    
    
    /**
     * Tries to remove a member from this system
     * @param id std::string member id
     */
    void remove_member(std::string id);
    
    /**
     * Return instance id from member id
     * @param id std::string member id
     * @return memberid (>= 0) when id is member in this system, -1 otherwise
     */
    int member_id(std::string id);

    int max_users() {
        return N;
    }
    
    
    
    /**
     * Store BES state to internal string
     */
    void store();
    
    /**
     * Restores saved BES state
     */
    void restore();
    
    /**
     * BES public global params
     */
    bkem_global_params_t gbs;
        
    
private:
    
    
    /**
     * Max users
     */
    int N;
    
    /**
     * BES encryption scheme
     */
    bkem_system_t sys;
    
    /**
     * The sender's private key to decrypt all messages
     */
    bes_privkey_t SK;
    
    /*
     * IDs available in the system
     */
    std::deque<int> availableIDs;
    
    /*
     * Stores internal state (after BES_sender::store is called)
     * and is serialized by Boost::Serialization
     */
    std::string stored_state;
    
    /** 
     * Derivate a symmetric encryption key to be used within subset S
     * @param[out] key symmetric key of size keylen
     * @param[in] keylen length input for KDF
     * @param[in] bes_key element_t key from bes instance
     */
    void derivate_encryption_key(unsigned char *key, size_t keylen, element_t bes_key);
    
    
    //
    // Boost class serialization, independent from BES serialization
    //
    
    // Default Constructor, required for (De-)Serialization
    BES_sender() : Instance() {}
    
    friend class boost::serialization::access;
    template<class Archive>
    void serialize(Archive & ar, const unsigned int version)
    {
        ar & boost::serialization::make_nvp( BOOST_PP_STRINGIZE(*this),boost::serialization::base_object<Instance>(*this));
        ar & N;
        ar & gid;
        ar & members;
        ar & availableIDs;
        ar & stored_state;
    }
    
};

#endif