#ifndef H_BES_SENDER
#define H_BES_SENDER

#include <map>
#include <vector>
#include "BES_base.h"

// serialization
#include <boost/archive/text_oarchive.hpp>
#include <boost/archive/text_iarchive.hpp>
#include <boost/serialization/vector.hpp>
#include <boost/serialization/map.hpp>
#include <boost/serialization/base_object.hpp>


class BES_sender : public BES_base  {
    
public: 
    // Required for (De-)Serialization
    BES_sender() : BES_base() {}
    BES_sender(std::string gid, int num_users);    
    
    BES_sender(const BES_sender&);
    
    ~BES_sender();
    
    
    /**
     * Encrypt using Broadcast system
     * @param S receivers of the message
     * @param data binary data to encrypt
     */
    void bes_encrypt(bes_ciphertext_t *cts, std::vector<int>& S, std::string& data);
    
    
    /** 
     * Return the keypair (i, d_i) for the userid that is associated with index i
     * @param userID userid to receive key
     * @return a std::pair containing i and d_i
     */
    std::pair<int,element_t> get_private_key(std::string userID);
    
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
    int addMember(std::string id);
    
    
    /**
     * Tries to remove a member from this system
     * @param id std::string member id
     */
    void removeMember(std::string id);
    
    /**
     * Return instance id from member id
     * @param id std::string member id
     * @return memberid (>= 0) when id is member in this system, -1 otherwise
     */
    int memberID(std::string id);
    
    
    
    /**
     * Store BES state to its instance file
     * @param force Forces rewriting instance file
     */
    int store(bool force);
    
    /**
     * Restores saved BES state
     * @return 0 if successful, 1 otherwise
     */
    int restore();
        
    
private:
    /**
     * BES encryption scheme
     */
    bes_system_t sys;
    
    /*
     * Current users in the BES
     */
    std::map <std::string, int> users;
    
    /*
     * IDs available in the system
     */
    std::vector<int> availableIDs;
    
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
    friend class boost::serialization::access;
    template<class Archive>
    void serialize(Archive & ar, const unsigned int version)
    {
        ar & boost::serialization::make_nvp( BOOST_PP_STRINGIZE(*this),boost::serialization::base_object<BES_base>(*this));
        ar & N;
        ar & gid;
        ar & users;
        ar & availableIDs;
    }
    
};

#endif
