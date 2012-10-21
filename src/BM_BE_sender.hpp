#ifndef H_BM_BE_sender
#define H_BM_BE_sender

/**
 * @file   BM_BE_sender.hpp
 * @Author Oliver Guenther (mail@oliverguenther.de)
 * @date   September 2012
 * @brief  Extends BM-BE instance for sending new content
 *
 *
 */
#include "BM_BE.hpp"
#include <deque>
#include <vector>

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

// Include AE scheme wrapper
#include "BDEM/ae_wrapper.hpp"

/**
 * @class  BM_BE_Sender BM_BE_sender.hpp
 * @brief  Extends BM-BE instance for sending new content
 *
 */
class BM_BE_Sender : public BM_BE  {
    
public:
    /**
     * @brief Initialize a new BM_BE_Sender instance
     * @param gid A globally unique std::string identifier
     * @param num_users The upper limitation of participants for this instance.
     *
     */
    BM_BE_Sender(std::string gid, int num_users);
    ~BM_BE_Sender();
    
    instance_types type() { return BROADMASK_INSTANCE_BM_BE_SENDER; }
    
    /**
     * Encrypt using Broadcast system
     * @param[out] cts Pointer to bes_ciphertext_t, which is allocated and returned with the ciphertext
     * @param[in] S receivers of the message
     * @param[in] data binary data to encrypt
     */
    void bes_encrypt(bes_ciphertext_t *cts, const std::vector<std::string>& S, std::string& data);
    
    /**
     * Return the keypair (i, d_i) for the userid that is associated with index i
     * @param a struct containing i and d_i
     * @param userID userid to receive key
     */
    void get_private_key(bes_privkey_t* sk_ptr, std::string userID);
    
    /**
     * Return the public params required to create a receiving session
     * for this particular system (i.e., [N, PK])
     * @param os An std::ostream output stream to write to
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
    
    /**
     * Return upper limit of participants for this instance,
     */
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
    
private:
    
    /**
     * BES encryption scheme
     */
    bkem_system_t sys;
       
    /*
     * IDs available in the system
     */
    std::deque<int> availableIDs;
    
    /*
     * Stores internal state (after BM_BE_Sender::store is called)
     * and is serialized by Boost::Serialization
     */
    std::string stored_state;
      
    
    //
    // Boost class serialization, independent from BES serialization
    //
    
    // Default Constructor, required for (De-)Serialization
    BM_BE_Sender() : BM_BE() {}
    
    friend class boost::serialization::access;
    template<class Archive>
    void serialize(Archive & ar, const unsigned int version)
    {
        ar & boost::serialization::make_nvp( BOOST_PP_STRINGIZE(*this),boost::serialization::base_object<BM_BE>(*this));
        ar & availableIDs;
        ar & stored_state;
    }
    
};

#endif