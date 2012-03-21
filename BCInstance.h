#ifndef H_BCINSTANCE
#define H_BCINSTANCE

#include <stdexcept>
#include <map>

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
    
    /** 
     * Derivate a symmetric encryption key to be used within subset S
     * @param[out] 
     * @param[in] S indices of participating receivers
     * @param[in] num_receivers size of S
     * @return key size
     */
    void derivate_encryption_key(char *key, size_t keylen, int *S, int num_receivers);


    
    
private:
      
   	std::string gid;
	unsigned int N;
    static const char* params;
       
	// Global system parameters
	bes_global_params_t gbs;
    
    // Broadcast encryption system
    bes_system_t sys;
    
    // userids mapped to bes
    std::map <std::string, int> users;
    std::vector<int> availableIDs;
    
    void element_from_stream(element_t el, std::ifstream& is, int numbytes);
    void element_to_stream(element_t el, std::ofstream& is);

    
    /**
     * @return Path to saved instance file or NULL if nonexistant
     */
    boost::filesystem::path* instance_path(std::string&);



};

#endif
