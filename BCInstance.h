#ifndef H_BCINSTANCE
#define H_BCINSTANCE

#include <stdexcept>
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
      
   	std::string gid;
	unsigned int N;
    static const char* params;
       
	// Global system parameters
	bes_global_params_t gbs;
    
    // Broadcast encryption system
    bes_system_t sys;
    
    void element_from_stream(element_t el, std::ifstream& is, int numbytes);
    void element_to_stream(element_t el, std::ofstream& is);

    
    /**
     * @return Path to saved instance file or NULL if nonexistant
     */
    boost::filesystem::path* instance_path(std::string&);



};

#endif
