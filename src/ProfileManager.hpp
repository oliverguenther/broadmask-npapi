/*
 * BroadMask Profile Manager
 * 
 * Broadmask is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * Broadmask is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with Broadmask.  If not, see <http://www.gnu.org/licenses/>.
 * 
 * Oliver Guenther
 * mail@oliverguenther.de
 *
 * 
 * ProfileManager
 */

#ifndef H_PROFILE_MANAGER
#define H_PROFILE_MANAGER

// serialization
#include <boost/archive/text_oarchive.hpp>
#include <boost/archive/text_iarchive.hpp>
#include <boost/serialization/map.hpp>


#include "Profile.hpp"
#include <map>


class ProfileManager  {
    
public:
    ProfileManager();
    ~ProfileManager();
    
    /**
     * @fn ProfileManager::get_stored_profiles
     * @brief Returns a map (name -> PGP key) of all known profiles
     * @return FB::VariantMap of all known profiles 
     */    
    FB::VariantMap get_stored_profiles();
    
    
    /**
     * @fn ProfileManager::unlock_profile
     * @brief Unlocks a profile by decrypting the profile.data store
     * using the associated PGP key
     * @return A pointer to the unlocked Profile, or NULL
     */    
    Profile* unlock_profile(FB::DOM::WindowPtr window, std::string profilename);
    
    void store_profile(std::string profilename, Profile* istore);
       
    void add_profile(std::string name, std::string keyid) {
        
        // Insert profile only if no such key exists
        if (profiles.find(name) == profiles.end()) {
            profiles.insert(std::pair<std::string, std::string>(name, keyid));
        }
    }
    
    
    static void archive(ProfileManager *p);
    static ProfileManager* unarchive();
    
    
private:
       
    // Stored profiles, name -> PGP key id
    std::map<std::string, std::string> profiles;
    
    // Caches previously used profile
    Profile *active_profile;
    
    // Records the time when the active profile was cached
    time_t cached_at;
    
    // Stores authorized domains the user has allowed
    std::map<std::string, bool> authorized_domains;

    /**
     * @fn ProfileManager::is_active_and_valid
     * @brief Checks if the cached active_profile is the matching profile
     * and if so, whether the cache is valid
     * @return A pointer to the unlocked Profile, or NULL
     */   
    bool is_active_and_valid (std::string profilename);
    
    /**
     * @fn ProfileManager::has_user_ack
     * @brief Checks if the user has authorized the current domain to access
     * the Profile
     * @return true if the user has authorized, false otherwise
     */   
    bool has_user_ack (std::string profilename, FB::DOM::WindowPtr window);
    
    //
    // Boost class serialization, independent from BES serialization
    //
    friend class boost::serialization::access;
    template<class Archive>
    void serialize(Archive & ar, const unsigned int version)
    {
        ar & profiles;
        ar & authorized_domains;
    }
};

#endif