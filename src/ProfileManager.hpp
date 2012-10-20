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

/**
 * @file   ProfileManager.hpp
 * @Author Oliver Guenther (mail@oliverguenther.de)
 * @date   September 2012
 * @brief  Entrypoint to Profile Management
 *
 * The ProfileManager persists local profiles to disk, handling PGP encryption
 * and serialization. It provides a cache to unlocked profiles.
 *
 */

#include "Profile.hpp"
#include <map>

// Boost serialization
#include <boost/archive/text_oarchive.hpp>
#include <boost/archive/text_iarchive.hpp>
#include <boost/serialization/map.hpp>

// Boost Shared pointers
#include <boost/shared_ptr.hpp>

/**
 * @class ProfileManager ProfileManager.h
 * @brief Entrypoint to Profile Management
 *
 * The ProfileManager persists local profiles to disk, handling PGP encryption
 * and serialization. It provides a cache to unlocked profiles.
 */
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
     * @fn ProfileManager::get_last_profile
     * @brief Returns last active (i.e., unlocked) profile name, if existent
     */
    std::string get_last_profile() {
        return last_profile;
    }
    
    
    /**
     * @fn ProfileManager::unlock_profile
     * @brief Unlocks a profile by decrypting the profile.data store
     * using the associated PGP key
     * @return A profile_ptr to either the active profile or an empty profile_ptr if 
     * the unlock was unsuccessful
     */    
    profile_ptr unlock_profile(FB::DOM::WindowPtr window, std::string profilename);
    
    /**
     * @fn ProfileManager::store_profile
     * @brief Stores the given profile to disk
     * @param profilename the profile name
     * @param istore a profile_ptr to a profile to store (i.e. the active profile)
     */   
    void store_profile(std::string profilename, profile_ptr istore);
    
    /**
     * @fn ProfileManager::store_active
     * @brief Stores the active profile to disk (if any). 
     * Used before destructing the ProfileManager object, to store the latest state
     */   
    void store_active();
    
    
    /**
     * @fn ProfileManager::add_profile
     * @brief Add new (empty) profile to ProfileManager
     * @param name The profile name
     * @param keyid Associated PGP key identifier or fingerprint
     */
    void add_profile(std::string name, std::string keyid) {
        
        // Insert profile only if no such key exists
        if (profiles.find(name) == profiles.end()) {
            profiles.insert(std::pair<std::string, std::string>(name, keyid));
        }
    }
    
    /**
     * @fn ProfileManager::delete_profile
     * @brief Remove a profile from ProfileManager
     *
     * Removing a profile will first unlock it.
     */
    FB::VariantMap delete_profile(FB::DOM::WindowPtr window, std::string profilename);
    
    
    static void archive(ProfileManager *p);
    static ProfileManager* unarchive();
    
    
private:
       
    // Stored profiles, name -> PGP key id
    std::map<std::string, std::string> profiles;
    
    // Caches previously used profile
    profile_ptr active_profile;
    
    // Caches the last profile name
    std::string last_profile;
    
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
     * @fn ProfileManager::make_active
     * @brief Set this profile as active_profile, set the cached_at and
     * last_profile string
     * @return a profile_ptr to the internal active_profile shared_ptr
     */
    profile_ptr make_active(profile_ptr p);
    
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
        ar & last_profile;
    }
};

#endif