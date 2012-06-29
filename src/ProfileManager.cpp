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
 * ProfileManager.cpp
 */

#include "ProfileManager.hpp"
#include "gnupg_wrapper.hpp"
#include "utils.h"
#include "Base64.h"

#include <time.h>
#include <string>
#include <fstream>
#include <streambuf>
#include <sstream>

// Boost filesystem
#include <boost/filesystem.hpp>
#include <boost/filesystem/operations.hpp>
#include <boost/filesystem/path.hpp>
namespace fs = boost::filesystem;

// DOM Window for alerts/confirmation dialogs
#include "DOM/Window.h"

// JSAPI
#include "JSAPIAuto.h"
#include "JSObject.h"
#include "variant_map.h"
#include "variant_list.h"
#include "variant.h"


static const char* kProfileManagerFile = "bm_profiles";
static const char* kProfileStorageFile = "profile.data";

ProfileManager::ProfileManager() {
    profiles = std::map<std::string, std::string>();
}

FB::VariantMap ProfileManager::get_stored_profiles() {
    FB::VariantMap result;
    for (std::map<std::string, std::string>::iterator it = profiles.begin(); it != profiles.end(); ++it) {
        result[it->first] = it->second;
    }
    return result;
}


bool ProfileManager::has_user_ack(std::string profilename, FB::DOM::WindowPtr window) {
    
    try {
        if (window && window->getJSObject()->HasProperty("location")) {
            // Create a reference to the browswer console object
            FB::JSObjectPtr obj = window->getProperty<FB::JSObjectPtr>("location");
            
            std::string origin = obj->GetProperty("origin").convert_cast<std::string>();
            std::string href = obj->GetProperty("href").convert_cast<std::string>();
            
            // Return the result of authorized domain entry, if found
            std::map<std::string, bool>::iterator it = authorized_domains.find(origin);
            if (it != authorized_domains.end())
                return it->second;
            
            // Ask user
            FB::variant ack_result;
            std::stringstream ss;
            ss << "The following page requests access to the BroadMask profile ";
            ss << "'" << profilename << "' :" << endl;
            ss << href << endl << endl;
            ss << "Do you want to authorize the domain?";
            ack_result = window->getJSObject()->Invoke("confirm", FB::variant_list_of(ss.str()));
            
            bool ack = ack_result.convert_cast<bool>();
            
            if (ack == true) {
                authorized_domains.insert(std::pair<std::string, bool>(origin, true));
                return true;
            } else {
                return false;
            }
            
        }
    } catch (exception& e) {
        cerr << "[BroadMask ProfileManager] Error getting user ack: " << e.what() << endl;
        return false;
    }
    
    return false;
}

bool ProfileManager::is_active_and_valid (std::string profilename) {
    
    if (!active_profile.get() || !cached_at)
        return false; // No profile cached
    
    if (profilename.compare(active_profile->profilename()) != 0)
        return false; // Different profile cached
    
    // compare cache time
    int cache_hold = 7200; // 2 hours
    time_t current = time (NULL);    
    if (current > (cached_at + cache_hold)) {
        // Store and invalidate cache
        store_active();
        active_profile.reset();
        make_active(active_profile);
        return false;
    }
    
    // Profile matches and is valid
    return true;
    
}


void ProfileManager::store_profile(std::string profilename, profile_ptr p) {
    
    // If profile_ptr empty, nothing to store
    if (!p.get()) {
        cout << "[BroadMask] Not storing empty profile_ptr for " << profilename << endl;
        return;
    }
    
    std::map<std::string, std::string>::iterator it = profiles.find(profilename);
    
    if (it == profiles.end())
        return;
    
    fs::path profilepath = broadmask_root();
    profilepath /= profilename;
    fs::path datapath (profilepath / kProfileStorageFile);
    
    
    std::stringstream os;
    Profile::store(p, os);
    
    std::string keyid = it->second;
    // Encode Profile as Base64, as Instances are 
    // manually serialized, and may contain \0 characters
    std::string istore_str = base64_encode(os.str());
    
    gpgme_result enc_result = gpgme_encrypt_tofile(istore_str.data(), keyid.c_str(), datapath.string().c_str());
       
    if (enc_result.error) {
        cerr << "[BroadMask] Could not store profile " << profilename << ". Error was: "
        << enc_result.error_msg << endl;
    }
    
}

void ProfileManager::store_active() {
    Profile *p = active_profile.get();
    
    // Store only if active
    if (p)
        store_profile(p->profilename(), active_profile);    
}


profile_ptr ProfileManager::unlock_profile(FB::DOM::WindowPtr window, std::string profilename) {
    
    
    profile_ptr p = profile_ptr();
    
    // Request permission from user if domain unknown
    if (!has_user_ack(profilename, window))
        return p;
    
    // if Profile matches active profile
    if (is_active_and_valid(profilename))
        return active_profile;
    
    std::map<std::string, std::string>::iterator it = profiles.find(profilename);
    
    if (it == profiles.end())
        return p; // No such profile
    
    fs::path profilepath = broadmask_root();
    profilepath /= profilename;
    fs::path datapath (profilepath / kProfileStorageFile);

    // Profile has not been created or Profile Storage not existant
    // then create it and return new storage
    if (!fs::is_directory(profilepath) || !fs::is_regular_file(datapath)) {
        fs::create_directories(profilepath);
        boost::shared_ptr<Profile> p(new Profile(profilename, it->second));
        return make_active(p);
    }
    
    // Test if file is empty, in which case delete it and return new storage
    if (fs::is_empty(datapath)) {
        cout << "Found empty profile.data for profile " << profilename << endl;
        fs::remove(datapath);
        boost::shared_ptr<Profile> p(new Profile(profilename, it->second));
        return make_active(p);
    }
    
    // Read file
    gpgme_result dec_result = gpgme_decrypt_file(datapath.string().c_str());
    
    if (dec_result.error) {
        cerr << "[BroadMask] Could not load profile " << profilename << ". Error was: "
        << dec_result.error_msg << endl;
        p.reset();
        return p;
    }
    
    // Use recovered plaintext to load Profile
    std::string recovered = base64_decode(std::string(dec_result.result));
    std::istringstream is(recovered);
    
    
    p = Profile::load(is);
    return make_active(p);
}

FB::VariantMap ProfileManager::delete_profile(FB::DOM::WindowPtr window, std::string profilename) {
    profile_ptr p = unlock_profile(window, profilename);
    Profile *istore = p.get();
    
    FB::VariantMap result; 
    if (!istore) {
        result["error"] = true;
        result["error_msg"] = "Could not unlock profile";
    } else {
        // delete profile entry
        profiles.erase(profilename);
        // delete file itself
        fs::path profilepath = broadmask_root();
        profilepath /= profilename;
        fs::remove_all(profilepath);
        // p == active_profile
        p.reset();
        make_active(p);
        
        result["error"] = false;
        
        ProfileManager::archive(this);
    }
    
    return result;
}

profile_ptr ProfileManager::make_active(profile_ptr p) {  
    Profile *istore = p.get();
    if (istore) {
        cached_at = time(NULL);
        last_profile = istore->profilename();
        active_profile = p;
    } else {
        // If p is null, removes current active profile
        active_profile.reset();
        cached_at = NULL;
        last_profile.clear();
    }
    
    return active_profile;
}

void ProfileManager::archive(ProfileManager *p) {
    fs::path profilepath = broadmask_root();
    if (!fs::is_directory(profilepath)) {
        fs::create_directories(profilepath);
    }
    
    fs::path datapath (profilepath / kProfileManagerFile);    
    ofstream ofs (datapath.string().c_str());
    boost::archive::text_oarchive oa(ofs);
    
    try {
        oa << *p;
    } catch (exception& e) {
        cerr << "[BroadMask] Could not store ProfileManager: " << e.what() << endl;
    }    
}
ProfileManager* ProfileManager::unarchive() {
    ProfileManager *pm = new ProfileManager();
    fs::path profilepath = broadmask_root();
    fs::path datapath (profilepath / kProfileManagerFile);    

    if (fs::is_regular_file(datapath)) {
        std::ifstream ifs(datapath.string().c_str(), std::ios::in);
        boost::archive::text_iarchive ia(ifs);
        
        try {
            ia >> *pm;
        } catch (exception& e) {
            cout << e.what() << endl;
        }
    }
    
    return pm;
}

ProfileManager::~ProfileManager() {
    // Store active profile, if any
    store_active();
    
    // Archive this ProfileManager to disk
    ProfileManager::archive(this);
    
    
    profiles.clear();
    active_profile.reset();
}