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
//static const char* kProfileLockFile = "profile.lock";

ProfileManager::ProfileManager() {
    profiles = std::map<std::string, std::string>();
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
    
    if (!active_profile || !cached_at)
        return false; // No profile cached
    
    if (profilename.compare(active_profile->profilename()) != 0)
        return false; // Different profile cached
    
    // compare cache time
    int cache_hold = 1800; // 30 minutes
    time_t current = time (NULL);    
    if (current > (cached_at + cache_hold)) {
        // Store and invalidate cache
        store_profile(profilename, active_profile);
        delete active_profile;
        return false;
    }
    
    // Profile matches and is valid
    return true;
    
}


void ProfileManager::store_profile(std::string profilename, Profile* istore) {
    std::map<std::string, std::string>::iterator it = profiles.find(profilename);
    
    if (it == profiles.end())
        return;
    
    fs::path profilepath = broadmask_root();
    profilepath /= profilename;
    fs::path datapath (profilepath / kProfileStorageFile);
    
    
    std::stringstream os;
    Profile::store(istore, os);
    
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


Profile* ProfileManager::unlock_profile(FB::DOM::WindowPtr window, std::string profilename) {
    
    // Request permission from user if domain unknown
    if (!has_user_ack(profilename, window))
        return NULL;
    
    // if Profile matches active profile
    if (is_active_and_valid(profilename))
        return active_profile;
    
    std::map<std::string, std::string>::iterator it = profiles.find(profilename);
    
    if (it == profiles.end())
        // No such profile
        return NULL;
    
    fs::path profilepath = broadmask_root();
    profilepath /= profilename;
    fs::path datapath (profilepath / kProfileStorageFile);

    // Profile has not been created or Profile Storage not existant
    // then create it and return new storage
    if (!fs::is_directory(profilepath) || !fs::is_regular_file(datapath)) {
        fs::create_directories(profilepath);
        cached_at = time(NULL);
        active_profile = new Profile(profilename);
        return active_profile;   
    }
    
    // Test if file is empty, in which case delete it and return new storage
    if (fs::is_empty(datapath)) {
        cout << "Found empty profile.data for profile " << profilename << endl;
        fs::remove(datapath);
        cached_at = time(NULL);
        active_profile = new Profile(profilename);
        return active_profile;
    }
    
    // Read file
    gpgme_result dec_result = gpgme_decrypt_file(datapath.string().c_str());
    
    if (dec_result.error) {
        cerr << "[BroadMask] Could not load profile " << profilename << ". Error was: "
        << dec_result.error_msg << endl;
        return NULL;
    }
    
    // Use recovered plaintext to load Profile
    std::string recovered = base64_decode(std::string(dec_result.result));
    std::istringstream is(recovered);
    
    active_profile = Profile::load(is);
    
    if (active_profile)
        cached_at = time(NULL);

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
    profiles.clear();
}