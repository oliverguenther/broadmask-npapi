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
#include <string>
#include <fstream>
#include <streambuf>
#include <sstream>

// Boost filesystem
#include <boost/filesystem.hpp>
#include <boost/filesystem/operations.hpp>
#include <boost/filesystem/path.hpp>
namespace fs = boost::filesystem;


static const char* kProfileStorageFile = "profile.data";
//static const char* kProfileLockFile = "profile.lock";


void ProfileManager::store_profile(std::string profilename, InstanceStorage* istore) {
    std::map<std::string, std::string>::iterator it = profiles.find(profilename);
    
    if (it == profiles.end())
        return;
    
    fs::path profilepath = broadmask_root();
    profilepath /= profilename;
    fs::path datapath (profilepath / kProfileStorageFile);
    
    
    std::stringstream os;
    InstanceStorage::store(istore, os);
    
    std::string keyid = it->second;
    std::string istore_str = os.str();
    
    cout << "String istore is " << endl << istore_str << endl << "===" << endl;
    
    gpgme_result enc_result = gpgme_encrypt_tofile(istore_str.c_str(), keyid.c_str(), datapath.string().c_str());
    
    
    if (enc_result.error) {
        cerr << "[BroadMask] Could not store profile " << profilename << ". Error was: "
        << enc_result.error_msg << endl;
    }
    
}


InstanceStorage* ProfileManager::unlock_profile(std::string profilename) {
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
        return new InstanceStorage();   
    }
    
    // Test if file is empty, in which case delete it and return new storage
    if (fs::is_empty(datapath)) {
        cout << "Found empty profile.data for profile " << profilename << endl;
        fs::remove(datapath);
        return new InstanceStorage();
    }
    
    // Read file
    gpgme_result dec_result = gpgme_decrypt_file(datapath.string().c_str());
    
    if (dec_result.error) {
        cerr << "[BroadMask] Could not load profile " << profilename << ". Error was: "
        << dec_result.error_msg << endl;
        return NULL;
    }
    
    // Use recovered plaintext to load InstanceStorage
    std::string recovered = std::string(dec_result.result);
    std::istringstream is(recovered);
    
    return InstanceStorage::load(is);

}

ProfileManager::~ProfileManager() {
    profiles.clear();
}