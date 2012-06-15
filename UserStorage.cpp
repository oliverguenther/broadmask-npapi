/*
 * GPG Wrapper using GPGME
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
 * UserStorage.cpp
 */

#include "UserStorage.hpp"
#include "utils.h"
#include "gnupg_wrapper.hpp"

#include "boost/lexical_cast.hpp"

// filesystem
#include <boost/filesystem/operations.hpp>
#include <boost/filesystem/path.hpp>
#include <fstream>


using namespace std;
namespace fs = boost::filesystem;



UserStorage::UserStorage() {
    keymap = map<string,string>();
    version = (char *) gpgme_check_version(NULL);
}

UserStorage::~UserStorage() {
    keymap.clear();
}

FB::VariantMap UserStorage::associatedKeys() {
    FB::VariantMap keys;
    for (map<string,string>::iterator it = keymap.begin(); it != keymap.end(); ++it) {
        keys[it->first] = it->second;
    }
    
    return keys;
}



void UserStorage::setPGPKey(string& user_id, string& keyid) {
    keymap.insert(pair<string,string>(user_id, keyid));
}

FB::VariantMap UserStorage::getPGPKey(string& user_id) {
    FB::VariantMap result;
    result["userid"] = user_id;
    
    map<string,string>::iterator it = keymap.find(user_id);
    
    if (it != keymap.end()) {
        result["keyid"] = it->second;
        result["found"] = true;
    } else {
        result["found"] = false;
    }
    
    return result;    
}

FB::VariantMap UserStorage::encrypt_for(std::string& data, std::string& user_id) {
    std::map<std::string, std::string>::iterator it = keymap.find(user_id);
    
    if (it != keymap.end()) {
        return gpgme_encrypt_with(data, it->second);
    } else {
        FB::VariantMap output;
        output["error"] = true;
        output["key_missing"] = true;
        output["error_msg"] = "User has no corresponding key";
        return output;
    }
    
}

void UserStorage::removePGPKey(string& user_id) {
    keymap.erase(user_id);
}



void UserStorage::archive(UserStorage *us) {
    fs::path storage = broadmask_root() / "userstorage";
    std::ofstream ofs(storage.string().c_str(), std::ios::out);
    boost::archive::text_oarchive oa(ofs);
    
    try {
        oa << *us;
    } catch (exception& e) {
        cout << e.what() << endl;
    }    
}

UserStorage* UserStorage::unarchive() {
    UserStorage *ustore = new UserStorage();
    fs::path storage = broadmask_root() / "userstorage";
    if (fs::is_regular_file(storage)) {
        std::ifstream ifs(storage.string().c_str(), std::ios::in);
        boost::archive::text_iarchive ia(ifs);
        
        try {
            ia >> *ustore;
        } catch (exception& e) {
            cout << e.what() << endl;
        }
    }
    
    return ustore;
}