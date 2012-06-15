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


#include "InstanceStorage.hpp"


class ProfileManager  {
    
public:
    ~ProfileManager();
    
    FB::VariantMap get_stored_profiles();
    
    InstanceStorage* unlock_profile(std::string profilename);
    
    void store_profile(std::string profilename, InstanceStorage* istore);
    
    std::istream& unlock_file(std::string path);
    
    void add_profile(std::string name, std::string keyid) {
        profiles.insert(std::pair<std::string, std::string>
                        (name, keyid));
    }
    
    
    static void archive(ProfileManager *p);
    static ProfileManager* unarchive();
    
    
private:
       
    // Stored profiles, name -> PGP key id
    std::map<std::string, std::string> profiles;
    
    
    // Caches previously used profile
    std::string active_profile;
    
    // Caches the domain on which user requests have been performed
    std::string active_domain;

    
    
    //
    // Boost class serialization, independent from BES serialization
    //
    friend class boost::serialization::access;
    template<class Archive>
    void serialize(Archive & ar, const unsigned int version)
    {
        ar & profiles;
    }
};

#endif