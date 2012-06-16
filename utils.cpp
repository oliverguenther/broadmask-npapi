#include "utils.h"
#include <iostream>
#include <sstream>
#include <utility>

namespace fs = boost::filesystem;
using namespace std;

int istream_size(std::istream& is) {
    is.seekg(0, ios::end);
    return is.tellg();
}


fs::path broadmask_root() {
    fs::path broadmask_dir(fs::path(getenv("HOME")) / ".broadmask");

    if(!fs::is_directory(broadmask_dir)) {
        fs::create_directories(broadmask_dir);
    }

    return broadmask_dir;
    
    

}

fs::path instance_dir(string &gid) {
    fs::path instance_dir = (broadmask_root() / "instances");
    instance_dir /= gid;
    
    if(!fs::is_directory(instance_dir)) {
        fs::create_directories(instance_dir);
    }
    
    return instance_dir;
}

fs::path get_instance_file(string gid, string file) {

    fs::path instance = instance_dir(gid);
    
    instance /= file;
    
    return instance;
    
}

fs::path get_instance_path(string type, string instance_id) {
    
    fs::path path = broadmask_root();
    path /= type;
    
    if(!fs::is_directory(path)) {
        fs::create_directories(path);
    }
    
    path /= instance_id;

    
    return path;
    
}
