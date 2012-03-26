#include "utils.h"
#include <iostream>
#include <utility>

namespace fs = boost::filesystem;
using namespace std;


fs::path broadmask_root() {
    fs::path broadmask_dir(fs::path(getenv("HOME")) / ".broadmask");

    if(!fs::is_directory(broadmask_dir)) {
        fs::create_directory(broadmask_dir);
    }

    return broadmask_dir;
    
    

}

fs::path instance_dir(string &gid) {
    fs::path instance_dir = (broadmask_root() / "instances") / gid;
    
    if(!fs::is_directory(instance_dir)) {
        fs::create_directory(instance_dir);
    }
    
    return instance_dir;
}

fs::path get_instance_file(string gid, string file) {

    fs::path instance = instance_dir(gid);
    
    instance /= file;
    
    cout << "Path is " << instance.string() << " - exists? " << fs::is_regular_file(file) << endl;
    return instance;
    
}


pair< vector<string>, vector<string> > stored_instances() {
    
    vector<string> receiver, sender;
    
    fs::path instance = broadmask_root() / "instances";
    fs::directory_iterator end_itr;

    for( fs::directory_iterator i(instance); i != end_itr; ++i ) {
        
        // Skip if not directory
        if(!fs::is_directory(instance)) 
            continue;
        
        // Check for sender/receiving instance
        fs::path spath = instance / "sender";
        fs::path rpath = instance / "receiver"; 
        
        if (fs::is_regular_file(spath))
            sender.push_back(spath.string());

        if (fs::is_regular_file(rpath))
            sender.push_back(rpath.string());

        
    }
    
    
    return make_pair(sender, receiver);
    
}

template<class T>
void vector_from_stream(std::vector<T>& v, std::istream& is) {
    T el;
    while (is >> el) {
        v.push_back(el);
    }
}
