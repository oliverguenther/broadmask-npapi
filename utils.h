#ifndef H_BROADMASK_UTILS
#define H_BROADMASK_UTILS

// filesystem
#include <boost/filesystem.hpp>
#include <boost/filesystem/operations.hpp>
#include <boost/filesystem/path.hpp>

#include <vector>

using namespace std;


boost::filesystem::path broadmask_root(std::string& gid);
boost::filesystem::path instance_dir(std::string &gid);
    

/**
 * Returns a filename to gid/file within the Broadmask folder
 * @return a boost::filesystem::path to the file <Broadmask-Root>/gid/file
 */
boost::filesystem::path get_instance_file(std::string gid, std::string file);

std::pair< std::vector<std::string>, std::vector<std::string> > stored_instances();


void vector_from_stream(std::vector<unsigned char>& v, std::istream& is);

#endif