/**********************************************************\

  Auto-generated BroadmaskAPI.cpp

  \**********************************************************/

#include <iostream>
#include <sstream>
#include <cmath>

#include <boost/timer.hpp>
#include <boost/filesystem/operations.hpp>
#include <boost/filesystem/path.hpp>
#include <boost/filesystem/fstream.hpp> 


#include "JSObject.h"
#include "variant_list.h"
#include "DOM/Document.h"
#include "global/config.h"
#include "BroadmaskAPI.h"

#include <gmpxx.h>

using namespace std;


/** Load the BES instance with the GID or create one if non-existant
 *
 * @param gid Group identifier
 * @param N User count
 */
void BroadmaskAPI::invokeInstance(string gid, int N) {
    
    map<string,BCInstance>::iterator it = instances.find(gid);
    
    if (it != instances.end()) {
        cout << "Instance " << gid << " is already loaded" << endl;
        return;
    }
    
    BCInstance bci = BCInstance(gid, N);    
    instances.insert( pair<string, BCInstance>(gid, bci) );
    
    bci.store(false);
              
}

void BroadmaskAPI::loadInstance(string gid) {
    

}

///////////////////////////////////////////////////////////////////////////////
BroadmaskPtr BroadmaskAPI::getPlugin()
{
	BroadmaskPtr plugin(m_plugin.lock());
	if (!plugin) {
		throw FB::script_error("The plugin is invalid");
	}
	return plugin;
}
