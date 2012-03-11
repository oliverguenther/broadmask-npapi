/* Boneh-Gentry-Waters Broadcast Encryption Scheme
 * General construction
 *
 * Oliver Guenther oliver_g@rbg.informatik.tu-darmstadt.de
 *
 * Depends on some typedefs from the BPC BCE library 
 * http://crypto.stanford.edu/pbc/bce/
 * (Matt Steiner, Ben Lynn)
 *
 */

#include "BCInstance.h"
#include <cmath>
#include <boost/timer.hpp>


using namespace std;
namespace fs = boost::filesystem;

const char* BCInstance::params = 
"type a\n"
"q 8780710799663312522437781984754049815806883199414208211028653399266475630880222957078625179422662221423155858769582317459277713367317481324925129998224791\n"
"h 12016012264891146079388821366740534204802954401251311822919615131047207289359704531102844802183906537786776\n"
"r 730750818665451621361119245571504901405976559617\n"
"exp2 159\n"
"exp1 107\n"
"sign1 1\n"
"sign0 1";

BCInstance::BCInstance(string groupID, unsigned int numUsers) {
    gid = groupID;
    N = numUsers;
    
    fs::path *instance = instance_path(gid);
    if (instance == NULL)
        cout << "Couldn't read home directory. BES won't be saved!" << endl;
    
    if (fs::is_regular_file(*instance)) {
        // restore instance
        
    }
    delete instance;
    
    // Setup global params
    bes_global_params_t gps;
    setup_global_system(&gps, params, N);
    
	bes_system_t sys;
	setup(&sys, gps);
    
    
    boost::timer total, enc, dec;
    unsigned int c,k,j;
    for (c = 2; c <= N; c+=2) {
        //        if (c == 3) return;
        int S[c];
        printf("Testing with S = [ ");
        for (k = 0; k < c; ++k) {
            S[k] = k;
            printf("%d ", k);
        }
        printf("]\n");
        enc.restart();
        keypair_t keypair;
        get_encryption_key(&keypair, S, c, sys, gps);
        cout << "Encryption key computed in " << enc.elapsed() << endl;
        element_t K;
        
        for (j = 0; j < N; ++j) {
            dec.restart();
            get_decryption_key(K, gps, S, c, j, sys->d_i[j], keypair->HDR, sys->PK);
            cout << "Decryption key computed in " << dec.elapsed() << endl;
            if (!element_cmp(keypair->K, K)) {
                if (j >= c)
                    printf("ERROR: Decryption Key for [User %d] matches, but should NOT\n", j);
                else
                    printf("SUCCESS: Decryption Key for [User %d] matches\n", j);            
            } else {
                if (j < c)
                    printf("ERROR: Decryption Key for [User %d] does not match!\n", j);
            }
            element_clear(K);
        }
        free(keypair);
        
    }
    cout << "Time elapsed:" << total.elapsed() << endl;
    
}

fs::path* BCInstance::instance_path(string &gid) {
    fs::path home_dir(fs::path(getenv("HOME")));
    
    if (!fs::is_directory(home_dir)) {
        return NULL;
    } else {
        fs::path broadmask_dir(home_dir / "broadmask");
        
        if(!fs::is_directory(broadmask_dir)) {
            fs::create_directory(broadmask_dir);
        }
        
        fs::path *instance_file = new fs::path(broadmask_dir / gid);
        return instance_file;
        
    }
    
}

string BCInstance::groupid() 
{
	return gid;
}

BCInstance::~BCInstance()
{
}
