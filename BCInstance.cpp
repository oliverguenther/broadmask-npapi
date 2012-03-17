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
#include <iostream>
#include <sstream>
#include <iomanip>
#include <cmath>
#include <boost/timer.hpp>
#include <fstream>


namespace fs = boost::filesystem;
using namespace std;

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
       
    // Setup global params
    setup_global_system(&gbs, params, N);
    
    if (restore()) {
        // setup new instance
        cout << "Setting up new BCInstance: " << groupID << endl;
        setup(&sys, gbs);
    }
    
   
    boost::timer total;
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
        keypair_t keypair;
        get_encryption_key(&keypair, S, c, sys, gbs);
        element_t K;

        
        for (j = 0; j < N; ++j) {
            get_decryption_key(K, gbs, S, c, j, sys->d_i[j], keypair->HDR, sys->PK);
            if (!element_cmp(keypair->K, K)) {
                if (j >= c)
                    printf("ERROR: Decryption Key for [User %d] matches, but should NOT\n", j);       
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

void BCInstance::element_from_stream(element_t el, std::ifstream& is, int numbytes) {
    
    unsigned char buf[numbytes];
    
    is.read(reinterpret_cast<char*>(buf), numbytes);
    element_init_G1(el, gbs->pairing);
    element_from_bytes(el, buf);
    
}


void BCInstance::element_to_stream(element_t el, std::ofstream& os) {
    int numbytes = element_length_in_bytes(el);
    unsigned char buf[numbytes];
    element_to_bytes(buf, el);
    os.write(reinterpret_cast<char*>(buf), numbytes);
    
}



int BCInstance::restore() {
    fs::path *bcfile = instance_path(gid);
            
    if (!fs::is_regular_file(*bcfile)) {
        cout << "No saved instance of " << gid << endl;
        return 1;
    }
    
    ifstream bcs(bcfile->string().c_str(), std::ios::in|std::ios::binary);
    
    if (!bcs.good()) {
        cout << "Unable to open instance file" << endl;
        return 1;
    }
        
    
    int version, element_size;
    
    bcs >> version;
    bcs >> element_size;
    bcs.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
          
    
    // System
    sys = (bes_system_t) pbc_malloc(sizeof(struct bes_system_s));
    
    // Public Key
    sys->PK = (pubkey_t) pbc_malloc(sizeof(struct pubkey_s));
    
    element_from_stream(sys->PK->g, bcs, element_size);
    
    int i;
    // g_i
    sys->PK->g_i = (element_t*) pbc_malloc((2 * gbs->B) * sizeof(element_t)); 
    for (i = 0; i < 2*gbs->B; ++i) {
        element_from_stream(sys->PK->g_i[i], bcs, element_size);
    }
    
    // v_i
    sys->PK->v_i = (element_t*) pbc_malloc(gbs->A * sizeof(element_t));
    for (i = 0; i < gbs->A; ++i) {
        element_from_stream(sys->PK->v_i[i], bcs, element_size);
    }
    
    // Store private keys
    sys->d_i = (element_t*) pbc_malloc(gbs->N * sizeof(element_t));        
    for (i = 0; i < (int) N; ++i) {
        element_from_stream(sys->d_i[i], bcs, element_size);
    }
    
    return 0;
            
    
    
}

int BCInstance::store(bool force) {
    fs::path *bcfile = instance_path(gid);
    
    if (fs::is_regular_file(*bcfile) && !force) {
        cout << "BES already stored" << endl;
        return 0;
    }
    cout << "Storing BES" << endl;
    

    ofstream os(bcfile->string().c_str(), std::ios::out|std::ios::binary);
    int version = 0;
    int element_size = element_length_in_bytes(sys->PK->g);
    
    os << version << " ";
    os << element_size << endl;

    // Store Public Key
    // g
    element_to_stream(sys->PK->g, os);
    
    int i;
    // g_i
    for (i = 0; i < 2*gbs->B; ++i) {
        element_to_stream(sys->PK->g_i[i], os);
    }
    
    // v_i
    for (i = 0; i < gbs->A; ++i) {
        element_to_stream(sys->PK->v_i[i], os);
    }
    
    // Store private keys
    for (i = 0; i < (int) N; ++i) {
        element_to_stream(sys->d_i[i], os);
    }
    return 0;

}

fs::path* BCInstance::instance_path(string &gid) {
    fs::path home_dir(fs::path(getenv("HOME")));
    
    if (!fs::is_directory(home_dir)) {
        return NULL;
    } else {
        fs::path broadmask_dir(home_dir / ".broadmask");
        
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
