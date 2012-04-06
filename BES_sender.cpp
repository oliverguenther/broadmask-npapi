#include "BES_sender.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <cmath>
#include <fstream>
#include <algorithm>
#include <utility>

#include <boost/filesystem/operations.hpp>
#include <boost/filesystem/path.hpp>

// hkdf scheme, rfc5869
#include <cryptopp/hmac.h>
#include <cryptopp/hkdf.h>
#include <cryptopp/sha.h>

#include <cryptopp/filters.h>
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;

#include <cryptopp/aes.h>
using CryptoPP::AES;

#include <cryptopp/modes.h>
using CryptoPP::CFB_Mode;

#include <cryptopp/cryptlib.h>
using CryptoPP::Exception;

#include <cryptopp/osrng.h>
using CryptoPP::AutoSeededRandomPool;


#include "utils.h"

namespace fs = boost::filesystem;
using namespace std;

const int kDerivedKeysize = 32; // bytes

struct inc_index {
    int cur;
    inc_index() {cur=0;}
    int operator()() {return cur++;}
} FillIndex;

BES_sender::BES_sender(string gid, int num_users) : BES_base(gid, num_users) {
    cout << "Setting up " << gid << " as encryption system" << endl;    
    setup(&sys, gbs);
    
    // Initially, all ids are available
    availableIDs.resize(num_users);
    generate(availableIDs.begin(), availableIDs.end(), FillIndex);
    
}

BES_sender::BES_sender(const BES_sender& b) {
    
    N = b.N;
    gid = b.gid;
    sys = b.sys;
    users = b.users;
    availableIDs = b.availableIDs;
    setup_global_system(&gbs, params, N);
}

int BES_sender::add_member(std::string id) {

    int current_id = member_id(id);
    if (current_id != -1)
        return current_id;
    
    if (availableIDs.empty())
        return -1;
    
    int sys_id = availableIDs.front();
    availableIDs.pop_front();
    
    users.insert(pair<string, int> (id, sys_id));
    return sys_id;    
}


void BES_sender::remove_member(std::string id) {
    map<string, int>::iterator it = users.find(id);
    
    if (it != users.end()) {
        availableIDs.push_back(it->second);
        users.erase(it);        
    }
}

int BES_sender::member_id(std::string id) {
    map<string, int>::iterator it = users.find(id);
    
    if (it != users.end()) {
        return it->second;     
    } else {
        return -1;
    }
}

void BES_sender::get_private_key(bes_privkey_t* sk_ptr, std::string userID) {
    int id = member_id(userID);
    if (id == -1)
        return;
    
    bes_privkey_t sk = (bes_privkey_t) pbc_malloc(sizeof(struct bes_privkey_s));
    sk->id = id;
    memcpy(sk->privkey, sys->d_i[id], sizeof(element_t));
    
    *sk_ptr = sk;
}


void BES_sender::public_params_to_stream(std::ostream& os) {
    int element_size = element_length_in_bytes(sys->PK->g);
    os << element_size << " ";
    os << kDerivedKeysize << "\n";
    
    public_key_to_stream(sys->PK, os);
}
    

void BES_sender::bes_encrypt(bes_ciphertext_t *cts, std::vector<string>& S, std::string& data) {
    
    bes_ciphertext_t ct = (bes_ciphertext_t) malloc(sizeof(struct bes_ciphertext_s));
    
    // Receivers
    ct->num_receivers = S.size();
    
    ct->receivers = (int *) malloc(ct->num_receivers * sizeof(int));
        
    int i = 0;
    for (vector<string>::iterator it = S.begin(); it != S.end(); ++it) {
        int id = member_id(*it);
        if (id == -1) {
            cout << "Member " << *it << " is not member of this group" << endl;
            free(ct->receivers);
            return;
        }
        ct->receivers[i] = id;
        i++;
    }
    
    // Key generation
    keypair_t keypair;
    get_encryption_key(&keypair, ct->receivers, ct->num_receivers, sys, gbs);
    

    // HDR
    ct->HDR = (element_t*) pbc_malloc( (gbs->A+1) * sizeof(element_t));
    memcpy(ct->HDR, keypair->HDR, (gbs->A+1) * sizeof(element_t));
    
    // Key derivation
    unsigned char sym_key[kDerivedKeysize];
    derivate_encryption_key(sym_key, kDerivedKeysize, keypair->K);
        
    // AES encrpytion    

    // IV
    ct->iv = (unsigned char*) malloc(AES::BLOCKSIZE * sizeof(unsigned char));
    AutoSeededRandomPool prng;
	prng.GenerateBlock(ct->iv, sizeof(ct->iv));

    try {
		CFB_Mode< AES >::Encryption enc;
		enc.SetKeyWithIV(sym_key, sizeof(sym_key), ct->iv, AES::BLOCKSIZE);
        string cipher;
		StringSource(data, true, new StreamTransformationFilter(enc, new StringSink(cipher)));
                
        ct->ct = (unsigned char*) malloc(cipher.size() * sizeof(unsigned char));
        ct->ct_length = cipher.size();
        memcpy(ct->ct, cipher.c_str(), ct->ct_length);  
        *cts = ct;
        
	} catch(const CryptoPP::Exception& e) {
		cerr << e.what() << endl;
        ct = NULL;
	}
    
}


void BES_sender::derivate_encryption_key(unsigned char *key, size_t keylen, element_t bes_key) {

    int keysize = element_length_in_bytes(bes_key);
    unsigned char *buf = new unsigned char[keysize];
    
    element_to_bytes(buf, bes_key);
    
    const byte salt[53] = {
        0x42, 0x72, 0x6F, 0x61, 0x64, 0x6D, 0x61, 0x73, 0x6B, 0x20, 0x2D, 0x20, 0x43, 0x6F, 0x6E, 0x74, 0x65, 0x6E, 0x74, 0x20, 
        0x48, 0x69, 0x64, 0x69, 0x6E, 0x67, 0x20, 0x69, 0x6E, 0x20, 0x4F, 0x6E, 0x6C, 0x69, 0x6E, 0x65, 0x20, 0x53, 0x6F, 0x63, 
        0x69, 0x61, 0x6C, 0x20, 0x4E, 0x65, 0x74, 0x77, 0x6F, 0x72, 0x6B, 0x73, 0x0A
    };
    
    CryptoPP::HMACKeyDerivationFunction<CryptoPP::SHA256> hkdf;
    hkdf.DeriveKey(
                   key, keylen, // Derived key
                   (const byte*) buf, keysize, // input key material (ikm)
                   salt, 53, // Salt
                   NULL, 0 // context information
                   );
}

int BES_sender::restore() {
    
    // Restore global parameters
    setup_global_system(&gbs, params, N);
    
    fs::path bcfile = get_instance_file(gid, "bes_sender");
    
    if (!fs::is_regular_file(bcfile)) {
        cout << "No saved instance of " << gid << endl;
        return 1;
    }
    
    ifstream bcs(bcfile.string().c_str(), std::ios::in|std::ios::binary);
    
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

int BES_sender::store(bool force) {
    fs::path bcfile = get_instance_file(gid, "bes_sender");
    
    if (fs::is_regular_file(bcfile) && !force) {
        cout << "BES already stored" << endl;
        return 0;
    }
    cout << "Storing BES to " << bcfile.string() << endl;
    
    
    ofstream os(bcfile.string().c_str(), std::ios::out|std::ios::binary);
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

string BES_sender::instance_file() {
    fs::path bcfile = get_instance_file(gid, "bes_sender");
    return bcfile.string();
}

    
    
BES_sender::~BES_sender() {}
