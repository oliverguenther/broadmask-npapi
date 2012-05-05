#include "BES_sender.hpp"
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
#include <cryptopp/sha.h>
#include "hkdf.h"

#include <cryptopp/filters.h>
using CryptoPP::Redirector;
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::AuthenticatedEncryptionFilter;
using CryptoPP::AuthenticatedDecryptionFilter;

#include <cryptopp/aes.h>
using CryptoPP::AES;

#include <cryptopp/gcm.h>
using CryptoPP::GCM;
using CryptoPP::GCM_TablesOption;

#include <cryptopp/cryptlib.h>
using CryptoPP::Exception;
using CryptoPP::BufferedTransformation;
using CryptoPP::AuthenticatedSymmetricCipher;

#include <cryptopp/osrng.h>
using CryptoPP::AutoSeededRandomPool;


#define AES_IV_LENGTH 12
#define TAG_SIZE 12
#define AES_DEFAULT_KEYSIZE 32
#define SENDER_MEMBER_ID "myself"

#include "utils.h"

namespace fs = boost::filesystem;
using namespace std;

/**
 * struct for the std::generate method to produce
 * free identifiers from 1 to N-1
 */
struct inc_index {
    int cur;
    inc_index() {cur=0;}
    int operator()() {return cur++;}
} FillIndex;

BES_sender::BES_sender(string gid, int num_users) : Instance(gid) {
    
    
    N = num_users;
    members = std::map<std::string, int>();
    setup_global_system(&gbs, params, num_users);
    
    
    setup(&sys, gbs);
    
    // Initially, all ids are available
    availableIDs.resize(num_users);
    generate(availableIDs.begin(), availableIDs.end(), FillIndex);
    
    // Add myself as 0. user
    add_member(SENDER_MEMBER_ID);
    get_private_key(&SK, SENDER_MEMBER_ID);
    
}

BES_sender::BES_sender(const BES_sender& b) {
    
    N = b.N;
    members = b.members;
    gid = b.gid;
    sys = b.sys;
    SK = b.SK;
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
    
    members.insert(pair<string, int> (id, sys_id));
    return sys_id;    
}


void BES_sender::remove_member(std::string id) {
    map<string, int>::iterator it = members.find(id);
    
    if (it != members.end()) {
        availableIDs.push_back(it->second);
        members.erase(it);        
    }
}

int BES_sender::member_id(std::string id) {
    map<string, int>::iterator it = members.find(id);
    
    if (it != members.end()) {
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
    
    element_init(sk->privkey, gbs->pairing->G1);
	element_set(sk->privkey, sys->d_i[id]);
    
    *sk_ptr = sk;
}


void BES_sender::public_params_to_stream(std::ostream& os) {
    int element_size = element_length_in_bytes(sys->PK->g);
    os << element_size << " ";
    os << AES_DEFAULT_KEYSIZE << "\n";
    
    public_key_to_stream(sys->PK, gbs, os);
}
    

void BES_sender::bes_encrypt(bes_ciphertext_t *cts, const std::vector<std::string>& receivers, std::string& data) {
    
    bes_ciphertext_t ct = (bes_ciphertext_t) malloc(sizeof(struct bes_ciphertext_s));
    
    // Ensure myself is added to S
    std::vector<std::string> S (receivers);
    std::vector<std::string>::iterator it = std::find(S.begin(), S.end(), "myself");
    if (it == S.end())
        S.push_back(SENDER_MEMBER_ID);
    
    // Receivers
    ct->num_receivers = S.size();
    
    ct->receivers = (int *) malloc(ct->num_receivers * sizeof(int));
        
    int i = 0;
    for (std::vector<string>::const_iterator it = S.begin(); it != S.end(); ++it) {
        int id = member_id(*it);
        if (id == -1) {
            cout << "Member " << *it << " is not member of this group" << endl;
            free(ct->receivers);
            free(ct);
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
    unsigned char sym_key[AES_DEFAULT_KEYSIZE];
    derivate_encryption_key(sym_key, AES_DEFAULT_KEYSIZE, keypair->K);
    
    // AES encrpytion    

    // IV
    ct->iv = (unsigned char*) malloc(AES_IV_LENGTH * sizeof(unsigned char));
    AutoSeededRandomPool prng;
	prng.GenerateBlock(ct->iv, AES_IV_LENGTH);

    try {
		GCM< AES >::Encryption e;
		e.SetKeyWithIV(sym_key, sizeof(sym_key), ct->iv, AES_IV_LENGTH);
        string cipher;
        StringSource(data, true,
                     new AuthenticatedEncryptionFilter( e,
                                                       new StringSink( cipher ), false, TAG_SIZE
                                                       )
                     );
                
        ct->ct = (unsigned char*) malloc(cipher.size() * sizeof(unsigned char));
        ct->ct_length = cipher.size();
        memcpy(ct->ct, cipher.c_str(), ct->ct_length);  
        *cts = ct;        
        
	} catch(const CryptoPP::Exception& e) {
		cerr << "HKDF enc error" << e.what() << endl;
        ct = NULL;
	}
    
}

FB::VariantMap BES_sender::bes_decrypt(bes_ciphertext_t& cts) {
    
    element_t raw_key;
    get_decryption_key(raw_key, gbs, cts->receivers, cts->num_receivers, SK->id, SK->privkey, cts->HDR, sys->PK);
    
    unsigned char derived_key[AES_DEFAULT_KEYSIZE];
    derivate_encryption_key(derived_key, AES_DEFAULT_KEYSIZE, raw_key);

    
    FB::VariantMap result;
    
	try {
        string r_plaintext;
        GCM< AES >::Decryption d;
		d.SetKeyWithIV(derived_key, AES_DEFAULT_KEYSIZE, cts->iv, AES_IV_LENGTH);
        
        string cipher(reinterpret_cast<char const*>(cts->ct), cts->ct_length);        
        AuthenticatedDecryptionFilter df( d,
                                         new StringSink( r_plaintext ),
                                         AuthenticatedDecryptionFilter::DEFAULT_FLAGS, TAG_SIZE
                                         ); // AuthenticatedDecryptionFilter
        
        StringSource( cipher, true,
                     new Redirector( df /*, PASS_EVERYTHING */ )
                     ); // StringSource
        
        // If the object does not throw, here's the only
        //  opportunity to check the data's integrity
        if( true == df.GetLastResult() ) {
            result["plaintext"] = r_plaintext;
            return result;
        }
        
	} catch(const CryptoPP::Exception& e) {
        result["error"] = true;
        result["error_msg"] = e.what();
	}
    
    result["error"] = true;
    result["error_msg"] = "Invalid ciphertext";
    return result;
    
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
    
    delete[] buf;
}

int BES_sender::restore() {
    
    // Restore global parameters
    setup_global_system(&gbs, params, N);
    
    string bcfile = instance_file();
    
    if (!fs::is_regular_file(bcfile)) {
        return 1;
    }
    
    ifstream bcs(bcfile.c_str(), std::ios::in|std::ios::binary);
    
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
    
    element_from_stream(sys->PK->g, gbs, bcs, element_size);
    
    int i;
    // g_i
    sys->PK->g_i = (element_t*) pbc_malloc((2 * gbs->B) * sizeof(element_t)); 
    for (i = 0; i < 2*gbs->B; ++i) {
        element_from_stream(sys->PK->g_i[i], gbs, bcs, element_size);
    }
    
    // v_i
    sys->PK->v_i = (element_t*) pbc_malloc(gbs->A * sizeof(element_t));
    for (i = 0; i < gbs->A; ++i) {
        element_from_stream(sys->PK->v_i[i], gbs, bcs, element_size);
    }
    
    // Restore private keys
    sys->d_i = (element_t*) pbc_malloc(gbs->N * sizeof(element_t));        
    for (i = 0; i < (int) N; ++i) {
        element_from_stream(sys->d_i[i], gbs, bcs, element_size);
    }
    
    // Restore my own private key
    private_key_from_stream(&SK, gbs, bcs, element_size);
    
    
    return 0;
    
    
    
}

int BES_sender::store() {
    string bcfile = instance_file();    
    
    ofstream os(bcfile.c_str(), std::ios::out|std::ios::binary);
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
    
    // Store my own private key
    private_key_to_stream(SK, os);
    
    return 0;
    
}

string BES_sender::instance_file() {
    fs::path instance_path = get_instance_path("bes_sender", gid);
    return instance_path.string();
}

    
    
BES_sender::~BES_sender() {
    free_bes_system(sys, gbs);
    availableIDs.clear();
    members.clear();
}
