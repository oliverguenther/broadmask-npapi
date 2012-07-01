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

// Include AE scheme wrapper
#include "BDEM/ae_wrapper.hpp"
// hkdf scheme, rfc5869
#include <cryptopp/hmac.h>
#include <cryptopp/sha.h>
#include "hkdf.h"

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
    os << AE_KEY_LENGTH << "\n";
    
    public_key_to_stream(sys->PK, gbs, os);
}
    

void BES_sender::bes_encrypt(bes_ciphertext_t *cts, const std::vector<std::string>& receivers, std::string& pdata) {
    
    bes_ciphertext_t ct = new bes_ciphertext_s;
    
    // Ensure myself is added to S
    std::vector<std::string> S (receivers);
    std::vector<std::string>::iterator it = std::find(S.begin(), S.end(), SENDER_MEMBER_ID);
    if (it == S.end())
        S.push_back(SENDER_MEMBER_ID);
    
    // Receivers
    ct->num_receivers = S.size();    
    ct->receivers = new int[ct->num_receivers];
        
    int i = 0;
    for (std::vector<string>::const_iterator it = S.begin(); it != S.end(); ++it) {
        int id = member_id(*it);
        if (id == -1) {
            cout << "Member " << *it << " is not member of this group" << endl;
            delete ct->receivers;
            delete ct;
            
            return;
        }
        ct->receivers[i] = id;
        i++;
    }
    
    // Key generation
    keypair_t keypair;
    get_encryption_key(&keypair, ct->receivers, ct->num_receivers, sys, gbs);
    
    // Copy public header
    ct->HDR = new element_t[gbs->A+1];
    memcpy(ct->HDR, keypair->HDR, (gbs->A+1) * sizeof(element_t));
    
    // Key derivation
    unsigned char sym_key[AE_KEY_LENGTH];
    derivate_encryption_key(sym_key, AE_KEY_LENGTH, keypair->K);
    
    
    // AES encrpytion
    AE_Plaintext* pts = new AE_Plaintext;
    AE_Plaintext* header = new AE_Plaintext;
    
    pts->plaintext = new unsigned char[pdata.size()];
    memcpy(pts->plaintext, reinterpret_cast<const unsigned char*>(pdata.data()), pdata.size());
    pts->len = pdata.size();
    
    // Derive header raw data for authentication
    unsigned char *buf;
    size_t hdr_size = encryption_header_to_bytes(&buf, ct->HDR, gbs->A + 1);
    header->plaintext = buf;
    header->len = hdr_size;
    
    ae_error_t result = encrypt_aead(&ct->ae_ct, sym_key, pts, header);
    delete pts;
    delete header;
    
    if (result.error) {
        delete[] ct->receivers;
        delete[] ct->HDR;
        delete ct;
        
    }
    
    *cts = ct;
}

FB::VariantMap BES_sender::bes_decrypt(bes_ciphertext_t& cts) {
    
    element_t raw_key;
    get_decryption_key(raw_key, gbs, cts->receivers, cts->num_receivers, SK->id, SK->privkey, cts->HDR, sys->PK);
    
    unsigned char derived_key[AE_KEY_LENGTH];
    derivate_encryption_key(derived_key, AE_KEY_LENGTH, raw_key);
    
    cout << endl << "THIS IS BES SENDER" << endl;
    for (int i = 0; i < AE_KEY_LENGTH; ++i) {
        cout << std::hex << (int) derived_key[i] << " ";
    }

    
    AE_Plaintext* pts;
    AE_Plaintext* header = new AE_Plaintext;
    
    
    // Derive header raw data for authentication
    header->len = encryption_header_to_bytes(&header->plaintext, cts->HDR, gbs->A + 1);
    
    ae_error_t result = decrypt_aead(&pts, derived_key, cts->ae_ct, header);    
    FB::VariantMap rm;
    
    rm["error"] = result.error;
    if (result.error) {
        rm["error_msg"] = result.error_msg;
    } else {
        rm["result"] = std::string(reinterpret_cast<const char*>(pts->plaintext), pts->len);
        delete pts;
    }
    
    delete header;
    
    return rm;
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

void BES_sender::restore() {
    
    std::stringstream is (stored_state);
    
    // Restore global parameters
    setup_global_system(&gbs, params, N);
      
    if (!is.good()) {
        cout << "Unable to open instance file" << endl;
        return;
    }
    
    
    int version, element_size;
    
    is >> version;
    is >> element_size;
    is.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    
    
    // System
    sys = (bkem_system_t) pbc_malloc(sizeof(struct bkem_system_s));
    
    // Public Key
    sys->PK = (pubkey_t) pbc_malloc(sizeof(struct pubkey_s));
    
    element_from_stream(sys->PK->g, gbs, is, element_size);
    
    int i;
    // g_i
    sys->PK->g_i = (element_t*) pbc_malloc((2 * gbs->B) * sizeof(element_t)); 
    for (i = 0; i < 2*gbs->B; ++i) {
        element_from_stream(sys->PK->g_i[i], gbs, is, element_size);
    }
    
    // v_i
    sys->PK->v_i = (element_t*) pbc_malloc(gbs->A * sizeof(element_t));
    for (i = 0; i < gbs->A; ++i) {
        element_from_stream(sys->PK->v_i[i], gbs, is, element_size);
    }
    
    // Restore private keys
    sys->d_i = (element_t*) pbc_malloc(gbs->N * sizeof(element_t));        
    for (i = 0; i < (int) N; ++i) {
        element_from_stream(sys->d_i[i], gbs, is, element_size);
    }
    
    // Restore my own private key
    private_key_from_stream(&SK, gbs, is, element_size);
       
}

void BES_sender::store() {
    
    std::ostringstream os;
    
    
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
    
    stored_state.clear();
    stored_state = os.str();
    os.clear();
}

  
    
BES_sender::~BES_sender() {
    free_bkem_system(sys, gbs);
    availableIDs.clear();
    members.clear();
    stored_state.clear();
}
