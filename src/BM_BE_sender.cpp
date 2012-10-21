#include "BM_BE_Sender.hpp"
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

#define SENDER_MEMBER_ID "myself"

#include "utils.h"

namespace fs = boost::filesystem;
using namespace std;

/*
 * struct for the std::generate method to produce
 * free identifiers from 1 to N-1
 */
struct inc_index {
    int cur;
    inc_index() {cur=0;}
    int operator()() {return cur++;}
} FillIndex;

BM_BE_Sender::BM_BE_Sender(string groupid, int num_users) {
    
    gid = groupid;
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
    PK = sys->PK;
    
}

int BM_BE_Sender::add_member(std::string id) {
    
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


void BM_BE_Sender::remove_member(std::string id) {
    map<string, int>::iterator it = members.find(id);
    
    if (it != members.end()) {
        availableIDs.push_back(it->second);
        members.erase(it);
    }
}

int BM_BE_Sender::member_id(std::string id) {
    map<string, int>::iterator it = members.find(id);
    
    if (it != members.end()) {
        return it->second;
    } else {
        return -1;
    }
}

void BM_BE_Sender::get_private_key(bes_privkey_t* sk_ptr, std::string userID) {
    int id = member_id(userID);
    if (id == -1)
        return;
    
    bes_privkey_t sk = (bes_privkey_t) pbc_malloc(sizeof(struct bes_privkey_s));
    sk->id = id;
    
    element_init(sk->privkey, gbs->pairing->G1);
	element_set(sk->privkey, sys->d_i[id]);
    
    *sk_ptr = sk;
}


void BM_BE_Sender::public_params_to_stream(std::ostream& os) {
    int element_size = element_length_in_bytes(sys->PK->g);
    os << element_size << " ";
    os << AE_KEY_LENGTH << "\n";
    
    public_key_to_stream(sys->PK, gbs, os);
}


void BM_BE_Sender::bes_encrypt(bes_ciphertext_t *cts, const std::vector<std::string>& receivers, std::string& pdata) {
    
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
    derivate_decryption_key(sym_key, keypair->K);
    
    
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

void BM_BE_Sender::restore() {
    
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
    public_key_from_stream(&PK, gbs, is, element_size);
    
    // Restore private keys
    sys->d_i = (element_t*) pbc_malloc(gbs->N * sizeof(element_t));
    for (int i = 0; i < (int) N; ++i) {
        element_from_stream(sys->d_i[i], gbs, is, element_size);
    }
    
    // Restore my own private key
    private_key_from_stream(&SK, gbs, is, element_size);
    
}

void BM_BE_Sender::store() {
    
    std::ostringstream os;
    
    
    int version = 0;
    int element_size = element_length_in_bytes(sys->PK->g);
    
    os << version << " ";
    os << element_size << endl;
    
    // Store Public Key
    public_key_to_stream(PK, gbs, os);
    
    // Store private keys
    for (int i = 0; i < (int) N; ++i) {
        element_to_stream(sys->d_i[i], os);
    }
    
    // Store my own private key
    private_key_to_stream(SK, os);
    
    stored_state.clear();
    stored_state = os.str();
    os.clear();
}



BM_BE_Sender::~BM_BE_Sender() {
    free_bkem_system(sys, gbs);
    availableIDs.clear();
    members.clear();
    stored_state.clear();
}
