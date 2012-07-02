#include "BES_receiver.hpp"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <cmath>
#include <fstream>

#include "BDEM/ae_wrapper.hpp"

// hkdf scheme, rfc5869
#include "hkdf.h"
using CryptoPP::HMACKeyDerivationFunction;
#include <cryptopp/sha.h>
using CryptoPP::SHA256;

#include "utils.h"

namespace fs = boost::filesystem;
using namespace std;


BES_receiver::BES_receiver(string groupid, int max_users, string public_data, string private_key) : Instance(groupid) {

    istringstream public_params(public_data);
    
    int element_size;
    public_params >> element_size;
    public_params >> keylen;
    public_params.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

    N = max_users;
    members = std::map<std::string, int>();
    
    
    setup_global_system(&gbs, params, N);
    
    
    // Read public key
    public_key_from_stream(&PK, gbs, public_params, element_size);
    
    // Read private key
    istringstream skss(private_key);    
    
    private_key_from_stream(&SK, gbs, skss, element_size);
}

int BES_receiver::derivate_decryption_key(unsigned char *key, element_t raw_key) {

    int keysize = element_length_in_bytes(raw_key);
    unsigned char *buf = new unsigned char[keysize];
    
    element_to_bytes(buf, raw_key);
    
    const byte salt[53] = {
        0x42, 0x72, 0x6F, 0x61, 0x64, 0x6D, 0x61, 0x73, 0x6B, 0x20, 0x2D, 0x20, 0x43, 0x6F, 0x6E, 0x74, 0x65, 0x6E, 0x74, 0x20, 
        0x48, 0x69, 0x64, 0x69, 0x6E, 0x67, 0x20, 0x69, 0x6E, 0x20, 0x4F, 0x6E, 0x6C, 0x69, 0x6E, 0x65, 0x20, 0x53, 0x6F, 0x63, 
        0x69, 0x61, 0x6C, 0x20, 0x4E, 0x65, 0x74, 0x77, 0x6F, 0x72, 0x6B, 0x73, 0x0A
    };
    
    try {
    
        CryptoPP::HMACKeyDerivationFunction<SHA256> hkdf;
        hkdf.DeriveKey(
                       (byte*) key, AE_KEY_LENGTH, // Derived key
                       (const byte*) buf, keysize, // input key material (ikm)
                       salt, 53, // Salt
                       NULL, 0 // context information
                       );
        delete[] buf;
        return keysize;
        
    } catch (const CryptoPP::Exception& e) {
        delete[] buf;
        cerr << "HKDF error " << e.what() << endl;
        return 0;
    }
    
}

ae_error_t BES_receiver::bes_decrypt(AE_Plaintext** recovered_pts, bes_ciphertext_t& cts) {
    
    element_t raw_key;
    get_decryption_key(raw_key, gbs, cts->receivers, cts->num_receivers, SK->id, SK->privkey, cts->HDR, PK);
    
    unsigned char derived_key[AE_KEY_LENGTH];
    derivate_decryption_key(derived_key, raw_key);
    
    AE_Plaintext *pts;
    AE_Plaintext *header = new AE_Plaintext;
    
    // Derive header raw data for authentication
    header->len = encryption_header_to_bytes(&header->plaintext, cts->HDR, gbs->A + 1);
    
    ae_error_t result = decrypt_aead(&pts, derived_key, cts->ae_ct, header);    
    
    *recovered_pts = pts;
    delete header;
    
    return result;
}

void BES_receiver::restore() {
    
    std::istringstream is (stored_state);
    
    if (!is.good()) {
        cout << "Unable to restore instance state for " << gid << endl;
    }
    
    
    int version, element_size, sk_id;
    
    is >> version;
    is >> element_size;
    is >> sk_id;
    is.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    
    
    // Public Key
    PK = (pubkey_t) pbc_malloc(sizeof(struct pubkey_s));
    
    element_from_stream(PK->g, gbs, is, element_size);
    
    int i;
    // g_i
    PK->g_i = (element_t*) pbc_malloc((2 * gbs->B) * sizeof(element_t)); 
    for (i = 0; i < 2*gbs->B; ++i) {
        element_from_stream(PK->g_i[i], gbs, is, element_size);
    }
    
    // v_i
    PK->v_i = (element_t*) pbc_malloc(gbs->A * sizeof(element_t));
    for (i = 0; i < gbs->A; ++i) {
        element_from_stream(PK->v_i[i], gbs, is, element_size);
    }
    
    
    // Private Key
    SK = (bes_privkey_t) pbc_malloc(sizeof(struct bes_privkey_s));
    
    SK->id = sk_id;
    
    element_from_stream(SK->privkey, gbs, is, element_size);
}

void BES_receiver::store() {
    
    std::ostringstream os;
    
    int version = 0;
    int element_size = element_length_in_bytes(PK->g);
    
    os << version << " ";
    os << element_size << " ";
    os << SK->id << "\n";
    
    // Store Public Key
    // g
    element_to_stream(PK->g, os);
    
    int i;
    // g_i
    for (i = 0; i < 2*gbs->B; ++i) {
        element_to_stream(PK->g_i[i], os);
    }
    
    // v_i
    for (i = 0; i < gbs->A; ++i) {
        element_to_stream(PK->v_i[i], os);
    }
    
    // Store Private Key
    element_to_stream(SK->privkey, os);
    
    stored_state.clear();
    stored_state = os.str();
    os.clear();
    
}

BES_receiver::~BES_receiver() {
    free_pubkey(PK, gbs);
    delete SK;
    free_global_params(gbs);
    members.clear();
}