#include "SK_Instance.hpp"
#include <sstream>

#include "Base64.h"
#include "utils.h"

#include <cryptopp/osrng.h>
using CryptoPP::AutoSeededRandomPool;


SK_Instance::SK_Instance(std::string groupid) : Instance(groupid) {
    
    members = std::map<std::string, int>();
    
    // Create random key
    AutoSeededRandomPool prng;
    unsigned char buf[AE_KEY_LENGTH];
	prng.GenerateBlock(buf, AE_KEY_LENGTH);
    key.assign(buf, buf + AE_KEY_LENGTH);
    
    
}


SK_Instance::SK_Instance(std::string groupid, std::string key_b64) : Instance(groupid) {
    
    // Clear key
    key.clear();
    
    // Decode key from base64
    key = base64_decode_vec(key_b64);
    
    if (key.size() != AE_KEY_LENGTH) {
        cerr << "Input key unusable, as length was not " << AE_KEY_LENGTH << ", but " << key.size() << endl;
        key.clear();
    }
        
}


SK_Instance::~SK_Instance() {
    key.clear();
    members.clear();
}

std::vector<unsigned char> SK_Instance::get_symmetric_key() {
    return key;
}


ae_error_t SK_Instance::encrypt(AE_Ciphertext** cts, AE_Plaintext* pts) {
    return encrypt_ae(cts, &key[0], pts);
}


ae_error_t SK_Instance::decrypt(AE_Plaintext** pts, AE_Ciphertext* sk_ct) {
    return decrypt_ae(pts, &key[0], sk_ct);    
}