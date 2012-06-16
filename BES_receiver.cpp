#include "BES_receiver.hpp"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <cmath>
#include <fstream>

#include <cryptopp/osrng.h>
using CryptoPP::AutoSeededRandomPool;

#include <cryptopp/cryptlib.h>
using CryptoPP::Exception;
using CryptoPP::BufferedTransformation;
using CryptoPP::AuthenticatedSymmetricCipher;
using CryptoPP::DEFAULT_CHANNEL;
using CryptoPP::AAD_CHANNEL;

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

// hkdf scheme, rfc5869
#include "hkdf.h"
using CryptoPP::HMACKeyDerivationFunction;
#include <cryptopp/sha.h>
using CryptoPP::SHA256;

#include "utils.h"

#define AES_IV_LENGTH 12
#define TAG_SIZE 16
#define AES_DEFAULT_KEYSIZE 32

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

BES_receiver::BES_receiver(const BES_receiver& b) {
    N = b.N;
    gid = b.gid;
    members = b.members;
    SK = b.SK;    
    PK = b.PK;    
    keylen = b.keylen;
    setup_global_system(&gbs, params, N);
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
    
        HMACKeyDerivationFunction<SHA256> hkdf;
        hkdf.DeriveKey(
                       (byte*) key, keylen, // Derived key
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

FB::VariantMap BES_receiver::bes_decrypt(bes_ciphertext_t& cts) {
    
    element_t raw_key;
    get_decryption_key(raw_key, gbs, cts->receivers, cts->num_receivers, SK->id, SK->privkey, cts->HDR, PK);
    
    unsigned char derived_key[keylen];
    derivate_decryption_key(derived_key, raw_key);
    
    FB::VariantMap result;

	try {
        string r_plaintext;
        GCM< AES >::Decryption d;
		d.SetKeyWithIV(derived_key, keylen, cts->iv, AES_IV_LENGTH);
        
        /** Determine MAC offset */
        size_t mac_offset = cts->ct_length - TAG_SIZE;
        
        // Setup AE Decryption filter
        AuthenticatedDecryptionFilter df( d, NULL,
                                         AuthenticatedDecryptionFilter::MAC_AT_BEGIN |
                                         AuthenticatedDecryptionFilter::THROW_EXCEPTION, TAG_SIZE );
        
        // Push down MAC data first
        df.ChannelPut( DEFAULT_CHANNEL, (const unsigned char*) cts->ct + mac_offset, TAG_SIZE );
        
        // Get HDR data for authentication
        unsigned char *buf;
        size_t hdr_size = encryption_header_to_bytes(&buf, cts->HDR, gbs->A + 1);
        // Push down HDR as Additional Authenticated Data (AAD) for authentication
        df.ChannelPut( AAD_CHANNEL, (const unsigned char*) buf , hdr_size); 
        free(buf);
        
        // Push down Ciphertext
        df.ChannelPut( DEFAULT_CHANNEL, (const unsigned char*) cts->ct, cts->ct_length - TAG_SIZE);
        
        // END AAD and Regular Channel
        df.ChannelMessageEnd( AAD_CHANNEL );
        df.ChannelMessageEnd( DEFAULT_CHANNEL );
        
        // If the object does not throw, here's the only
        //  opportunity to check the data's integrity
        if( true == df.GetLastResult() ) {
            
            // Retrieve plaintext
            df.SetRetrievalChannel( DEFAULT_CHANNEL );
            size_t n = (size_t)df.MaxRetrievable();
            if( n > 0 ) { 
                unsigned char *recovered = new unsigned char[n];
                df.Get(recovered, n); 
                std::string r_plaintext (reinterpret_cast<char*>(recovered), n);
                result["plaintext"] = r_plaintext;
                result["success"] = true;
                delete[] recovered;
                return result;
            }
        }
        
        result["error"] = true;
        result["error_msg"] = "Invalid ciphertext. Authentication Failed";
        return result;
        
	} catch(const CryptoPP::Exception& e) {
        result["error"] = true;
        result["error_msg"] = e.what();
        return result;
	} 
    
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
    free_bes_privkey(SK);
    free_global_params(gbs);
    members.clear();
}