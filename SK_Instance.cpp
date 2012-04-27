#include "SK_Instance.hpp"
#include <sstream>

#include <cryptopp/aes.h>
using CryptoPP::AES;

#include <cryptopp/cryptlib.h>
using CryptoPP::BufferedTransformation;
using CryptoPP::AuthenticatedSymmetricCipher;

#include <cryptopp/filters.h>
using CryptoPP::Redirector;
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::AuthenticatedEncryptionFilter;
using CryptoPP::AuthenticatedDecryptionFilter;

#include <cryptopp/gcm.h>
using CryptoPP::GCM;
using CryptoPP::GCM_TablesOption;

#include <cryptopp/osrng.h>
using CryptoPP::AutoSeededRandomPool;

#include <boost/filesystem/operations.hpp>
#include <boost/filesystem/path.hpp>


#include "Base64.h"
#include "utils.h"


#define AES_IV_LENGTH 12
#define TAG_SIZE 12
#define AES_DEFAULT_KEYSIZE 32

SK_Instance::SK_Instance(std::string groupid) : Instance(groupid) {
    
    // Default is 256bit key
    keylen = AES_DEFAULT_KEYSIZE;
    members = std::map<std::string, int>();
    
    // Create random key
    AutoSeededRandomPool prng;
    unsigned char buf[keylen];
	prng.GenerateBlock(buf, keylen);
    key.assign(buf, buf + keylen);
    
    
}

SK_Instance::SK_Instance(std::string groupid, std::string key_b64, int keysize) : Instance(groupid) {
    
    // Copy key
    std::string key_str = base64_decode(key_b64);
    
    keylen = keysize;
    key.clear();
    
    std::stringstream ss(key_str);
    unsigned char b;
    
    while (ss >> b)
        key.push_back(b);
        
}


SK_Instance::~SK_Instance() {
    key.clear();
    members.clear();
}


FB::VariantMap SK_Instance::encrypt(std::string plaintext) {
    
    
    sk_ciphertext_t sk_ct = (sk_ciphertext_t) malloc(sizeof(struct sk_ciphertext_s));
    
    FB::VariantMap result;
    try {
        
        
        // Generate random IV
        sk_ct->iv = (unsigned char*) malloc(AES_IV_LENGTH * sizeof(unsigned char));
        AutoSeededRandomPool prng;
        prng.GenerateBlock(sk_ct->iv, AES_IV_LENGTH);
        
        GCM< AES >::Encryption e;
        e.SetKeyWithIV(&key[0], keylen, sk_ct->iv, AES_IV_LENGTH);
        
        std::string cipher;
        StringSource(plaintext, true,
                     new AuthenticatedEncryptionFilter( e,
                                                       new StringSink( cipher ), false, TAG_SIZE
                                                       )
                     );
        
        sk_ct->ct = (unsigned char*) malloc(cipher.size() * sizeof(unsigned char));
        sk_ct->ct_length = cipher.size();
        memcpy(sk_ct->ct, cipher.c_str(), sk_ct->ct_length);  
        
        result["success"] = true;
        std::stringstream ss;
        sk_ciphertext_to_stream(sk_ct, ss);
        result["ciphertext"] = ss.str();
        free_sk_ciphertext(sk_ct);
        
    } catch( exception& e )  {
        result["error"] = true;
        result["error_msg"] = e.what();
        free_sk_ciphertext(sk_ct);
        return result;
    }
    return result; 
}


FB::VariantMap SK_Instance::decrypt(sk_ciphertext_t sk_ct) {
    
    FB::VariantMap result;
    std::string r_plaintext;
    
    try {
        GCM< AES >::Decryption d;
        d.SetKeyWithIV(&key[0], keylen, sk_ct->iv, AES_IV_LENGTH);
        
        string cipher(reinterpret_cast<char const*>(sk_ct->ct), sk_ct->ct_length);        
        
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
    }
    catch( CryptoPP::Exception& e ) {
        result["error"] = true;
        result["error_msg"] = e.what();
    }
    
    result["error"] = true;
    result["error_msg"] = "Incorrect ciphertext";
    return result;
    
}




std::string SK_Instance::instance_file() {
    boost::filesystem::path instance_path = get_instance_path("sk", gid);
    return instance_path.string();
}