#include "SK_Instance.hpp"
#include <sstream>

#include <cryptopp/aes.h>
using CryptoPP::AES;

#include "cryptlib.h"
using CryptoPP::BufferedTransformation;
using CryptoPP::AuthenticatedSymmetricCipher;

#include "filters.h"
using CryptoPP::Redirector;
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::AuthenticatedEncryptionFilter;
using CryptoPP::AuthenticatedDecryptionFilter;



#include "aes.h"
using CryptoPP::AES;

#include "gcm.h"
using CryptoPP::GCM;
using CryptoPP::GCM_TablesOption;

#include <cryptopp/osrng.h>
using CryptoPP::AutoSeededRandomPool;

#include "Base64.h"


#define IV_LENGTH 12
#define TAG_SIZE 12
#define AES_DEFAULT_KEYSIZE 32

SK_Instance::SK_Instance(std::string groupid) : Instance(groupid) {
    
    // Default is 256bit key
    keylen = AES_DEFAULT_KEYSIZE;
    
    // Create random key
    key.resize(keylen);
    AutoSeededRandomPool prng;
	prng.GenerateBlock(&key[0], keylen);
    
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
}


FB::VariantMap SK_Instance::encrypt(std::string plaintext) {
    
    FB::VariantMap result;
    try {
        
        
        // Generate random IV
        unsigned char iv[IV_LENGTH];
        AutoSeededRandomPool prng;
        prng.GenerateBlock(iv, IV_LENGTH);
        
        
        std::vector<unsigned char> iv_vec;
        std::copy (iv, iv + IV_LENGTH, std::back_inserter(iv_vec)); 
        
        result["iv"] = base64_encode(iv_vec);
        
        GCM< AES >::Encryption e;
        e.SetKeyWithIV(&key[0], keylen, iv, IV_LENGTH);
        
        std::string cipher;
        StringSource(plaintext, true,
                     new AuthenticatedEncryptionFilter( e,
                                                       new StringSink( cipher ), false, TAG_SIZE
                                                       )
                     );
        
        result["ciphertext"] = base64_encode(cipher);
        
        
        
    } catch( CryptoPP::Exception& e )  {
        result["error"] = true;
        result["error_msg"] = e.what();
    }
}


FB::VariantMap SK_Instance::decrypt(FB::JSObjectPtr params) {
    
    FB::VariantMap result;
    
    // Extract IV
    std::string iv_b64 = params->GetProperty("iv").convert_cast<std::string>();
    std::string iv_str = base64_decode(iv_b64);
    
    // Extract ciphertext
    std::string cipher_b64 = params->GetProperty("iv").convert_cast<std::string>();
    std::string cipher = base64_decode(cipher_b64);
    
    unsigned char iv[IV_LENGTH];
    memcpy(iv, iv_str.c_str(), IV_LENGTH);
    

    std::string r_plaintext;
    
    try
    {
        GCM< AES >::Decryption d;
        d.SetKeyWithIV(&key[0], keylen, iv, IV_LENGTH);
        
        AuthenticatedDecryptionFilter df( d,
                                         new StringSink( r_plaintext ),
                                         AuthenticatedDecryptionFilter::DEFAULT_FLAGS, TAG_SIZE
                                         ); // AuthenticatedDecryptionFilter
        
        // The StringSource dtor will be called immediately
        //  after construction below. This will cause the
        //  destruction of objects it owns. To stop the
        //  behavior so we can get the decoding result from
        //  the DecryptionFilter, we must use a redirector
        //  or manually Put(...) into the filter without
        //  using a StringSource.
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
    catch( CryptoPP::Exception& e )
    {
        result["error"] = true;
        result["error_msg"] = e.what();
    }
    
    result["error"] = true;
    result["error_msg"] = "Incorrect ciphertext";
    return result;
    
}

bool SK_Instance::is_authorized(std::string user_id) {
    std::set<std::string>::iterator it = authorized_users.find(user_id);
    
    if (it != authorized_users.end())
        return true;
    else
        return false;
}

void SK_Instance::add_member(std::string user_id) {
    authorized_users.insert(user_id);
}