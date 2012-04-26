#include "BES_receiver.hpp"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <cmath>
#include <fstream>

#include <cryptopp/osrng.h>
using CryptoPP::AutoSeededRandomPool;

#include <iostream>
using std::cout;
using std::cerr;
using std::endl;

#include <string>
using std::string;

#include <cstdlib>
using std::exit;

#include <cryptopp/cryptlib.h>
using CryptoPP::Exception;

#include <cryptopp/hex.h>
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

#include <cryptopp/filters.h>
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;

#include <cryptopp/aes.h>
using CryptoPP::AES;

#include <cryptopp/modes.h>
using CryptoPP::CFB_Mode;

// hkdf scheme, rfc5869
#include "hkdf.h"
using CryptoPP::HMACKeyDerivationFunction;
#include <cryptopp/sha.h>
using CryptoPP::SHA256;

#include "utils.h"

namespace fs = boost::filesystem;
using namespace std;


BES_receiver::BES_receiver(string groupid, int max_users, string public_data, string private_key) : Instance(groupid) {
    
    cout << "Setting up " << gid << " as decryption system" << endl;    
    
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
        cerr << e.what() << endl;
        return 0;
    }
    
}

string BES_receiver::bes_decrypt(bes_ciphertext_t& cts) {
    

    
    
    element_t raw_key;
    get_decryption_key(raw_key, gbs, cts->receivers, cts->num_receivers, SK->id, SK->privkey, cts->HDR, PK);
    
    
    unsigned char *derived_key = (unsigned char*) malloc(keylen * sizeof(unsigned char));
    derivate_decryption_key(derived_key, raw_key);

	try {
        string plaintext;
		CFB_Mode< AES >::Decryption d;
		d.SetKeyWithIV(derived_key, keylen, cts->iv, AES::BLOCKSIZE);
        
        string cipher(reinterpret_cast<char const*>(cts->ct), cts->ct_length);        
		StringSource s(cipher, true, new StreamTransformationFilter(d, new StringSink(plaintext)));
        delete[] derived_key;
        return plaintext;
        
	}
	catch(const CryptoPP::Exception& e) {
        delete[] derived_key;
		cerr << e.what() << endl;
        return "";
        
	}
    
    
    
    
}

int BES_receiver::restore() {
    
    // Restore global parameters
    setup_global_system(&gbs, params, N);
    
    string bcfile = instance_file();

    if (!fs::is_regular_file(bcfile)) {
        cout << "No saved instance of " << gid << endl;
        return 1;
    }
    
    ifstream bcs(bcfile.c_str(), std::ios::in|std::ios::binary);
    
    if (!bcs.good()) {
        cout << "Unable to open instance file" << endl;
        return 1;
    }
    
    
    int version, element_size, sk_id;
    
    bcs >> version;
    bcs >> element_size;
    bcs >> sk_id;
    bcs.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    
    
    // Public Key
    PK = (pubkey_t) pbc_malloc(sizeof(struct pubkey_s));
    
    element_from_stream(PK->g, gbs, bcs, element_size);
    
    int i;
    // g_i
    PK->g_i = (element_t*) pbc_malloc((2 * gbs->B) * sizeof(element_t)); 
    for (i = 0; i < 2*gbs->B; ++i) {
        element_from_stream(PK->g_i[i], gbs, bcs, element_size);
    }
    
    // v_i
    PK->v_i = (element_t*) pbc_malloc(gbs->A * sizeof(element_t));
    for (i = 0; i < gbs->A; ++i) {
        element_from_stream(PK->v_i[i], gbs, bcs, element_size);
    }
    
    
    // Private Key
    SK = (bes_privkey_t) pbc_malloc(sizeof(struct bes_privkey_s));
    
    SK->id = sk_id;
    
    element_from_stream(SK->privkey, gbs, bcs, element_size);
    
    return 0;
    
    
    
}

int BES_receiver::store() {
    string bcfile = instance_file();
    
    cout << "Storing BES to " << bcfile << endl;
    
    
    ofstream os(bcfile.c_str(), std::ios::out|std::ios::binary);
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

    
    return 0;
    
}


string BES_receiver::instance_file() {
    fs::path instance_path = get_instance_path("bes_receiver", gid);
    return instance_path.string();
}



BES_receiver::~BES_receiver() {}