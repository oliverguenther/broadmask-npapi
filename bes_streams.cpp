#include "bes_streams.hpp"
#include <iostream>

#include <cryptopp/aes.h>
using CryptoPP::AES;

using namespace std;

void element_from_stream(element_t el, bes_global_params_t gbs, std::istream& is, int numbytes) {    
    unsigned char buf[numbytes];    
    is.read(reinterpret_cast<char*>(buf), numbytes);
    element_init_G1(el, gbs->pairing);
    element_from_bytes(el, buf);
    
}

void element_to_stream(element_t el, std::ostream& os) {
    int numbytes = element_length_in_bytes(el);
    unsigned char buf[numbytes];
    element_to_bytes(buf, el);
    os.write(reinterpret_cast<char*>(buf), numbytes);
    
}

void ciphertext_from_stream(bes_ciphertext_t* ct, bes_global_params_t gbs, istream& is) {
    bes_ciphertext_t cipher = (bes_ciphertext_t) malloc(sizeof(bes_ciphertext_s));
    
    int version, element_size;
    
    is >> version;
    is >> cipher->num_receivers;
    is >> cipher->ct_length;
    is >> element_size;
    
    is.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    cipher->receivers = (int*) malloc(cipher->num_receivers * sizeof(int));
    
    for (int i = 0; i < cipher->num_receivers; ++i) {
        is >> cipher->receivers[i];
    }
    
    is.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    cipher->HDR = (element_t*) pbc_malloc((gbs->A + 1) * sizeof(element_t));
    for (int i = 0; i < (gbs->A + 1); ++i) {
        element_from_stream(cipher->HDR[i], gbs, is, element_size);
    }
    
    cipher->iv = (unsigned char*) malloc(AES::BLOCKSIZE * sizeof(unsigned char));
    is.read(reinterpret_cast<char*>(cipher->iv), AES::BLOCKSIZE);
    
    cipher->ct = (unsigned char*) malloc(cipher->ct_length * sizeof(unsigned char));
    is.read(reinterpret_cast<char*>(cipher->ct), cipher->ct_length);

    *ct = cipher;

}

void ciphertext_to_stream(bes_ciphertext_t ct, bes_global_params_t gbs, ostream& os) {
    int version = 0;
    int element_size = element_length_in_bytes(ct->HDR[0]);

    
    os << version << " ";
    os << ct->num_receivers << " ";
    os << ct->ct_length << " ";
    os << element_size << "\n";

       
    for (int i = 0; i < ct->num_receivers; ++i) {
        os << ct->receivers[i] << " ";
    }
    
    os << "\n";
    
    // HDR
    for (int i = 0; i < (gbs->A + 1); ++i) {
        element_to_stream(ct->HDR[i], os);
    }
    
    // IV
    os.write(reinterpret_cast<char*>(ct->iv), AES::BLOCKSIZE);
    
    // CT
    os.write(reinterpret_cast<char*>(ct->ct), ct->ct_length);
}

void public_key_from_stream(pubkey_t *pubkey_p, bes_global_params_t gbs, std::istream& is, int element_size) {
    
    pubkey_t PK = (pubkey_t) pbc_malloc(sizeof(struct pubkey_s));
    
    // g
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
    
    *pubkey_p = PK;
}

void public_key_to_stream(pubkey_t PK, bes_global_params_t gbs, std::ostream& os) {

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
        
}

void private_key_from_stream(bes_privkey_t *privkey, bes_global_params_t gbs, std::istream& is, int element_size) {
    
    bes_privkey_t sk = (bes_privkey_t) pbc_malloc(sizeof(struct bes_privkey_s));

    is >> sk->id;
    
    is.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    element_from_stream(sk->privkey, gbs, is, element_size);
    
    *privkey = sk;
}

void private_key_to_stream(bes_privkey_t sk, std::ostream& os) {
    os << sk->id << "\n";
    
    element_to_stream(sk->privkey, os);
}