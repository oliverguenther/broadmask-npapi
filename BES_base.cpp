/* Broadmask
 * BES_base.cpp
 */

#include "BES_base.h"
#include <iostream>

#include <cryptopp/aes.h>
using CryptoPP::AES;

using namespace std;

const char* BES_base::params = 
"type a\n"
"q 8780710799663312522437781984754049815806883199414208211028653399266475630880222957078625179422662221423155858769582317459277713367317481324925129998224791\n"
"h 12016012264891146079388821366740534204802954401251311822919615131047207289359704531102844802183906537786776\n"
"r 730750818665451621361119245571504901405976559617\n"
"exp2 159\n"
"exp1 107\n"
"sign1 1\n"
"sign0 1";

BES_base::BES_base() {
    cout << "fooooo" << endl;
}

BES_base::BES_base(string groupID, int num_users) {
    gid = groupID;
    N = num_users;
    
    
    // Setup global params
    setup_global_system(&gbs, params, N);
    
}


void BES_base::element_from_stream(element_t el, std::istream& is, int numbytes) {    
    unsigned char buf[numbytes];    
    is.read(reinterpret_cast<char*>(buf), numbytes);
    element_init_G1(el, gbs->pairing);
    element_from_bytes(el, buf);
    
}

void BES_base::element_to_stream(element_t el, std::ostream& os) {
    int numbytes = element_length_in_bytes(el);
    unsigned char buf[numbytes];
    element_to_bytes(buf, el);
    os.write(reinterpret_cast<char*>(buf), numbytes);
    
}

void BES_base::ciphertext_from_stream(bes_ciphertext_t* ct, istream& is) {
    bes_ciphertext_t cipher = (bes_ciphertext_t) malloc(sizeof(bes_ciphertext_s));
    
    int version, num_receivers, element_size, ct_length;
    
    is >> version;
    is >> num_receivers;
    is >> ct_length;
    is >> element_size;
    
    is.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    cipher->receivers = (int*) malloc(num_receivers * sizeof(int));
    
    for (int i = 0; i < num_receivers; ++i) {
        is >> cipher->receivers[i];
    }
    
    is.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    cipher->HDR = (element_t*) pbc_malloc((gbs->A + 1) * sizeof(element_t));
    for (int i = 0; i < (gbs->A + 1); ++i) {
        element_from_stream(cipher->HDR[i], is, element_size);
    }
    
    cipher->iv = (unsigned char*) malloc(AES::BLOCKSIZE * sizeof(unsigned char));
    
    for (int i = 0; i < AES::BLOCKSIZE; ++i) {
        is >> cipher->iv[i];
    }
    
    for (int i = 0; i < ct_length; ++i) {
        is >> cipher->ct[i];
    }
    
    *ct = cipher;

}

void BES_base::ciphertext_to_stream(bes_ciphertext_t ct, ostream& os) {
    int version = 0;
    int element_size = element_length_in_bytes(ct->HDR[0]);

    
    os << version;
    os << ct->num_receivers;
    os << ct->ct_length;
    os << element_size;

    os << "\n";
       
    for (int i = 0; i < ct->num_receivers; ++i) {
        os << ct->receivers[i];
    }
    
    os << "\n";
    
    for (int i = 0; i < (gbs->A + 1); ++i) {
        element_to_stream(ct->HDR[i], os);
    }
    
    for (int i = 0; i < AES::BLOCKSIZE; ++i) {
        os << ct->iv[i];
    }
    
    for (int i = 0; i < ct->ct_length; ++i) {
        os << ct->ct[i];
    }
}

void BES_base::public_key_from_stream(pubkey_t *pubkey_p, std::istream& is, int element_size) {
    
    pubkey_t PK = (pubkey_t) pbc_malloc(sizeof(struct pubkey_s));
    
    // g
    element_from_stream(PK->g, is, element_size);
    
    int i;
    // g_i
    PK->g_i = (element_t*) pbc_malloc((2 * gbs->B) * sizeof(element_t)); 
    for (i = 0; i < 2*gbs->B; ++i) {
        element_from_stream(PK->g_i[i], is, element_size);
    }
    
    // v_i
    PK->v_i = (element_t*) pbc_malloc(gbs->A * sizeof(element_t));
    for (i = 0; i < gbs->A; ++i) {
        element_from_stream(PK->v_i[i], is, element_size);
    }
    
    *pubkey_p = PK;
}

void BES_base::public_key_to_stream(pubkey_t PK, std::ostream& os) {

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

void BES_base::private_key_from_stream(pair<int, element_t> *sk, std::istream& is, int element_size) {
    is >> sk->first;
    
    is.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    element_from_stream(sk->second, is, element_size);
}

void BES_base::private_key_to_stream(pair<int, element_t> sk, std::ostream& os) {
    os << sk.first << "\n";
    
    element_to_stream(sk.second, os);
}


string BES_base::groupid() { 
	return gid;
}

int BES_base::num_users() {
	return N;
}
