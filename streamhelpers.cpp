#include "streamhelpers.hpp"
#include <iostream>
#include "DOM/Window.h"


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
    
    cipher->iv = (unsigned char*) malloc(AES_IV_LENGTH * sizeof(unsigned char));
    is.read(reinterpret_cast<char*>(cipher->iv), AES_IV_LENGTH);
    
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
    os.write(reinterpret_cast<char*>(ct->iv), AES_IV_LENGTH);
    
    // CT
    os.write(reinterpret_cast<char*>(ct->ct), ct->ct_length);
}

//void debug_ciphertext(bes_ciphertext_t ct) {
//    cout << "*** CIPHERTEXT DEBUG ***" << endl;
//    cout << "Receivers" << ct->num_receivers << endl;
//    cout << "CT length" << ct->ct_length << endl << endl;
//    
//    cout << "RECEIVERS: ";
//    for (int i = 0; i < ct->num_receivers; ++i) {
//        cout << ct->receivers[i] << " ";
//    }
//    cout << endl << endl;
//    
//    cout << "IV ";
//    for (int i = 0; i < AES_IV_LENGTH; ++i) {
//        cout << hex << (int) ct->iv[i] << " ";
//    }
//    
//    cout << endl << endl;
//
//    cout << "CT ";
//    for (int i = 0; i < ct->ct_length; ++i) {
//        cout << hex << (int) ct->ct[i] << dec << " ";
//    }
//    
//    cout << endl << " *** END ** " << endl;
//}
//
//void debug_key(unsigned char* key, int keylen) {
//    cout << "*** KEY DEBUG ***" << endl;
//    
//    for (int i = 0; i < keylen; ++i) {
//        cout << hex << (int) key[i] << dec << " ";
//    }
//    
//    
//    cout << endl << " *** END ** " << endl;
//
//    
//}

void sk_ciphertext_to_stream(sk_ciphertext_t sk_ct, ostream& os) {
    int version = 0;
    os << version << " ";
    os << sk_ct->ct_length << "\n";
    
    // IV
    os.write(reinterpret_cast<char*>(sk_ct->iv), AES_IV_LENGTH);
    
    
    // CT
    os.write(reinterpret_cast<char*>(sk_ct->ct), sk_ct->ct_length);

    
}

void sk_ciphertext_from_stream(sk_ciphertext_t *ctptr, istream& is) {
    int version;
    
    sk_ciphertext_t sk_ct = (sk_ciphertext_t) malloc(sizeof(struct sk_ciphertext_s));
    
    is >> version;
    is >> sk_ct->ct_length;
    is.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

    // IV
    sk_ct->iv = (unsigned char*) malloc(AES_IV_LENGTH * sizeof(unsigned char));
    is.read(reinterpret_cast<char*>(sk_ct->iv), AES_IV_LENGTH);

    // CT
    sk_ct->ct = (unsigned char*) malloc(sk_ct->ct_length * sizeof(unsigned char));
    is.read(reinterpret_cast<char*>(sk_ct->ct), sk_ct->ct_length);

    *ctptr = sk_ct;
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


void free_sk_ciphertext(sk_ciphertext_t ct) {
    if (!ct)
        return;
    
    free(ct->iv);
    free(ct->ct);
    free(ct);
}

void free_bes_ciphertext(bes_ciphertext_t ct, bes_global_params_t gbs) {
    if (!ct || !gbs)
        return;
    
    // receivers
    free(ct->receivers);
    
    // HDR
    for (int i = 0; i < (gbs->A + 1); ++i) {
        element_clear(ct->HDR[i]);
    }
    
    free(ct->iv);
    free(ct->ct);
    free(ct);
    
}

void free_bes_privkey(bes_privkey_t sk) {
    if (!sk)
        return;
    
    element_clear(sk->privkey);
    free(sk);
}