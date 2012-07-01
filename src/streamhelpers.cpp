#include "streamhelpers.hpp"
#include <iostream>
#include "DOM/Window.h"


#include <cryptopp/aes.h>
using CryptoPP::AES;

#include "BDEM/ae_wrapper.hpp"

using namespace std;

void element_from_stream(element_t el, bkem_global_params_t gbs, std::istream& is, int numbytes) {    
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

void ciphertext_from_stream(bes_ciphertext_t* ct, bkem_global_params_t gbs, istream& is) {
    bes_ciphertext_t cipher = new bes_ciphertext_s;
    cipher->ae_ct = new AE_Ciphertext;
    
    int version, element_size;
    
    is >> version;
    is >> cipher->num_receivers;
    is >> cipher->ae_ct->ct_len;
    is >> element_size;
    
    is.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    cipher->receivers = new int[cipher->num_receivers];
    
    for (int i = 0; i < cipher->num_receivers; ++i) {
        is >> cipher->receivers[i];
    }
    
    is.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    cipher->HDR = new element_t[gbs->A + 1];
    for (int i = 0; i < (gbs->A + 1); ++i) {
        element_from_stream(cipher->HDR[i], gbs, is, element_size);
    }
    
    cipher->ae_ct->iv = new unsigned char[AE_IV_LENGTH];
    is.read(reinterpret_cast<char*>(cipher->ae_ct->iv), AE_IV_LENGTH);
    
    cipher->ae_ct->ct = new unsigned char[cipher->ae_ct->ct_len];
    is.read(reinterpret_cast<char*>(cipher->ae_ct->ct), cipher->ae_ct->ct_len);

    *ct = cipher;

}

size_t encryption_header_to_bytes(unsigned char** buf, element_t* HDR, int size) {
    
    std::ostringstream os;
    for (int i = 0; i < size; ++i) {
        element_to_stream(HDR[i], os);
    }
    
    size_t buf_size = os.str().size();
    unsigned char* result = (unsigned char*) malloc(buf_size * sizeof(unsigned char));
    memcpy(result, reinterpret_cast<const unsigned char*>(os.str().data()), buf_size);
    
    *buf = result;    
    return buf_size;
}

void ciphertext_to_stream(bes_ciphertext_t ct, bkem_global_params_t gbs, ostream& os) {
    int version = 0;
    int element_size = element_length_in_bytes(ct->HDR[0]);

    
    os << version << " ";
    os << ct->num_receivers << " ";
    os << ct->ae_ct->ct_len << " ";
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
    os.write(reinterpret_cast<char*>(ct->ae_ct->iv), AE_IV_LENGTH);
    
    // CT
    os.write(reinterpret_cast<char*>(ct->ae_ct->ct), ct->ae_ct->ct_len);
}

//void debug_ciphertext(bes_ciphertext_t ct) {
//    cout << "*** CIPHERTEXT DEBUG ***" << endl;
//    cout << "Receivers" << ct->num_receivers << endl;
//    cout << "CT length" << ct->ae_ct->ct_len << endl << endl;
//    
//    cout << "RECEIVERS: ";
//    for (int i = 0; i < ct->num_receivers; ++i) {
//        cout << ct->receivers[i] << " ";
//    }
//    cout << endl << endl;
//    
//    cout << "IV ";
//    for (int i = 0; i < AE_IV_LENGTH; ++i) {
//        cout << hex << (int) ct->ae_ct->iv[i] << " ";
//    }
//    
//    cout << endl << endl;
//
//    cout << "CT ";
//    for (int i = 0; i < ct->ae_ct->ct_len; ++i) {
//        cout << hex << (int) ct->ae_ct->ct[i] << dec << " ";
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

void sk_ciphertext_to_stream(AE_Ciphertext* sk_ct, ostream& os) {
    int version = 0;
    os << version << " ";
    os << sk_ct->ct_len << "\n";
    
    // IV
    os.write(reinterpret_cast<char*>(sk_ct->iv), AE_IV_LENGTH);
    
    
    // CT
    os.write(reinterpret_cast<char*>(sk_ct->ct), sk_ct->ct_len);

    
}

void sk_ciphertext_from_stream(AE_Ciphertext **ctptr, istream& is) {
    int version;
    
    AE_Ciphertext* sk_ct = new AE_Ciphertext;
    
    is >> version;
    is >> sk_ct->ct_len;
    is.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

    // IV
    sk_ct->iv = new unsigned char[AE_IV_LENGTH];
    is.read(reinterpret_cast<char*>(sk_ct->iv), AE_IV_LENGTH);

    // CT
    sk_ct->ct = new unsigned char[sk_ct->ct_len];
    is.read(reinterpret_cast<char*>(sk_ct->ct), sk_ct->ct_len);

    *ctptr = sk_ct;
}

void public_key_from_stream(pubkey_t *pubkey_p, bkem_global_params_t gbs, std::istream& is, int element_size) {
    
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

void public_key_to_stream(pubkey_t PK, bkem_global_params_t gbs, std::ostream& os) {

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

void private_key_from_stream(bes_privkey_t *privkey, bkem_global_params_t gbs, std::istream& is, int element_size) {
    
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


void free_bes_ciphertext(bes_ciphertext_t ct, bkem_global_params_t gbs) {
    if (!ct || !gbs)
        return;
    
    // receivers
    delete ct->receivers;
    
    // HDR
    for (int i = 0; i < (gbs->A + 1); ++i) {
        element_clear(ct->HDR[i]);
    }
    
    delete ct->ae_ct;
    delete ct;
    
}

void free_bes_privkey(bes_privkey_t sk) {
    if (!sk)
        return;
    
    element_clear(sk->privkey);
    free(sk);
}