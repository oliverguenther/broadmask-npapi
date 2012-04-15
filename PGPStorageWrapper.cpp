/*
 * GPG Wrapper using GPGME
 * 
 * Broadmask is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * Broadmask is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with Broadmask.  If not, see <http://www.gnu.org/licenses/>.
 * 
 * Oliver Guenther
 * mail@oliverguenther.de
 *
 * 
 * PGPStorageWrapper.cpp
 */
#include "PGPStorageWrapper.h"

using namespace std;


PGPStorageWrapper::PGPStorageWrapper() {
    keymap = map<string,string>();
    
    // Init GPGME
    setlocale (LC_ALL, "");
    version = gpgme_check_version (NULL);
    gpgme_set_locale (NULL, LC_CTYPE, setlocale (LC_CTYPE, NULL));
#ifdef LC_MESSAGES
    gpgme_set_locale (NULL, LC_MESSAGES, setlocale (LC_MESSAGES, NULL));
#endif
}

PGPStorageWrapper::~PGPStorageWrapper() {
    keymap.clear();
}



FB::VariantMap PGPStorageWrapper::encrypt_for(string data, string user_id) {
    gpgme_ctx_t ctx;
    gpgme_error_t err;
    gpgme_data_t in, out;
    gpgme_key_t key[2] = { NULL, NULL };
    gpgme_encrypt_result_t result;
    
    err = gpgme_new (&ctx);
    if (err) {
        return gpgme_error(err);
    }
    err = gpgme_set_protocol(ctx, GPGME_PROTOCOL_OpenPGP);
    if (err) {
        return gpgme_error(err);
    }
    gpgme_set_armor (ctx, 1);
    
    err = gpgme_data_new_from_mem (&in, data, data_size, 0);
    if (err) {
        return gpgme_error(err);
    }
    
    err = gpgme_data_new (&out);
    if (err) {
        return gpgme_error(err);
    }
    
    err = gpgme_get_key (ctx, receiver_fp,
                         &key[0], 0);
    if (err) {
        return gpgme_error(err);
    }
    err = gpgme_op_encrypt (ctx, key, GPGME_ENCRYPT_ALWAYS_TRUST, in, out);
    if (err) {
        return gpgme_error(err);
    }
    
    result = gpgme_op_encrypt_result (ctx);
    if (result->invalid_recipients) {
        std::string errstr = std::string("Invalid recipient encountered");
        errstr.append(result->invalid_recipients->fpr);
        return gpgme_error_str(errstr);
    }
    
    size_t enc_size = 0;
    std::string buf;
    buf = gpgme_data_release_and_get_mem (out, &enc_size);
    buf = buf.substr(0, enc_size);
    out = NULL;
    
    FB::VariantMap output;
    output["error"] = false;
    output["encoded_data"] = buf;
    
    gpgme_key_unref (key[0]);
    gpgme_data_release (in);
    gpgme_data_release (out);
    gpgme_release (ctx);
    
    return output;
}

FB::VariantMap PGPStorageWrapper::encrypt_with(string data, string key_id) {
    
}

FB::VariantMap PGPStorageWrapper::decrypt(string data) {
    
}

FB::VariantMap PGPStorageWrapper::setPGPKey(string user_id, string keyid) {
    
}

FB::VariantMap PGPStorageWrapper::getPGPKey(string user_id) {
    
}


FB::VariantMap PGPStorageWrapper::gpgme_error (gpgme_error_t& err) {
    FB::VariantMap error;
    error["error"] = true;
    error["source"] = gpgme_strsource (err);
    error["error_code"] = gpgme_err_code (err); 
    error["error_desc"] = gpgme_strerror (err);
    
    return error;
}