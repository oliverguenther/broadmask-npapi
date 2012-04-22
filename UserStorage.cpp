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
 * UserStorage.cpp
 */

#include "UserStorage.hpp"
#include "boost/lexical_cast.hpp"

using namespace std;


UserStorage::UserStorage() {
    keymap = map<string,string>();
    version = (char *) gpgme_check_version(NULL);
}

UserStorage::~UserStorage() {
    keymap.clear();
}

FB::VariantMap UserStorage::associatedKeys() {
    FB::VariantMap keys;
    for (map<string,string>::iterator it = keymap.begin(); it != keymap.end(); ++it) {
        keys[it->first] = it->second;
    }
    
    return keys;
}

FB::VariantMap UserStorage::import_key_block(std::string& keydata) {
    gpgme_ctx_t ctx = create_gpg_context();
    gpgme_error_t err;
    gpgme_data_t key;
    gpgme_import_result_t result;
    
    err = gpgme_set_protocol(ctx, GPGME_PROTOCOL_OpenPGP);
    if (err) {
        return gpgme_error(err);
    }
    
    err = gpgme_data_new_from_mem (&key, keydata.c_str(), keydata.length(), 1);
    if (err) {
        return gpgme_error(err);
    }
    
    err = gpgme_op_import (ctx, key);
    if (err) {
        return gpgme_error(err);
    }
    result = gpgme_op_import_result (ctx);
    gpgme_data_release (key);
    
    FB::VariantMap op_result;
    
    op_result["considered"] = result->considered;
    op_result["no_user_id"] = result->no_user_id;
    op_result["imported"] = result->imported;
    op_result["unchanged"] = result->imported;
    op_result["new_user_ids"] = result->new_user_ids;
    op_result["not_imported"] = result->not_imported;
    
    FB::VariantMap op_result_imports;
    int i;
    gpgme_import_status_t import;
    for (i = 0, import = result->imports; import; import = import->next, i++) {
        FB::VariantMap import_map;
        import_map["fingerprint"] = import->fpr;
        import_map["result"] = gpgme_strerror(import->result);
        import_map["status"] = import->status;
        import_map["new_key"] = (import->status & GPGME_IMPORT_NEW)? true : false;
		op_result_imports[import->fpr] = import_map;
	}
    op_result["imports"] = op_result_imports;
    gpgme_release (ctx);
    
    return op_result;
    
}

FB::VariantMap UserStorage::search_key(std::string& pattern) {
    gpgme_ctx_t ctx = create_gpg_context();
    gpgme_error_t err;
    gpgme_key_t key;
    
    err = gpgme_set_protocol(ctx, GPGME_PROTOCOL_OpenPGP);
    if (err) {
        return gpgme_error(err);
    }
    
    // Search external source
    err = gpgme_set_keylist_mode (ctx, (gpgme_get_keylist_mode (ctx)
                                        | GPGME_KEYLIST_MODE_EXTERN));
    if (err) {
        return gpgme_error(err);
    }
    
    // Search for keyid, or return all keys if keyid is null
    if (pattern.size() > 0){
        err = gpgme_op_keylist_start (ctx, pattern.c_str(), 0);
    } else { // list all keys
        err = gpgme_op_keylist_ext_start (ctx, NULL, 0, 0);
    }
    
    if (err) {
        return gpgme_error(err);
    }
    
    FB::VariantMap op_result;
    int num_keys = 0;
    while (!(err = gpgme_op_keylist_next (ctx, &key))) {
        FB::VariantMap key_result;
        
        key_result["key_id"] = key->subkeys->keyid;
        if (key->uids && key->uids->name) 
            key_result["name"] = key->uids->name;
        
        if (key->subkeys->fpr)
            key_result["fingerprint"] = key->subkeys->fpr;
        
        if (key->uids && key->uids->email)
            key_result["email"] = key->uids->email;
        
        key_result["expired"] = key->expired? true : false;
        key_result["revoked"] = key->revoked? true : false;
        key_result["disabled"] = key->disabled? true : false;
        key_result["invalid"] = key->invalid? true : false;
        key_result["secret"] = key->secret? true : false;
        key_result["can_encrypt"] = key->can_encrypt? true : false;
        key_result["can_sign"] = key->can_sign? true : false;
        key_result["can_certify"] = key->can_certify? true : false;
        key_result["can_authenticate"] = key->can_authenticate? true : false;
        key_result["is_qualified"] = key->is_qualified? true : false;
        key_result["owner_trust"] = key->owner_trust == GPGME_VALIDITY_UNKNOWN? "unknown":
        key->owner_trust == GPGME_VALIDITY_UNDEFINED? "undefined":
        key->owner_trust == GPGME_VALIDITY_NEVER? "never":
        key->owner_trust == GPGME_VALIDITY_MARGINAL? "marginal":
        key->owner_trust == GPGME_VALIDITY_FULL? "full":
        key->owner_trust == GPGME_VALIDITY_ULTIMATE? "ultimate": "[?]";
        
        op_result[key->subkeys->keyid] = key_result;
        num_keys++;
        gpgme_key_unref(key);
    }
    
    // gpgme_op_keylist_next returns GPG_ERR_EOF on completion
    if (gpg_err_code (err) != GPG_ERR_EOF) {
        return gpgme_error(err);
    }
    
    err = gpgme_op_keylist_end (ctx);
    if (err) {
        return gpgme_error(err);
    }
    
    if (!num_keys) {
        op_result["error"] = true;
        op_result["error_msg"] = "No keys found";
    }
    
    gpgme_release (ctx);    
    return op_result;
}

FB::VariantMap UserStorage::encrypt_with(string& data, string& key_id) {
    gpgme_ctx_t ctx = create_gpg_context();
    gpgme_error_t err;
    gpgme_data_t in, out;
    gpgme_key_t key[2] = { NULL, NULL };
    gpgme_encrypt_result_t result;
    
    
    err = gpgme_set_protocol(ctx, GPGME_PROTOCOL_OpenPGP);
    if (err) {
        return gpgme_error(err);
    }
    gpgme_set_armor (ctx, 1);
    
    err = gpgme_data_new_from_mem (&in, data.c_str(), data.size(), 0);
    if (err) {
        return gpgme_error(err);
    }
    
    err = gpgme_data_new (&out);
    if (err) {
        return gpgme_error(err);
    }
    
    err = gpgme_get_key (ctx, key_id.c_str(),
                         &key[0], 0);
    if (err) {
        return gpgme_error(err);
    }
    err = gpgme_op_encrypt_sign (ctx, key, GPGME_ENCRYPT_ALWAYS_TRUST, in, out);
    if (err) {
        return gpgme_error(err);
    }
    
    result = gpgme_op_encrypt_result (ctx);
    if (result->invalid_recipients) {
        std::string errstr = std::string("Invalid recipient encountered");
        errstr.append(result->invalid_recipients->fpr);
        FB::VariantMap result;
        result["error"] = true;
        result["error_msg"] = errstr;
        return result;
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

FB::VariantMap UserStorage::encrypt_for(string& data, string& user_id) {
    map<string,string>::iterator it = keymap.find(user_id);
    
    if (it != keymap.end()) {
        return encrypt_with(data, it->second);
    } else {
        FB::VariantMap output;
        output["error"] = true;
        output["key_missing"] = true;
        output["error_msg"] = "User has no corresponding key";
        return output;
    }
    
}

FB::VariantMap UserStorage::decrypt(string& data) {
    gpgme_ctx_t ctx;
    gpgme_error_t err;
    gpgme_data_t in, out;
    gpgme_decrypt_result_t decrypt_result;
    gpgme_verify_result_t verify_result;
    
    
    ctx = create_gpg_context();    
    err = gpgme_data_new_from_mem (&in, data.c_str(), data.length(), 0);
    if (err) {
        return gpgme_error(err);
    }
    
    err = gpgme_data_new (&out);
    if (err) {
        return gpgme_error(err);
    }
    
    err = gpgme_op_decrypt_verify (ctx, in, out);
    if (err) {
        return gpgme_error(err);
    }
    
    decrypt_result = gpgme_op_decrypt_result (ctx);
    verify_result = gpgme_op_verify_result (ctx);
    
    if (!verify_result) {
        FB::VariantMap result;
        result["error"] = true;
        result["error_msg"] = "Verification failed";
        return result;
    }
    
    FB::VariantMap sigmap, response;
    gpgme_signature_t sig = verify_result->signatures;
    
    int sigcount = 0;
    while (sig) {
        
        FB::VariantMap sig_i;
        
        sig_i["fingerprint"] = sig->fpr;
        sig_i["timestamp"] = sig->timestamp;
        sig_i["expire_at"] = sig->exp_timestamp;
        sig_i["valid"] = get_validity_str(sig->validity);
        sig_i["status"] = get_status_str(sig->status);
        
        sigmap[boost::lexical_cast<string>(sigcount)] = sig_i;
        
        // get status of next signature
        sig = sig->next;
        sigcount++;
    }
    
    if (sigcount < 1) {
        response["signed"] = false;
    } else {
        response["signed"] = true;
    }
    
    size_t out_size = 0;
    std::string out_buf;
    out_buf = gpgme_data_release_and_get_mem (out, &out_size);
    
    /* strip the size_t data out of the output buffer */
    out_buf = out_buf.substr(0, out_size);
    response["message"] = out_buf;
    
    /* set the output object to NULL since it has
     already been released */
    out = NULL;
    out_buf = "";
    
    response["signatures"] = sigmap;
    response["error"] = false;
    gpgme_data_release (in);
    gpgme_release (ctx);
    
    return response;
    
}

void UserStorage::setPGPKey(string& user_id, string& keyid) {
    keymap.insert(pair<string,string>(user_id, keyid));
}

FB::VariantMap UserStorage::getPGPKey(string& user_id) {
    FB::VariantMap result;
    result["userid"] = user_id;
    
    map<string,string>::iterator it = keymap.find(user_id);
    
    if (it != keymap.end()) {
        result["keyid"] = it->second;
        result["found"] = true;
    } else {
        result["found"] = false;
    }
    
    return result;    
}

void UserStorage::removePGPKey(string& user_id) {
    keymap.erase(user_id);
}



FB::VariantMap UserStorage::gpgme_error (gpgme_error_t& err) {
    FB::VariantMap error;
    error["error"] = true;
    error["source"] = gpgme_strsource (err);
    error["error_code"] = gpgme_err_code (err); 
    error["error_msg"] = gpgme_strerror (err);
    
    return error;
}

gpgme_ctx_t UserStorage::create_gpg_context() {
    gpgme_ctx_t ctx;
    gpgme_error_t err;
    
    setlocale (LC_ALL, ""); 
    gpgme_set_locale (NULL, LC_CTYPE, setlocale (LC_CTYPE, NULL));
#ifdef LC_MESSAGES
    gpgme_set_locale (NULL, LC_MESSAGES, setlocale (LC_MESSAGES, NULL));
#endif
    
    err = gpgme_new (&ctx);
    gpgme_set_textmode (ctx, 1);
    gpgme_set_armor (ctx, 1);
    
    return ctx;
}

string UserStorage::get_validity_str (gpgme_validity_t& v) {
    switch (v) {
        case GPGME_VALIDITY_UNKNOWN:
            return "unknown";
            break;
        case GPGME_VALIDITY_UNDEFINED:
            return "undefined";
            break;
        case GPGME_VALIDITY_NEVER:
            return "never";
            break;
        case GPGME_VALIDITY_MARGINAL:
            return "marginal";
            break;
        case GPGME_VALIDITY_FULL:
            return "full";
            break;
        case GPGME_VALIDITY_ULTIMATE:
            return "ultimate";
            break;
        default:
            return "[invalid value]";
            break;
    }
}

string UserStorage::get_status_str (gpgme_error_t& e) {
    switch (e) {
        case GPG_ERR_NO_ERROR:
            return "VALID";
            break;
        case GPG_ERR_KEY_EXPIRED:
            return "EXPIRED";
            break;
        case GPG_ERR_CERT_REVOKED:
            return "REVOKED";
            break;
        case GPG_ERR_BAD_SIGNATURE:
            return "INVALID";
            break;
        case GPG_ERR_NO_PUBKEY:
            return "CANNOT VERIFY";
            break;
        default:
            return "UNKNOWN";
            break;
    }
}