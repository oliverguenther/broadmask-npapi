#include "gnupg_wrapper.hpp"
#include <cstdio>
#include <iostream>
#include <fstream>
using std::cout;
using std::cerr;
using std::endl;

FB::VariantMap gpgme_import_key_block(std::string& keydata) {
    gpgme_ctx_t ctx = create_gpg_context();
    gpgme_error_t err;
    gpgme_data_t key;
    gpgme_import_result_t result;
    
    err = gpgme_set_protocol(ctx, GPGME_PROTOCOL_OpenPGP);
    if (err) {
        return gpgme_error_map(err);
    }
    
    err = gpgme_data_new_from_mem (&key, keydata.c_str(), keydata.length(), 1);
    if (err) {
        return gpgme_error_map(err);
    }
    
    err = gpgme_op_import (ctx, key);
    if (err) {
        return gpgme_error_map(err);
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

FB::VariantMap gpgme_search_key(std::string pattern, int secret_keys_only) {
    gpgme_ctx_t ctx = create_gpg_context();
    gpgme_error_t err;
    gpgme_key_t key;
    
    err = gpgme_set_protocol(ctx, GPGME_PROTOCOL_OpenPGP);
    if (err) {
        return gpgme_error_map(err);
    }
    
    err = gpgme_set_keylist_mode (ctx, (gpgme_get_keylist_mode (ctx)
                                        | GPGME_KEYLIST_MODE_LOCAL));
    if (err) {
        return gpgme_error_map(err);
    }
    
    // Search for keyid, or return all keys if keyid is null
    if (pattern.size() > 0){
        err = gpgme_op_keylist_start (ctx, pattern.c_str(), secret_keys_only);
    } else { // list all keys
        err = gpgme_op_keylist_ext_start (ctx, NULL, secret_keys_only, 0);
    }
    
    if (err) {
        return gpgme_error_map(err);
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
        
        key_result["expired"] = key->expired ? true : false;
        key_result["revoked"] = key->revoked ? true : false;
        key_result["disabled"] = key->disabled ? true : false;
        key_result["invalid"] = key->invalid ? true : false;
        key_result["secret"] = key->secret ? true : false;
        key_result["can_encrypt"] = key->can_encrypt ? true : false;
        key_result["can_sign"] = key->can_sign ? true : false;
        key_result["can_certify"] = key->can_certify ? true : false;
        key_result["can_authenticate"] = key->can_authenticate ? true : false;
        key_result["is_qualified"] = key->is_qualified ? true : false;
        key_result["owner_trust"] = key->owner_trust == GPGME_VALIDITY_UNKNOWN ? "unknown":
        key->owner_trust == GPGME_VALIDITY_UNDEFINED ? "undefined":
        key->owner_trust == GPGME_VALIDITY_NEVER ? "never":
        key->owner_trust == GPGME_VALIDITY_MARGINAL ? "marginal":
        key->owner_trust == GPGME_VALIDITY_FULL ? "full":
        key->owner_trust == GPGME_VALIDITY_ULTIMATE ? "ultimate": "[?]";
        
        op_result[key->subkeys->keyid] = key_result;
        num_keys++;
        gpgme_key_unref(key);
    }
    
    // gpgme_op_keylist_next returns GPG_ERR_EOF on completion
    if (gpg_err_code (err) != GPG_ERR_EOF) {
        return gpgme_error_map(err);
    }
    
    err = gpgme_op_keylist_end (ctx);
    if (err) {
        return gpgme_error_map(err);
    }
    
    if (!num_keys) {
        op_result["error"] = true;
        op_result["error_msg"] = "No keys found";
    }
    
    gpgme_release (ctx);    
    return op_result;
}

FB::VariantMap gpgme_encrypt_with(std::string& data, std::string& key_id) {
    gpgme_result r = gpgme_encrypt(data.c_str(), key_id.c_str(), 1, 1);
    return result_to_variant(r);
}


FB::VariantMap gpgme_decrypt(std::string& data) {
    gpgme_result r = gpgme_decrypt(data.c_str());
    return result_to_variant(r);
}


gpgme_result gpgme_encrypt(const char *data, const char *key_id, int sign, int armored) {
    gpgme_ctx_t ctx = create_gpg_context();
    
    // Armoring is enabled by default
    if (!armored) {
        gpgme_set_textmode (ctx, 0);
        gpgme_set_armor (ctx, 0);
    }
    gpgme_error_t err;
    gpgme_data_t in, out;
    
    
    err = gpgme_set_protocol(ctx, GPGME_PROTOCOL_OpenPGP);
    if (err) {
        return gpgme_error(err);
    }
    gpgme_set_armor (ctx, 1);
    
    err = gpgme_data_new_from_mem (&in, data, strlen(data), 0);
    if (err) {
        return gpgme_error(err);
    }
    
    err = gpgme_data_new (&out);
    if (err) {
        return gpgme_error(err);
    }
    
    gpgme_release (ctx);
    gpgme_result enc_result = gpgme_encrypt_io(in, out, key_id, sign);
    
    if (enc_result.error)
        return enc_result;
    
    size_t nRead = 0;
    char* buf = gpgme_data_release_and_get_mem (out, &nRead);
    
    gpgme_result r;
    if (!buf) {
        r.error = true;
        r.error_msg = "No data was returned";
        return r;
    }
    buf = (char *)realloc(buf, nRead+1);
    buf[nRead] = 0;
    
    r.error = false;
    r.result = buf;
    
    // Out has been released by gpgme_data_release
    out = NULL;
    
    
    return r;
}


gpgme_result gpgme_encrypt_io (gpgme_data_t in, gpgme_data_t out, const char* key_id, int sign) {
    gpgme_ctx_t ctx = create_gpg_context();
    gpgme_error_t err;
    gpgme_key_t key[2] = { NULL, NULL };
    gpgme_encrypt_result_t result;
    
    
   
    err = gpgme_get_key (ctx, key_id,
                         &key[0], 0);
    if (err) {
        return gpgme_error(err);
    }
    
    if (sign)
        err = gpgme_op_encrypt_sign (ctx, key, GPGME_ENCRYPT_ALWAYS_TRUST, in, out);
    else
        err = gpgme_op_encrypt(ctx, key, GPGME_ENCRYPT_ALWAYS_TRUST, in, out);
        
    if (err) {
        return gpgme_error(err);
    }
    
    result = gpgme_op_encrypt_result (ctx);
    gpgme_result r;
    if (result->invalid_recipients) {
        r.error = true;
        r.error_msg = "Invalid recipient encountered";
        return r;
    }
    
    gpgme_release (ctx);
    gpgme_key_unref (key[0]);
    gpgme_data_release (in);
    
    // In this case, result is already contained gpgme_data_t out
    r.error = false;
    return r;
}

gpgme_result gpgme_encrypt_tofile(const char *data,
                                  const char *key_id, const char *path) {
        
    
    // Encrypt without armoring, do not sign
    gpgme_result enc_result = gpgme_encrypt(data, key_id, 0, 0);
    
    if (enc_result.error)
        return enc_result;
    
    
    // Write result to file
    FILE* outfile = fopen(path, "w");
   
    if (!outfile) {
        gpgme_result r;
        r.error = true;
        r.error_msg = "Couldn't open file " + std::string(path);
        return r;
    }

    fwrite (enc_result.result , 1 , strlen(enc_result.result) , outfile );
    
    if (fflush(outfile) != 0)
        cerr << "Couldn't flush output file after gpgme_encrypt_io" << endl;
    if (fclose(outfile) != 0)
        cerr << "Couldn't close output file after gpgme_encrypt_io" << endl;

    return enc_result;
}


gpgme_result gpgme_decrypt(const char *data) {
    gpgme_data_t in;
	gpgme_error_t err;
    
	err = gpgme_data_new_from_mem(&in, data, strlen(data), 0);
	if (err) return gpgme_error(err);
    
	return gpgme_decrypt_input(in);
}


gpgme_result gpgme_decrypt_input(gpgme_data_t input) {
    gpgme_ctx_t ctx;
    gpgme_error_t err;
    gpgme_data_t out;
    gpgme_decrypt_result_t decrypt_result;
    gpgme_verify_result_t verify_result;
    
    
    ctx = create_gpg_context(); 
    err = gpgme_data_new (&out);
    if (err) return gpgme_error(err);
    
    err = gpgme_op_decrypt_verify (ctx, input, out);
    if (err) return gpgme_error(err);
    
    decrypt_result = gpgme_op_decrypt_result (ctx);
    verify_result = gpgme_op_verify_result (ctx);
    
    gpgme_result r;
    
    if (!verify_result) {
        r.error = true;
        r.error_msg = gpgme_strerror (err);
        return r;
    }
      
    size_t nRead = 0;
    char* buf = gpgme_data_release_and_get_mem (out, &nRead);
    if (!buf) {
        r.error = true;
        r.error_msg = "No data was returned";
        return r;
    }
    buf = (char *)realloc(buf, nRead+1);
    buf[nRead] = 0;
    
    r.error = false;
    r.result = buf;
    return r;
}

gpgme_result gpgme_decrypt_file(const char *path) {
	gpgme_data_t in;
	gpgme_error_t err;

	err = gpgme_data_new_from_file(&in, path, 1);
	if (err) return gpgme_error(err);

	return gpgme_decrypt_input(in);
}

gpgme_result gpgme_error (gpgme_error_t& err) {
    gpgme_result r;
    
    r.error = true;
    r.error_msg = gpgme_strerror(err);
    return r;
}
    

FB::VariantMap result_to_variant (gpgme_result& r) {
    FB::VariantMap vmap;
    
    vmap["error"] = r.error;
    vmap["error_msg"] = r.error_msg;
    
    if (!r.error)
        vmap["result"] = std::string(r.result);

    return vmap;
}


FB::VariantMap gpgme_error_map (gpgme_error_t& err) {
    FB::VariantMap error;
    error["error"] = true;
    error["source"] = gpgme_strsource (err);
    error["error_code"] = gpgme_err_code (err); 
    error["error_msg"] = gpgme_strerror (err);
    
    return error;
}

gpgme_ctx_t create_gpg_context() {
    gpgme_ctx_t ctx;
    gpgme_error_t err;
    
    setlocale (LC_ALL, ""); 
    gpgme_set_locale (NULL, LC_CTYPE, setlocale (LC_CTYPE, NULL));
#ifdef LC_MESSAGES
    gpgme_set_locale (NULL, LC_MESSAGES, setlocale (LC_MESSAGES, NULL));
#endif
    
    gpgme_check_version (NULL);
    
    err = gpgme_new (&ctx);
    if (err) {
        cerr << "Could not create context " << gpgme_strerror(err) << endl;
        return NULL;
    }
    gpgme_set_textmode (ctx, 1);
    gpgme_set_armor (ctx, 1);
    
    return ctx;
}

std::string get_validity_str (gpgme_validity_t& v) {
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

std::string get_status_str (gpgme_error_t& e) {
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