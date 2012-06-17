/*
 * GnuPG (GPGME) wrapper
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
 * gnupg_wrapper.hpp
 */


#ifndef H_GNUPG_WRAPPER
#define H_GNUPG_WRAPPER

// JSAPI
#include "JSAPIAuto.h"
#include "APITypes.h"
#include "JSObject.h"
#include "variant_map.h"

// GPGME
#include <gpgme.h>

// Wraps enc/dec result and/or error information
typedef struct {
    char *result;
    bool error;
    std::string error_msg;
} gpgme_result;

/**
 * @fn gpgme_encrypt
 * @brief Tries to encrypt data with PGP key key_id
 * @param data Data to encrypt
 * @param key_id key identifier or fingerprint
 * @param sign set != 0 to use sign operation
 * @return gpgme_result struct
 */
gpgme_result gpgme_encrypt(const char *data, const char *key_id, int sign);

/**
 * @fn gpgme_encrypt_input
 * @brief Tries to encrypt a gpgme_data_t input with PGP key key_id
 * to a gpgme_data_t output
 * @param in gpgme_data_t to encrypt
 * @param out gpgme_data_t output
 * @param key_id key identifier or fingerprint
 * @param sign set != 0 to use sign operation
 * @return gpgme_result struct
 */
gpgme_result gpgme_encrypt_io(gpgme_data_t in, gpgme_data_t out, const char* key_id, int sign);


/**
 * @fn gpgme_encrypt_tofile
 * @brief Tries to encrypt a gpgme_data_t input with PGP key key_id
 * to the file at path
 * @param data data to encrypt
 * @param key_id key identifier or fingerprint
 * @return gpgme_result struct
 */
gpgme_result gpgme_encrypt_tofile(const char *data, const char *key_id, const char *path);

/**
 * @fn gpgme_decrypt
 * @brief Tries to decrypt an ASCII message
 * @param data Data to decrypt
 * @return gpgme_result struct
 */
gpgme_result gpgme_decrypt(const char *data);

/**
 * @fn gpgme_decrypt_input
 * @brief Tries to decrypt a prepared gpgme_data_t (e.g. from a file)
 * @param input gpgme_data_t input data
 * @return gpgme_result struct
 */
gpgme_result gpgme_decrypt_input (gpgme_data_t input);

/**
 * @fn gpgme_decrypt_file
 * @brief Tries to decrypt an ASCII file
 * @param path file path
 * @return gpgme_result struct
 */
gpgme_result gpgme_decrypt_file (const char *path);


/**
 * @fn gpgme_encrypt_with
 * @brief Tries to encrypt data with PGP key key_id
 * @param data Data to encrypt
 * @param key_id key identifier or fingerprint
 * @return JS object with op results
 */
FB::VariantMap gpgme_encrypt_with(std::string& data, std::string& key_id);

/**
 * @fn gpgme_decrypt
 * @brief Tries to decrypt payload with a key from keyring
 * @param data Data to decrypt
 * @return JS object with op results
 */
FB::VariantMap gpgme_decrypt(std::string& data);


/**
 * @fn gpgme_fetch_key_id
 * @brief Retrieves the key that matches pattern and imports the key to the GPG keychain
 * @return JS object with op results
 */    
FB::VariantMap gpgme_search_key(std::string key, int secret_keys_only);

/**
 * @fn gpgme_import_key_block
 * @brief Import the keyblock to gpg keychain
 * @return JS object with op results
 */    
FB::VariantMap gpgme_import_key_block(std::string& keydata);


// Create a gpgme context
gpgme_ctx_t create_gpg_context();

// Return the content of a gpgme_result in a FB::VariantMap
FB::VariantMap result_to_variant (gpgme_result& r);

// return string representation of a gpgme_validity_t struct
std::string get_validity_str (gpgme_validity_t& v);

// return string representation of a gpgme_error struct
std::string get_status_str (gpgme_error_t& e);

// Return a gpgme_result struct with error description
gpgme_result gpgme_error(gpgme_error_t& err);

// Return a FB::VariantMap with error description
FB::VariantMap gpgme_error_map (gpgme_error_t& err);

#endif