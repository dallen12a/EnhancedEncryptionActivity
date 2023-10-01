/**
 * File: EncryptionDecryption.cpp
 * Author: David Allen
 * Date: 10-01-2023
 * Version: 2.0 - updated header
 *
 * Description:
 * This C++ program demonstrates encryption and decryption of a text file using the AES algorithm in CBC mode.
 * The program uses OpenSSL's EVP library for encryption and decryption operations.
 * It reads data from a file, encrypts it using a random initialization vector (IV) and a provided key, saves the encrypted data to another file,
 * and then decrypts the encrypted data using the same key and IV and saves it to yet another file.
 *
 * File Details:
 * - "EncryptionDecryption.cpp": Main file containing the program logic.
 *
 * Included Libraries:
 * - <sstream>: String stream for parsing
 * - <openssl/evp.h>: OpenSSL library for encryption and decryption
 * - <openssl/rand.h>: OpenSSL library for random key and IV generation
 *
 * Functions:
 * - std::string generate_random_key(int key_length): Generates a random encryption key.
 * - std::string aes_encrypt(const std::string& source, const std::string& key, const std::string& iv): Performs AES encryption.
 * - std::string aes_decrypt(const std::string& ciphertext, const std::string& key, const std::string& iv): Performs AES decryption.
 * - std::string read_file(const std::string& filename): Reads data from a file.
 * - void save_data_file(const std::string& filename, const std::string& student_name, const std::string& key, const std::string& data): Saves data to a file.
 * - int main(): Main function containing program logic.
 *
 * Additional Notes:
 * - The program uses OpenSSL EVP library for AES encryption and decryption operations.
 * - A random IV is generated for encryption.
 * - The input file is expected to have the student's name on the first line.
 */

#include <iostream>
#include <fstream>
#include <sstream>
#include <openssl/evp.h>
#include <openssl/rand.h>

// Function to generate a random encryption key
std::string generate_random_key(int key_length) {
    std::string key;
    key.resize(key_length);

    RAND_bytes(reinterpret_cast<unsigned char*>(&key[0]), key_length);

    return key;
}

// Function to perform AES encryption
std::string aes_encrypt(const std::string& source, const std::string& key, const std::string& iv) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, reinterpret_cast<const unsigned char*>(key.c_str()), reinterpret_cast<const unsigned char*>(iv.c_str()));
    EVP_CIPHER_CTX_set_key_length(ctx, key.size());

    int ciphertext_len;
    std::string ciphertext(source.size() + EVP_MAX_BLOCK_LENGTH, '\0');
    EVP_EncryptUpdate(ctx, reinterpret_cast<unsigned char*>(&ciphertext[0]), &ciphertext_len, reinterpret_cast<const unsigned char*>(source.c_str()), source.size());

    int final_len;
    EVP_EncryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(&ciphertext[ciphertext_len]), &final_len);
    ciphertext_len += final_len;

    EVP_CIPHER_CTX_free(ctx);

    // Resize the ciphertext to the actual length
    ciphertext.resize(ciphertext_len);

    return ciphertext;
}

// Function to perform AES decryption
std::string aes_decrypt(const std::string& ciphertext, const std::string& key, const std::string& iv) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, reinterpret_cast<const unsigned char*>(key.c_str()), reinterpret_cast<const unsigned char*>(iv.c_str()));
    EVP_CIPHER_CTX_set_key_length(ctx, key.size());

    int plaintext_len;
    std::string plaintext(ciphertext.size(), '\0');
    EVP_DecryptUpdate(ctx, reinterpret_cast<unsigned char*>(&plaintext[0]), &plaintext_len, reinterpret_cast<const unsigned char*>(ciphertext.c_str()), ciphertext.size());

    int final_len;
    EVP_DecryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(&plaintext[plaintext_len]), &final_len);
    plaintext_len += final_len;

    EVP_CIPHER_CTX_free(ctx);

    // Resize the plaintext to the actual length
    plaintext.resize(plaintext_len);

    return plaintext;
}

// Function to read data from a file
std::string read_file(const std::string& filename) {
    std::ifstream file(filename);
    std::stringstream buffer;
    buffer << file.rdbuf();
    return buffer.str();
}

// Function to save data to a file
void save_data_file(const std::string& filename, const std::string& student_name, const std::string& key, const std::string& data) {
    std::ofstream file(filename);
    if (file.is_open()) {
        // Save the data to the file in the specified format - Change first line in inputdata file to reflect student name
        file << "Student Name: " << student_name << '\n';

        // Get the current timestamp
        std::time_t now = std::time(nullptr);
        char timestamp[11]; // "yyyy-mm-dd\0"
        std::tm time_info;
        localtime_s(&time_info, &now);
        std::strftime(timestamp, sizeof(timestamp), "%F", &time_info);
        file << "Timestamp: " << timestamp << '\n';

        file << "Encryption Key: " << key << '\n';
        file << "Data:\n" << data;

        file.close();
    }
    else {
        std::cerr << "Error creating file: " << filename << std::endl;
    }
}

int main() {
    std::cout << "Encryption Decryption Test!" << std::endl;

    const std::string file_name = "inputdatafile.txt";
    const std::string encrypted_file_name = "encrypteddatafile.txt";
    const std::string decrypted_file_name = "decrypteddatafile.txt";
    const std::string source_string = read_file(file_name);
    const std::string key = "password";

    // Generate a random IV (Initialization Vector)
    unsigned char iv[EVP_MAX_IV_LENGTH];
    RAND_bytes(iv, EVP_MAX_IV_LENGTH);

    // Get the student name from the first line of the input file
    std::istringstream source_stream(source_string);
    std::string student_name;
    std::getline(source_stream, student_name);  // Read the first line

    // Encrypt sourceString with key
    const std::string encrypted_string = aes_encrypt(source_string, key, std::string(reinterpret_cast<const char*>(iv), EVP_MAX_IV_LENGTH));

    // Save encrypted_string to file
    save_data_file(encrypted_file_name, student_name, key, encrypted_string);

    // Decrypt encryptedString with key
    const std::string decrypted_string = aes_decrypt(encrypted_string, key, std::string(reinterpret_cast<const char*>(iv), EVP_MAX_IV_LENGTH));

    // Save decrypted_string to file
    save_data_file(decrypted_file_name, student_name, key, decrypted_string);

    std::cout << "Read File: " << file_name << " - Encrypted To: " << encrypted_file_name << " - Decrypted To: " << decrypted_file_name << std::endl;

    return 0;
}
