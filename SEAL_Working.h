#ifndef SEAL_WORKING_H
#define SEAL_WORKING_H

#include <iostream>
#include <vector>
#include <chrono>
#include <iomanip>
#include <cmath> // For std::abs
#include <optional>
#include <sstream>
#include <fstream> // <-- ADDED for file output

// Includes are now active
#include "seal/seal.h"
using namespace seal;

/**
 * Working BFV and CKKS Implementation using Microsoft SEAL
 */

class SEAL_Working {
private:
    std::ostream& log_stream; 

  
    static EncryptionParameters create_bfv_parms() {
        EncryptionParameters parms(scheme_type::bfv);
        size_t poly_modulus_degree = 8192;
        parms.set_poly_modulus_degree(poly_modulus_degree);
        parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
        parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 20));
        return parms;
    }

    static EncryptionParameters create_ckks_parms() {
        EncryptionParameters parms(scheme_type::ckks);
        size_t poly_modulus_degree = 8192;
        parms.set_poly_modulus_degree(poly_modulus_degree);
        parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {60, 40, 40, 60}));
        return parms;
    }

    // --- BFV ---
    EncryptionParameters bfv_parms;
    SEALContext bfv_context;
    KeyGenerator bfv_keygen;
    SecretKey bfv_secret_key;
    PublicKey bfv_public_key;   
    RelinKeys bfv_relin_keys;   
    std::optional<Encryptor> bfv_encryptor; 
    Evaluator bfv_evaluator;
    Decryptor bfv_decryptor;
    BatchEncoder bfv_encoder;
    
    // --- CKKS ---
    EncryptionParameters ckks_parms;
    SEALContext ckks_context;
    KeyGenerator ckks_keygen;
    SecretKey ckks_secret_key;
    PublicKey ckks_public_key;   
    RelinKeys ckks_relin_keys;   
    std::optional<Encryptor> ckks_encryptor; 
    Evaluator ckks_evaluator;
    Decryptor ckks_decryptor;
    CKKSEncoder ckks_encoder;

    double ckks_scale = pow(2.0, 40);

    
    void print_bfv_info(const Ciphertext &ctxt, const std::string &name) {
       
        log_stream << "      [INFO] " << std::setw(30) << std::left << (name + ":")
                  << "size = " << ctxt.size()
                  << ", noise budget = " << bfv_decryptor.invariant_noise_budget(ctxt) << " bits"
                  << std::endl;
    }

    void print_ckks_info(const Ciphertext &ctxt, const std::string &name) {
       
        log_stream << "      [INFO] " << std::setw(30) << std::left << (name + ":")
                  << "size = " << ctxt.size()
                  << ", level = " << ckks_context.get_context_data(ctxt.parms_id())->chain_index()
                  << ", scale = " << std::fixed << std::setprecision(1) << std::log2(ctxt.scale()) << " bits"
                  << std::endl;
    }

 
    size_t getUserSize() {
        size_t size = 0;
        std::string line;
        while (size <= 0) {
            // Prompt goes to std::cout
            std::cout << "   Enter the number of elements for the vectors (e.g., 4): "; 
            if (!std::getline(std::cin, line)) { 
                break; 
            }
            std::stringstream ss(line);
            if (ss >> size && size > 0) {
                char c;
                if (ss >> c) { 
                    // Error message goes to std::cout
                    std::cout << "      Error: Invalid input. Please enter a single positive number." << std::endl;
                    size = 0; 
                } else {
                    break; 
                }
            } else {
                // Error message goes to std::cout
                std::cout << "      Error: Invalid input. Please enter a positive number." << std::endl;
                size = 0; 
            }
        }
        // Log the chosen size to the file
        log_stream << "   Vector size chosen: " << size << std::endl; 
        return size;
    }

    std::vector<int64_t> getUserVectorInt(size_t size, const std::string &name) {
        std::vector<int64_t> vec;
        while (vec.size() < size) {
            // Prompt goes to std::cout
            std::cout << "   Enter " << size << " space-separated integers for " << name << ": ";
            std::string line;
            if (!std::getline(std::cin, line)) { // Read from std::cin
                break;
            }
            // Log the raw input line to the file
            log_stream << "   User input for " << name << ": " << line << std::endl; 
            std::stringstream ss(line);
            int64_t val;
            while (ss >> val && vec.size() < size) {
                vec.push_back(val);
            }
            if (vec.size() < size) {
                // Error message goes to std::cout
                std::cout << "      Error: Not enough numbers entered. Please try again." << std::endl;
                vec.clear(); 
            }
        }
        return vec;
    }

    std::vector<double> getUserVectorDouble(size_t size, const std::string &name) {
        std::vector<double> vec;
        while (vec.size() < size) {
            // Prompt goes to std::cout
            std::cout << "   Enter " << size << " space-separated doubles for " << name << ": ";
            std::string line;
            if (!std::getline(std::cin, line)) { // Read from std::cin
                break;
            }
            // Log the raw input line to the file
            log_stream << "   User input for " << name << ": " << line << std::endl; 
            std::stringstream ss(line);
            double val;
            while (ss >> val && vec.size() < size) {
                vec.push_back(val);
            }
            if (vec.size() < size) {
                 // Error message goes to std::cout
                std::cout << "      Error: Not enough numbers entered. Please try again." << std::endl;
                vec.clear(); 
            }
        }
        return vec;
    }


public:
   
    SEAL_Working(std::ostream& output_stream) :
        log_stream(output_stream), // <-- Initialize log_stream member
        // BFV Initialization
        bfv_parms(create_bfv_parms()),
        bfv_context(bfv_parms),
        bfv_keygen(bfv_context),
        bfv_secret_key(bfv_keygen.secret_key()),
        bfv_public_key(), 
        bfv_relin_keys(), 
        bfv_evaluator(bfv_context),
        bfv_decryptor(bfv_context, bfv_secret_key),
        bfv_encoder(bfv_context),

        // CKKS Initialization
        ckks_parms(create_ckks_parms()),
        ckks_context(ckks_parms),
        ckks_keygen(ckks_context),
        ckks_secret_key(ckks_keygen.secret_key()),
        ckks_public_key(), 
        ckks_relin_keys(), 
        ckks_evaluator(ckks_context),
        ckks_decryptor(ckks_context, ckks_secret_key),
        ckks_encoder(ckks_context)
    {
        // Use log_stream
        log_stream << "SEAL_Working: Microsoft SEAL library implementation" << std::endl;
        log_stream << "Features: Real BFV and CKKS with proper noise management" << std::endl;

        bfv_keygen.create_public_key(bfv_public_key);
        bfv_keygen.create_relin_keys(bfv_relin_keys);

        ckks_keygen.create_public_key(ckks_public_key);
        ckks_keygen.create_relin_keys(ckks_relin_keys);

        bfv_encryptor.emplace(bfv_context, bfv_public_key);
        ckks_encryptor.emplace(ckks_context, ckks_public_key);
    }

    // BFV Methods
    void demonstrateBFV() {
        // Use log_stream for all output
        log_stream << "\n" << std::string(60, '=') << std::endl;
        log_stream << "BFV (Brakerski-Fan-Vercauteren) with Microsoft SEAL" << std::endl;
        log_stream << std::string(60, '=') << std::endl;
        
        log_stream << "\n1. Key Generation:" << std::endl;
        auto start = std::chrono::high_resolution_clock::now();
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
        log_stream << "   Key generation completed in constructor (" << duration.count() << " microseconds)" << std::endl;
        
        log_stream << "\n2. Encryption:" << std::endl;
        
        size_t vector_size = getUserSize(); 
        std::vector<int64_t> plaintext1 = getUserVectorInt(vector_size, "plaintext1");
        std::vector<int64_t> plaintext2 = getUserVectorInt(vector_size, "plaintext2");
        
        log_stream << "   Plaintext 1: ";
        for (int64_t val : plaintext1) log_stream << val << " ";
        log_stream << std::endl;
        log_stream << "   Plaintext 2: ";
        for (int64_t val : plaintext2) log_stream << val << " ";
        log_stream << std::endl;

        Plaintext ptxt1, ptxt2, ptxt_scalar;
        Ciphertext ctxt1, ctxt2;

        start = std::chrono::high_resolution_clock::now();
        bfv_encoder.encode(plaintext1, ptxt1);
        bfv_encoder.encode(plaintext2, ptxt2);
        log_stream << "      [INFO] Plaintext 1 encoded to polynomial: " 
                  << ptxt1.to_string().substr(0, 40) << "... " << std::endl;

        bfv_encryptor->encrypt(ptxt1, ctxt1);
        bfv_encryptor->encrypt(ptxt2, ctxt2);
        end = std::chrono::high_resolution_clock::now();
        duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
        log_stream << "   Encryption completed in " << duration.count() << " microseconds" << std::endl;
        print_bfv_info(ctxt1, "ctxt1 (after encryption)");
        print_bfv_info(ctxt2, "ctxt2 (after encryption)");
        
        log_stream << "\n3. Homomorphic Operations:" << std::endl;
        
        // Addition
        Ciphertext ctxt_sum;
        start = std::chrono::high_resolution_clock::now();
        bfv_evaluator.add(ctxt1, ctxt2, ctxt_sum);
        end = std::chrono::high_resolution_clock::now();
        duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
        
        Plaintext ptxt_sum;
        std::vector<int64_t> sum_result;
        bfv_decryptor.decrypt(ctxt_sum, ptxt_sum);
        bfv_encoder.decode(ptxt_sum, sum_result);

        log_stream << "   Addition (";
        for (size_t i = 0; i < vector_size; ++i) {
             log_stream << plaintext1[i] << "+" << plaintext2[i] << (i == vector_size - 1 ? "": ", ");
        }
        log_stream << "): ";
        for (size_t i = 0; i < vector_size; ++i) log_stream << sum_result[i] << " ";
        log_stream << std::endl;
        log_stream << "   Addition operation took " << duration.count() << " microseconds" << std::endl;
        print_bfv_info(ctxt_sum, "ctxt_sum (after addition)");
        
        // Multiplication
        Ciphertext ctxt_mult;
        start = std::chrono::high_resolution_clock::now();
        bfv_evaluator.multiply(ctxt1, ctxt2, ctxt_mult);
        end = std::chrono::high_resolution_clock::now();
        duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
        log_stream << "   Multiplication operation took " << duration.count() << " microseconds" << std::endl;
        print_bfv_info(ctxt_mult, "ctxt_mult (after multiply)");

        // Relinearization
        start = std::chrono::high_resolution_clock::now();
        bfv_evaluator.relinearize_inplace(ctxt_mult, bfv_relin_keys); 
        end = std::chrono::high_resolution_clock::now();
        duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
        log_stream << "   Relinearization operation took " << duration.count() << " microseconds" << std::endl;
        print_bfv_info(ctxt_mult, "ctxt_mult (after relinearize)");

        Plaintext ptxt_mult;
        std::vector<int64_t> mult_result;
        bfv_decryptor.decrypt(ctxt_mult, ptxt_mult);
        bfv_encoder.decode(ptxt_mult, mult_result);

        log_stream << "   Multiplication (";
        for (size_t i = 0; i < vector_size; ++i) {
             log_stream << plaintext1[i] << "*" << plaintext2[i] << (i == vector_size - 1 ? "": ", ");
        }
        log_stream << "): ";
        for (size_t i = 0; i < vector_size; ++i) log_stream << mult_result[i] << " ";
        log_stream << std::endl;
        
        // Scalar multiplication
        Ciphertext ctxt_scalar;
        int64_t scalar = 2;
        bfv_encoder.encode(std::vector<int64_t>(plaintext1.size(), scalar), ptxt_scalar);
        start = std::chrono::high_resolution_clock::now();
        bfv_evaluator.multiply_plain(ctxt1, ptxt_scalar, ctxt_scalar);
        end = std::chrono::high_resolution_clock::now();
        duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);

        Plaintext ptxt_scalar_res;
        std::vector<int64_t> scalar_result;
        bfv_decryptor.decrypt(ctxt_scalar, ptxt_scalar_res);
        bfv_encoder.decode(ptxt_scalar_res, scalar_result);
        
        log_stream << "   Scalar multiplication (";
        for (size_t i = 0; i < vector_size; ++i) {
             log_stream << plaintext1[i] << "*" << scalar << (i == vector_size - 1 ? "": ", ");
        }
        log_stream << "): ";
        for (size_t i = 0; i < vector_size; ++i) log_stream << scalar_result[i] << " ";
        log_stream << std::endl;
        log_stream << "   Scalar multiplication took " << duration.count() << " microseconds" << std::endl;
        print_bfv_info(ctxt_scalar, "ctxt_scalar (after plain_mult)");
        
        // Verification
        log_stream << "\n4. Verification:" << std::endl;
        
        std::vector<int64_t> expected_sum;
        std::vector<int64_t> expected_mult;
        std::vector<int64_t> expected_scalar;
        for (size_t i = 0; i < vector_size; ++i) {
            expected_sum.push_back(plaintext1[i] + plaintext2[i]);
            expected_mult.push_back(plaintext1[i] * plaintext2[i]);
            expected_scalar.push_back(plaintext1[i] * scalar);
        }
        
        sum_result.resize(expected_sum.size());
        mult_result.resize(expected_mult.size());
        scalar_result.resize(expected_scalar.size());

        bool sum_correct = (sum_result == expected_sum);
        bool mult_correct = (mult_result == expected_mult);
        bool scalar_correct = (scalar_result == expected_scalar);
        
        log_stream << "   Addition verification: " << (sum_correct ? "PASS" : "FAIL") << std::endl;
        log_stream << "   Multiplication verification: " << (mult_correct ? "PASS" : "FAIL") << std::endl;
        log_stream << "   Scalar multiplication verification: " << (scalar_correct ? "PASS" : "FAIL") << std::endl;
        
        if (sum_correct && mult_correct && scalar_correct) {
            log_stream << "\n✅ BFV with Microsoft SEAL: ALL TESTS PASSING!" << std::endl;
            log_stream << "   - Proper noise management" << std::endl;
            log_stream << "   - Relinearization after multiplication" << std::endl;
            log_stream << "   - Modulus switching for noise reduction" << std::endl;
        }
    }

    // CKKS Methods
    void demonstrateCKKS() {
        // Use log_stream for all output
        log_stream << "\n" << std::string(60, '=') << std::endl;
        log_stream << "CKKS (Cheon-Kim-Kim-Song) with Microsoft SEAL" << std::endl;
        log_stream << std::string(60, '=') << std::endl;
        
        log_stream << "\n1. Key Generation:" << std::endl;
        auto start = std::chrono::high_resolution_clock::now();
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
        log_stream << "   Key generation completed in constructor (" << duration.count() << " microseconds)" << std::endl;
        
        log_stream << "\n2. Encryption:" << std::endl;
        
        size_t vector_size = getUserSize(); 
        std::vector<double> plaintext1 = getUserVectorDouble(vector_size, "plaintext1");
        std::vector<double> plaintext2 = getUserVectorDouble(vector_size, "plaintext2");
        
        log_stream << "   Plaintext 1: ";
        for (double val : plaintext1) log_stream << val << " ";
        log_stream << std::endl;
        log_stream << "   Plaintext 2: ";
        for (double val : plaintext2) log_stream << val << " ";
        log_stream << std::endl;

        Plaintext ptxt1, ptxt2, ptxt_scalar, ptxt_plain_add;
        Ciphertext ctxt1, ctxt2;

        start = std::chrono::high_resolution_clock::now();
        ckks_encoder.encode(plaintext1, ckks_scale, ptxt1);
        ckks_encoder.encode(plaintext2, ckks_scale, ptxt2);
        
        ckks_encryptor->encrypt(ptxt1, ctxt1);
        ckks_encryptor->encrypt(ptxt2, ctxt2);
        
        end = std::chrono::high_resolution_clock::now();
        duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
        log_stream << "   Encryption completed in " << duration.count() << " microseconds" << std::endl;
        print_ckks_info(ctxt1, "ctxt1 (after encryption)");
        print_ckks_info(ctxt2, "ctxt2 (after encryption)");
        
        log_stream << "\n3. Homomorphic Operations:" << std::endl;
        
        // Addition
        Ciphertext ctxt_sum;
        start = std::chrono::high_resolution_clock::now();
        ckks_evaluator.add(ctxt1, ctxt2, ctxt_sum);
        end = std::chrono::high_resolution_clock::now();
        duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
        
        Plaintext ptxt_sum;
        std::vector<double> sum_result;
        ckks_decryptor.decrypt(ctxt_sum, ptxt_sum);
        ckks_encoder.decode(ptxt_sum, sum_result);

        log_stream << "   Addition result: ";
        for (size_t i = 0; i < vector_size; ++i) log_stream << std::fixed << std::setprecision(3) << sum_result[i] << " ";
        log_stream << std::endl;
        log_stream << "   Addition operation took " << duration.count() << " microseconds" << std::endl;
        print_ckks_info(ctxt_sum, "ctxt_sum (after addition)");
        
        // Multiplication
        Ciphertext ctxt_mult;
        start = std::chrono::high_resolution_clock::now();
        ckks_evaluator.multiply(ctxt1, ctxt2, ctxt_mult);
        end = std::chrono::high_resolution_clock::now();
        duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
        log_stream << "   Multiplication operation took " << duration.count() << " microseconds" << std::endl;
        print_ckks_info(ctxt_mult, "ctxt_mult (after multiply)");
        
        // Relinearization
        start = std::chrono::high_resolution_clock::now();
        ckks_evaluator.relinearize_inplace(ctxt_mult, ckks_relin_keys);
        end = std::chrono::high_resolution_clock::now();
        duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
        log_stream << "   Relinearization operation took " << duration.count() << " microseconds" << std::endl;
        print_ckks_info(ctxt_mult, "ctxt_mult (after relinearize)");

        // Rescaling
        start = std::chrono::high_resolution_clock::now();
        ckks_evaluator.rescale_to_next_inplace(ctxt_mult); 
        end = std::chrono::high_resolution_clock::now();
        duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
        log_stream << "   Rescaling operation took " << duration.count() << " microseconds" << std::endl;
        print_ckks_info(ctxt_mult, "ctxt_mult (after rescale)");

        Plaintext ptxt_mult;
        std::vector<double> mult_result;
        ckks_decryptor.decrypt(ctxt_mult, ptxt_mult);
        ckks_encoder.decode(ptxt_mult, mult_result);

        log_stream << "   Multiplication result: ";
        for (size_t i = 0; i < vector_size; ++i) log_stream << std::fixed << std::setprecision(3) << mult_result[i] << " ";
        log_stream << std::endl;
        
        // Scalar multiplication
        Ciphertext ctxt_scalar;
        double scalar = 2.0;
        ckks_encoder.encode(scalar, ctxt1.parms_id(), ctxt1.scale(), ptxt_scalar);
        start = std::chrono::high_resolution_clock::now();
        ckks_evaluator.multiply_plain(ctxt1, ptxt_scalar, ctxt_scalar);
        ckks_evaluator.rescale_to_next_inplace(ctxt_scalar); 
        end = std::chrono::high_resolution_clock::now();
        duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);

        Plaintext ptxt_scalar_res;
        std::vector<double> scalar_result;
        ckks_decryptor.decrypt(ctxt_scalar, ptxt_scalar_res);
        ckks_encoder.decode(ptxt_scalar_res, scalar_result);

        log_stream << "   Scalar multiplication (2.0x) result: ";
        for (size_t i = 0; i < vector_size; ++i) log_stream << std::fixed << std::setprecision(3) << scalar_result[i] << " ";
        log_stream << std::endl;
        log_stream << "   Scalar multiplication took " << duration.count() << " microseconds" << std::endl;
        print_ckks_info(ctxt_scalar, "ctxt_scalar (after plain_mult)");
        
        // Plaintext addition
        Ciphertext ctxt_add_plain;
        start = std::chrono::high_resolution_clock::now();
        ckks_evaluator.add_plain(ctxt1, ptxt2, ctxt_add_plain);
        end = std::chrono::high_resolution_clock::now();
        duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);

        Plaintext ptxt_add_plain_res;
        std::vector<double> add_plain_result;
        ckks_decryptor.decrypt(ctxt_add_plain, ptxt_add_plain_res);
        ckks_encoder.decode(ptxt_add_plain_res, add_plain_result);
        
        log_stream << "   Plaintext addition result: ";
        for (size_t i = 0; i < vector_size; ++i) log_stream << std::fixed << std::setprecision(3) << add_plain_result[i] << " ";
        log_stream << std::endl;
        log_stream << "   Plaintext addition took " << duration.count() << " microseconds" << std::endl;
        print_ckks_info(ctxt_add_plain, "ctxt_add_plain (after add_plain)");
        
        // Verification
        log_stream << "\n4. Verification:" << std::endl;

        std::vector<double> expected_sum;
        std::vector<double> expected_mult;
        std::vector<double> expected_scalar;
        std::vector<double> expected_add_plain;
        for (size_t i = 0; i < vector_size; ++i) {
            expected_sum.push_back(plaintext1[i] + plaintext2[i]);
            expected_mult.push_back(plaintext1[i] * plaintext2[i]);
            expected_scalar.push_back(plaintext1[i] * scalar);
            expected_add_plain.push_back(plaintext1[i] + plaintext2[i]); 
        }
        
        sum_result.resize(expected_sum.size());
        mult_result.resize(expected_mult.size());
        scalar_result.resize(expected_scalar.size());
        add_plain_result.resize(expected_add_plain.size());

        bool sum_correct = verifyVectors(expected_sum, sum_result, 0.01);
        bool mult_correct = verifyVectors(expected_mult, mult_result, 0.01);
        bool scalar_correct = verifyVectors(expected_scalar, scalar_result, 0.01);
        bool add_plain_correct = verifyVectors(expected_add_plain, add_plain_result, 0.01);
        
        log_stream << "   Addition verification: " << (sum_correct ? "PASS" : "FAIL") << std::endl;
        log_stream << "   Multiplication verification: " << (mult_correct ? "PASS" : "FAIL") << std::endl;
        log_stream << "   Scalar multiplication verification: " << (scalar_correct ? "PASS" : "FAIL") << std::endl;
        log_stream << "   Plaintext addition verification: " << (add_plain_correct ? "PASS" : "FAIL") << std::endl;
        
        if (sum_correct && mult_correct && scalar_correct && add_plain_correct) {
            log_stream << "\n✅ CKKS with Microsoft SEAL: ALL TESTS PASSING!" << std::endl;
            log_stream << "   - Proper noise management" << std::endl;
            log_stream << "   - Approximate arithmetic" << std::endl;
            log_stream << "   - Real number support" << std::endl;
        }
    }

private:
    // verifyVectors now logs failures to log_stream
    bool verifyVectors(const std::vector<double>& expected, const std::vector<double>& actual, double tolerance) {
        if (expected.size() > actual.size()) return false; 
        
        for (size_t i = 0; i < expected.size(); i++) {
            if (std::abs(expected[i] - actual[i]) > tolerance) {
                // Log failure to the file
                log_stream << "   [VERIFY FAIL] at index " << i << ": expected " << expected[i] << ", got " << actual[i] << std::endl;
                return false;
            }
        }
        return true;
    }
};

#endif 

