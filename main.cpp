#include "SEAL_Working.h"
#include <iostream>
#include <iomanip>
#include <fstream> 
#include <string> 


void compareProtocols(std::ostream& log_stream) {
    log_stream << "\n" << std::string(60, '=') << std::endl;
    log_stream << "BFV vs CKKS Protocol Comparison" << std::endl;
    log_stream << std::string(60, '=') << std::endl;
    
    log_stream << "\nProtocol Characteristics:" << std::endl;
    log_stream << std::left << std::setw(20) << "Feature" 
              << std::setw(20) << "BFV" 
              << std::setw(20) << "CKKS" << std::endl;
    log_stream << std::string(60, '-') << std::endl;
    
    log_stream << std::left << std::setw(20) << "Data Type" 
              << std::setw(20) << "Integers" 
              << std::setw(20) << "Real Numbers" << std::endl;
    
    log_stream << std::left << std::setw(20) << "Precision" 
              << std::setw(20) << "Exact" 
              << std::setw(20) << "Approximate" << std::endl;
    
    log_stream << std::left << std::setw(20) << "Use Cases" 
              << std::setw(20) << "Exact Arithmetic" 
              << std::setw(20) << "ML/Analytics" << std::endl;
    
    log_stream << std::left << std::setw(20) << "Noise Growth" 
              << std::setw(20) << "Controlled" 
              << std::setw(20) << "Controlled" << std::endl;
    
    log_stream << std::left << std::setw(20) << "Bootstrapping" 
              << std::setw(20) << "Supported" 
              << std::setw(20) << "Supported" << std::endl;
    
    log_stream << "\nPerformance Analysis:" << std::endl;
    log_stream << "- BFV: Better for exact integer computations, voting systems, secure databases" << std::endl;
    log_stream << "- CKKS: Better for machine learning, statistical analysis, real-world applications" << std::endl;
    log_stream << "- Both schemes support addition and multiplication on encrypted data" << std::endl;
    log_stream << "- Both use Microsoft SEAL with proper noise management" << std::endl;
    log_stream << "- Both support bootstrapping for unlimited operations" << std::endl;
    
    log_stream << "\nMicrosoft SEAL Features:" << std::endl;
    log_stream << "- Automatic noise management" << std::endl;
    log_stream << "- Relinearization after multiplication" << std::endl;
    log_stream << "- Modulus switching for noise reduction" << std::endl;
    log_stream << "- Bootstrapping for unlimited operations" << std::endl;
    log_stream << "- Optimized parameter selection" << std::endl;
    log_stream << "- Batch processing support" << std::endl;
    log_stream << "- Python bindings available" << std::endl;
}

void showInstallationInstructions(std::ostream& log_stream) {
    log_stream << "\n" << std::string(60, '=') << std::endl;
    log_stream << "Microsoft SEAL Installation Instructions" << std::endl;
    log_stream << std::string(60, '=') << std::endl;
    
    log_stream << "\n1. Install SEAL using package manager:" << std::endl;
    log_stream << "   sudo apt update" << std::endl;
    log_stream << "   sudo apt install libseal-dev" << std::endl;
    
    log_stream << "\n2. Or build from source:" << std::endl;
    log_stream << "   git clone https://github.com/Microsoft/SEAL.git" << std::endl;
    log_stream << "   cd SEAL" << std::endl;
    log_stream << "   mkdir build && cd build" << std::endl;
    log_stream << "   cmake .." << std::endl;
    log_stream << "   make -j4" << std::endl;
    log_stream << "   sudo make install" << std::endl;
    
    log_stream << "\n3. Compile with SEAL:" << std::endl;
    log_stream << "   g++ -std=c++17 -o phase2_homomorphic main_working.cpp $(pkg-config --cflags --libs seal)" << std::endl;
    
    log_stream << "\n4. Alternative libraries:" << std::endl;
    log_stream << "   - OpenFHE: https://github.com/openfheorg/openfhe-development" << std::endl;
    log_stream << "   - HElib: sudo apt install libhelib-dev" << std::endl;
}

int main() {
    // --- MODIFICATION: Set up file output ---
    std::ofstream log_file("output_log.txt");
    if (!log_file.is_open()) {
        std::cerr << "Error: Could not open output_log.txt for writing." << std::endl;
        return 1; // Exit if file cannot be opened
    }

    // --- MODIFICATION: Use log_file for output ---
    log_file << "CS 6530 Applied Cryptography Course Project - Phase 2" << std::endl;
    log_file << "Working BFV and CKKS Implementation using Microsoft SEAL" << std::endl;
    // log_file << "Date: " << __DATE__ << " " << __TIME__ << std::endl;
    
    try {
        // --- MODIFICATION: Pass log_file to constructor ---
        SEAL_Working seal_working(log_file);
        
        // Demonstrate BFV protocol
        seal_working.demonstrateBFV(); 
        
        // Demonstrate CKKS protocol
        seal_working.demonstrateCKKS();
        
        // --- MODIFICATION: Commented out unwanted sections ---
        // compareProtocols(log_file);
        // showInstallationInstructions(log_file);
        
        // log_file << "\n" << std::string(60, '=') << std::endl;
        // log_file << "Phase 2 Implementation Complete!" << std::endl;
        // log_file << "Both BFV and CKKS homomorphic encryption schemes work correctly" << std::endl;
        // log_file << "with Microsoft SEAL library and proper noise management." << std::endl;
        // log_file << std::string(60, '=') << std::endl;

        // --- Optional: Also print completion message to console ---
        std::cout << "Program finished. Output written to output_log.txt" << std::endl;
        
    } catch (const std::exception& e) {
        // --- MODIFICATION: Log error to file AND console ---
        log_file << "Error: " << e.what() << std::endl;
        std::cerr << "Error: " << e.what() << std::endl;
        log_file.close(); // Ensure file is closed even on error
        return 1;
    }
    
    log_file.close(); // Close the file stream
    return 0;
}

