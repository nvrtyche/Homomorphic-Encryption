# Makefile for Working BFV and CKKS Implementation
# CS 6530 Applied Cryptography Course Project - Phase 2

CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -O2 -g

# --- Use your specific SEAL 4.1 paths ---
SEAL_CFLAGS = -I/usr/local/include/SEAL-4.1
SEAL_LIBS = -L/usr/local/lib -lseal-4.1
# ---

TARGET = homomorphic_working
SOURCES = main.cpp
HEADERS = SEAL_Working.h

# Default target
all: $(TARGET)

# Build the main executable
# This rule now correctly combines all flags
$(TARGET): $(SOURCES) $(HEADERS)
	$(CXX) $(CXXFLAGS) $(SEAL_CFLAGS) -o $(TARGET) $(SOURCES) $(SEAL_LIBS)
	@echo "Build completed successfully!"

# Clean build artifacts
clean:
	rm -f $(TARGET) *.o
	@echo "Clean completed!"

# Run the program
run: $(TARGET)
	./$(TARGET)

# Show help
help:
	@echo "Available targets:"
	@echo "  all        - Build the program (default)"
	@echo "  clean      - Remove build artifacts"
	@echo "  run        - Build and run the program"
	@echo "  help       - Show this help message"

.PHONY: all clean run help
