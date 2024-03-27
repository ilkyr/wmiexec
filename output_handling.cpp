#include "output_handling.h"

// Reads and handles the output from a given file path, with retries.
void ReadAndHandleOutput(const std::wstring& outputPath) {
    const int maxAttempts = 10;
    int attempts = 0;
    std::wifstream outputFile;

    while (attempts < maxAttempts) {
        outputFile.open(outputPath);
        if (outputFile.is_open()) {
            std::wstring line;
            while (getline(outputFile, line)) {
                std::wcout << line << std::endl;
            }
            outputFile.close();

            if (!DeleteFile(outputPath.c_str())) {
                std::wcout << L"Failed to delete output file." << std::endl;
            }
            return;
        }
        else {
            attempts++;
            Sleep(1000); // Wait for 1 second before retrying
        }
    }

    std::wcout << L"Failed to open output file after several attempts." << std::endl;
}

// Reads output from an SMB share.
void ReadOutputSMBShare(const std::wstring& outputPath) {
    std::wifstream outputFile(outputPath);
    if (outputFile.is_open()) {
        std::wstring line;
        while (getline(outputFile, line)) {
            std::wcout << line << std::endl;
        }
        outputFile.close();
    }
    else {
        std::wcout << L"Failed to open output file." << std::endl;
    }

    // Delete the file after reading
    if (!DeleteFile(outputPath.c_str())) {
        std::wcout << L"Failed to delete output file." << std::endl;
    }
}
