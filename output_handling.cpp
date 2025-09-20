#include "output_handling.h"
#include <fstream>
#include <iostream>
#include <Windows.h>

void ReadAndHandleOutput(const std::wstring& outputPath) {
    const int maxAttempts = 10;
    int attempts = 0;

    while (attempts < maxAttempts) {
        std::wifstream outputFile(outputPath);
        if (outputFile.is_open()) {
            std::wstring line;
            while (std::getline(outputFile, line)) {
                std::wcout << line << std::endl;
            }
            outputFile.close();

            if (!DeleteFileW(outputPath.c_str())) {
                std::wcout << L"Failed to delete output file." << std::endl;
            }
            return;
        }
        else {
            attempts++;
            Sleep(1000);
        }
    }

    std::wcout << L"Failed to open output file after several attempts." << std::endl;
}

void ReadOutputSMBShare(const std::wstring& outputPath) {
    std::wifstream outputFile(outputPath);
    if (outputFile.is_open()) {
        std::wstring line;
        while (std::getline(outputFile, line)) {
            std::wcout << line << std::endl;
        }
        outputFile.close();
    }
    else {
        std::wcout << L"Failed to open output file." << std::endl;
    }

    if (!DeleteFileW(outputPath.c_str())) {
        std::wcout << L"Failed to delete output file." << std::endl;
    }
}
