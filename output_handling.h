#ifndef OUTPUT_HANDLING_H
#define OUTPUT_HANDLING_H

#include <Windows.h>
#include <iostream>
#include <fstream>
#include <string>

void ReadAndHandleOutput(const std::wstring& outputPath);
void ReadOutputSMBShare(const std::wstring& outputPath);

#endif // !OUTPUT_HANDLING_H