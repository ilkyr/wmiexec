#define _CRT_SECURE_NO_WARNINGS
#define _WIN32_DCOM
#define UNICODE
#include <iostream>
#include <comdef.h>
#include <Wbemidl.h>
#include <wincred.h>
#include <strsafe.h>
#include <Windows.h>
#include <string>
#include <fstream>
#include <chrono>
#include <ctime>
#include <sstream>
#include <iomanip>
#include <map>
#include "smb_connection.h"
#include "argument_utility.h"
#include "concat.h"
#include "output_handling.h"
#include "remote_command.h"
#include "usage_utility.h"


#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "credui.lib")
#pragma comment(lib, "comsuppw.lib")
#pragma comment(lib, "Mpr.lib")


int __cdecl main(int argc, char** argv) {
    HRESULT hres;

    // Initialize COM
    hres = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hres)) {
        std::cout << "Failed to initialize COM library. Error code = 0x" << std::hex << hres << std::endl;
        return 1;
    }

    // Set general COM security levels
    hres = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IDENTIFY, NULL, EOAC_NONE, NULL);
    if (FAILED(hres)) {
        std::cout << "Failed to initialize security. Error code = 0x" << std::hex << hres << std::endl;
        CoUninitialize();
        return 1;
    }

    // Obtain the initial locator to WMI
    IWbemLocator* pLoc = NULL;
    hres = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc);
    if (FAILED(hres)) {
        std::cout << "Failed to create IWbemLocator object. Err code = 0x" << std::hex << hres << std::endl;
        CoUninitialize();
        return 1;
    }

    // Process command line arguments
    std::map<std::string, std::string> args;
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-h" || arg == "--help") {
            printUsage(argv[0]);
            return 0;
        }
        else if ((arg == "-t" || arg == "--target" || arg == "-d" || arg == "--domain" ||
            arg == "-u" || arg == "--user" || arg == "-p" || arg == "--password") && i + 1 < argc) {
            args[getArgKey(arg)] = argv[++i];
        }
        else {
            std::cerr << "Invalid argument or missing value: " << arg << std::endl;
            printUsage(argv[0]);
            return 1;
        }
    }

    if (args.find("-t") == args.end() || args.find("-d") == args.end() ||
        args.find("-u") == args.end() || args.find("-p") == args.end()) {
        std::cerr << "Missing required arguments." << std::endl;
        printUsage(argv[0]);
        return 1;
    }

    // Extract and convert values to wide strings
    std::wstring targetW = std::wstring(args["-t"].begin(), args["-t"].end());
    std::wstring domainW = std::wstring(args["-d"].begin(), args["-d"].end());
    std::wstring usernameW = std::wstring(args["-u"].begin(), args["-u"].end());
    std::wstring passwordW = std::wstring(args["-p"].begin(), args["-p"].end());

    // Connect to WMI through the IWbemLocator::ConnectServer method
    IWbemServices* pSvc = NULL;
    std::wstring wmiPath = L"\\\\" + targetW + L"\\root\\cimv2";
    hres = pLoc->ConnectServer(_bstr_t(wmiPath.c_str()), _bstr_t(usernameW.c_str()), _bstr_t(passwordW.c_str()), NULL, NULL, NULL, NULL, &pSvc);
    if (FAILED(hres)) {
        std::cout << "Could not connect. Error code = 0x" << std::hex << hres << std::endl;
        pLoc->Release();
        CoUninitialize();
        return 1;
    }

    // Create COAUTHIDENTITY that can be used for setting security on proxy
    COAUTHIDENTITY* userAcct = NULL;
    COAUTHIDENTITY authIdent = { 0 };
    authIdent.User = (USHORT*)usernameW.c_str();
    authIdent.UserLength = usernameW.size();
    authIdent.Domain = (USHORT*)domainW.c_str();
    authIdent.DomainLength = domainW.size();
    authIdent.Password = (USHORT*)passwordW.c_str();
    authIdent.PasswordLength = passwordW.size();
    authIdent.Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;

    userAcct = &authIdent;


    if (FAILED(hres))
    {
        std::cout << "Could not set proxy blanket. Error code = 0x"
            << std::hex << hres << std::endl;
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return 1;
    }

    // Set security levels on a WMI connection
    hres = CoSetProxyBlanket(pSvc, RPC_C_AUTHN_DEFAULT, RPC_C_AUTHZ_DEFAULT, COLE_DEFAULT_PRINCIPAL, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE, userAcct, EOAC_NONE);
    if (FAILED(hres)) {
        std::cerr << "Failed to set proxy blanket. Error code = 0x" << std::hex << hres << std::endl;
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return 1;
    }

    // Connect to SMB share
    std::wstring smbSharePath = L"\\\\" + targetW + L"\\ADMIN$";
    DWORD dwResult = ConnectToSMBShare(smbSharePath, domainW + L"\\" + usernameW, passwordW);
    if (dwResult != NO_ERROR) {
        std::cerr << "Failed to connect to SMB share. Error code = " << dwResult << std::endl;
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return 1;
    }

    std::cout << "Connected to ROOT\\CIMV2 WMI namespace" << std::endl;
    std::cout << "Enter commands to execute remotely (type 'exit' to quit):" << std::endl;

    std::string commandLine;
    int commandCounter = 0; // A counter to generate unique filenames

    while (true) {
        std::cout << "> ";
        std::getline(std::cin, commandLine);
        if (commandLine == "exit") break;

        if (commandLine.empty()) {
            continue;
        }

        // Fetch current time at the beginning of each loop iteration
        auto t = std::time(nullptr);
        std::tm tm;
        localtime_s(&tm, &t);

        // Create a unique filename using the timestamp and command counter
        std::wostringstream ws;
        ws << std::put_time(&tm, L"%Y%m%d%H%M%S") << L"_" << commandCounter++;
        std::wstring timestamp = ws.str();

        std::wstring outputFilePath = smbSharePath + L"\\output_" + timestamp + L".txt";
        std::wstring commandLineW = std::wstring(commandLine.begin(), commandLine.end());

        if (ExecuteRemoteCommand(commandLineW, pSvc, outputFilePath)) {
            Sleep(1000); // Allow time for command execution and output to be written
            ReadAndHandleOutput(outputFilePath);
        }
        else {
            std::cout << "Failed to execute command." << std::endl;
        }
    }

    // When you have finished using the credentials,
    // erase them from memory.
    SecureZeroMemory(&passwordW[0], passwordW.size() * sizeof(wchar_t));
    SecureZeroMemory(&usernameW[0], usernameW.size() * sizeof(wchar_t));
    SecureZeroMemory(&domainW[0], domainW.size() * sizeof(wchar_t));

    // Cleanup
    pSvc->Release();
    pLoc->Release();

    return 0;
}
