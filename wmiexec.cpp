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
#include <ctime>
#include <map>

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "credui.lib")
#pragma comment(lib, "comsuppw.lib")

// Concatenates two BSTR strings.
BSTR Concat(BSTR a, BSTR b);

// Establishes an SMB connection to a remote share.
DWORD ConnectToSMBShare(const std::wstring& remoteName, const std::wstring& username, const std::wstring& password);

// Executes a command remotely via WMI and saves the output to a specified file.
bool ExecuteRemoteCommand(const std::wstring& command, IWbemServices* pSvc, const std::wstring& outputFilePath);

// Reads and handles the output from a given file path, with retries.
void ReadAndHandleOutput(const  std::wstring& outputPath);

// Reads output from an SMB share.
void ReadOutputSMBShare(const std::wstring& outputPath);

// Prints usage information for the program.
void printUsage(const char* programName);

// Maps long-form command line arguments to their corresponding short-form keys.
std::string getArgKey(const std::string& arg);

int __cdecl main(int argc, char** argv) {
    HRESULT hres;
    DWORD dwResult;

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


    // Set security levels on a WMI connection
    hres = CoSetProxyBlanket(
        pSvc,                           // Indicates the proxy to set
        RPC_C_AUTHN_DEFAULT,            // RPC_C_AUTHN_xxx
        RPC_C_AUTHZ_DEFAULT,            // RPC_C_AUTHZ_xxx
        COLE_DEFAULT_PRINCIPAL,         // Server principal name 
        RPC_C_AUTHN_LEVEL_PKT_PRIVACY,  // RPC_C_AUTHN_LEVEL_xxx 
        RPC_C_IMP_LEVEL_IMPERSONATE,    // RPC_C_IMP_LEVEL_xxx
        userAcct,                       // client identity
        EOAC_NONE                       // proxy capabilities 
    );

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
    dwResult = ConnectToSMBShare(smbSharePath, domainW + L"\\" + usernameW, passwordW);
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

        // Get the current time
        auto t = std::time(nullptr);
        struct tm tm;
        if (localtime_s(&tm, &t) == 0) {
            auto tm = *std::localtime(&t);
        }

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

// Concatenates two BSTR strings.
BSTR Concat(BSTR a, BSTR b) {
    if (a == NULL || b == NULL) return NULL;

    auto lengthA = SysStringLen(a);
    auto lengthB = SysStringLen(b);

    auto result = SysAllocStringLen(NULL, lengthA + lengthB);
    if (result == NULL) {
        return NULL;
    }

    if (lengthA > 0) {
        memcpy(result, a, lengthA * sizeof(OLECHAR));
    }
    if (lengthB > 0) {
        memcpy(result + lengthA, b, lengthB * sizeof(OLECHAR));
    }

    result[lengthA + lengthB] = 0;
    return result;
}

// Establishes an SMB connection to a remote share.
DWORD ConnectToSMBShare(const std::wstring& remoteName, const std::wstring& username, const std::wstring& password) {
    NETRESOURCE nr = { 0 };
    nr.dwType = RESOURCETYPE_DISK;
    nr.lpLocalName = NULL;

    // Allocate memory for the remote name
    wchar_t* dynamicRemoteName = new wchar_t[remoteName.length() + 1];
    wcscpy_s(dynamicRemoteName, remoteName.length() + 1, remoteName.c_str());
    nr.lpRemoteName = dynamicRemoteName; // Assign dynamically allocated name

    // Connect to the SMB share
    DWORD dwResult = WNetAddConnection2(&nr, password.c_str(), username.c_str(), CONNECT_TEMPORARY);

    // Free the dynamically allocated memory
    delete[] dynamicRemoteName;

    return dwResult;
}

// Executes a command remotely via WMI and saves the output to a specified file.
bool ExecuteRemoteCommand(const std::wstring& command, IWbemServices* pSvc, const std::wstring& outputFilePath) {
    IWbemClassObject* pClass = NULL;
    IWbemClassObject* pInParamsDefinition = NULL;
    IWbemClassObject* pClassInstance = NULL;
    IWbemClassObject* pOutParams = NULL;
    HRESULT hres;

    // Obtain the class object for Win32_Process
    BSTR className = SysAllocString(L"Win32_Process");
    hres = pSvc->GetObject(className, 0, NULL, &pClass, NULL);
    if (FAILED(hres)) {
        SysFreeString(className);
        return false;
    }

    // Get the method parameters for the "Create" method
    BSTR methodName = SysAllocString(L"Create");
    hres = pClass->GetMethod(methodName, 0, &pInParamsDefinition, NULL);
    if (FAILED(hres)) {
        SysFreeString(className);
        SysFreeString(methodName);
        pClass->Release();
        return false;
    }

    // Create an instance of the input parameters
    hres = pInParamsDefinition->SpawnInstance(0, &pClassInstance);
    if (FAILED(hres)) {
        SysFreeString(className);
        SysFreeString(methodName);
        pInParamsDefinition->Release();
        pClass->Release();
        return false;
    }

    // Construct the full command to execute and redirect output
    BSTR cmdPrefix = SysAllocString(L"cmd.exe /C ");
    BSTR fullCommand = Concat(cmdPrefix, Concat(SysAllocString(command.c_str()), SysAllocString((L" > " + outputFilePath).c_str())));
    SysFreeString(cmdPrefix);

    // Set the command in the input parameters
    VARIANT varCommand;
    varCommand.vt = VT_BSTR;
    varCommand.bstrVal = fullCommand;
    hres = pClassInstance->Put(L"CommandLine", 0, &varCommand, 0);

    if (FAILED(hres)) {
        SysFreeString(className);
        SysFreeString(methodName);
        SysFreeString(fullCommand);
        pClassInstance->Release();
        pInParamsDefinition->Release();
        pClass->Release();
        return false;
    }

    // Execute the method
    hres = pSvc->ExecMethod(className, methodName, 0, NULL, pClassInstance, &pOutParams, NULL);

    // Release the allocated resources
    SysFreeString(className);
    SysFreeString(methodName);
    SysFreeString(fullCommand);
    VariantClear(&varCommand);
    pClassInstance->Release();
    pInParamsDefinition->Release();
    pClass->Release();

    if (pOutParams != NULL) {
        pOutParams->Release();
    }

    return SUCCEEDED(hres);
}

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

// Prints usage information for the program
void printUsage(const char* programName) {
    std::cout << "Usage: " << programName << " -t <target-host> -d <domain> -u <user> -p <password>\n"
        << "Options:\n"
        << "  -t, --target  Target host IP or hostname\n"
        << "  -d, --domain  Domain\n"
        << "  -u, --user    Username\n"
        << "  -p, --password Password\n"
        << "  -h, --help    Show this help message\n";
}

// Maps long-form command line arguments to their corresponding short-form keys
std::string getArgKey(const std::string& arg) {
    if (arg == "--target") return "-t";
    if (arg == "--domain") return "-d";
    if (arg == "--user") return "-u";
    if (arg == "--password") return "-p";
    return arg; // For short-form arguments
}
