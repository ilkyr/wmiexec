#define _WIN32_DCOM
#define UNICODE
#include <iostream>
using namespace std;
#include <comdef.h>
#include <Wbemidl.h>
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "credui.lib")
#pragma comment(lib, "comsuppw.lib")
#include <wincred.h>
#include <strsafe.h>

// Function to concatenate two BSTR strings
BSTR Concat(BSTR a, BSTR b)
{
    auto lengthA = SysStringLen(a);
    auto lengthB = SysStringLen(b);

    auto result = SysAllocStringLen(NULL, lengthA + lengthB);

    memcpy(result, a, lengthA * sizeof(OLECHAR));
    memcpy(result + lengthA, b, lengthB * sizeof(OLECHAR));

    result[lengthA + lengthB] = 0;
    return result;
}


int __cdecl main(int argc, char** argv)
{
    HRESULT hres;

    // Step 1: Initialize COM
    hres = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hres))
    {
        cout << "Failed to initialize COM library. Error code = 0x"
            << hex << hres << endl;
        return 1;
    }

    // Step 2: Set general COM security levels
    hres = CoInitializeSecurity(
        NULL,
        -1,                          // COM authentication
        NULL,                        // Authentication services
        NULL,                        // Reserved
        RPC_C_AUTHN_LEVEL_DEFAULT,   // Default authentication 
        RPC_C_IMP_LEVEL_IDENTIFY,    // Default Impersonation  
        NULL,                        // Authentication info
        EOAC_NONE,                   // Additional capabilities 
        NULL                         // Reserved
    );


    if (FAILED(hres))
    {
        cout << "Failed to initialize security. Error code = 0x"
            << hex << hres << endl;
        CoUninitialize();
        return 1;
    }

    // Step 3: Obtain the initial locator to WMI
    IWbemLocator* pLoc = NULL;

    hres = CoCreateInstance(
        CLSID_WbemLocator,
        0,
        CLSCTX_INPROC_SERVER,
        IID_IWbemLocator, (LPVOID*)&pLoc);

    if (FAILED(hres))
    {
        cout << "Failed to create IWbemLocator object."
            << " Err code = 0x"
            << hex << hres << endl;
        CoUninitialize();
        return 1;
    }

    // Step 4: Check if the required arguments are provided
    if (argc != 6) {
        wcout << L"Usage: " << argv[0] << L" <Target-host> <Domain> <Username> <Password> <Command>" << endl;
        return 1;
    }

    string target = argv[1];
    string domain = argv[2];
    string username = argv[3];
    string password = argv[4];
    string commandArg = argv[5];

    wstring targetW = wstring(target.begin(), target.end());
    wstring domainW = wstring(domain.begin(), domain.end());
    wstring usernameW = wstring(username.begin(), username.end());
    wstring passwordW = wstring(password.begin(), password.end());
    wstring commandArgW = wstring(commandArg.begin(), commandArg.end());

    // Step 5: Connect to WMI through the IWbemLocator::ConnectServer method
    IWbemServices* pSvc = NULL;

    // Construct the WMI path
    wstring wmiPath = L"\\\\" + targetW + L"\\root\\cimv2";


    // Connect to the remote root\cimv2 namespace
    // and obtain pointer pSvc to make IWbemServices calls    
    hres = pLoc->ConnectServer(
        _bstr_t(wmiPath.c_str()),             // WMI Path
        _bstr_t(usernameW.c_str()),    // User name
        _bstr_t(password.c_str()),     // User password
        NULL,                              // Locale             
        NULL,                              // Security flags
        NULL,                              // Authority        
        NULL,                              // Context object 
        &pSvc                              // IWbemServices proxy
    );

    if (FAILED(hres))
    {
        cout << "Could not connect. Error code = 0x"
            << hex << hres << endl;
        pLoc->Release();
        CoUninitialize();
        return 1;                // Program has failed.
    }

    cout << "Connected to ROOT\\CIMV2 WMI namespace" << endl;


    // step 6: Create COAUTHIDENTITY that can be used for setting security on proxy
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


    // Step 7: Set security levels on a WMI connection
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
        cout << "Could not set proxy blanket. Error code = 0x"
            << hex << hres << endl;
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return 1;
    }

    // Step 8: Use the IWbemServices pointer to make requests of WMI
    IEnumWbemClassObject* pEnumerator = NULL;

    // Obtain the WMI class object for Win32_Process
    IWbemClassObject* pClass = NULL;
    hres = pSvc->GetObject(_bstr_t(L"Win32_Process"), 0, NULL, &pClass, NULL);

    // Obtain the method parameters for the Create method
    IWbemClassObject* pInParamsDefinition = NULL;
    hres = pClass->GetMethod(_bstr_t(L"Create"), 0, &pInParamsDefinition, NULL);

    // Create an instance of the input parameters
    IWbemClassObject* pClassInstance = NULL;
    hres = pInParamsDefinition->SpawnInstance(0, &pClassInstance);

    // Prepare the command to be executed
    BSTR className = SysAllocString(L"Win32_Process");
    BSTR methodName = SysAllocString(L"Create");
    BSTR prefix = SysAllocString(L"cmd.exe /C ");
    BSTR argument = SysAllocString(commandArgW.c_str());
    BSTR command = Concat(prefix, argument);


    // Set the command line for execution
    VARIANT varCommand;
    varCommand.vt = VT_BSTR;
    varCommand.bstrVal = command;
    hres = pClassInstance->Put(L"CommandLine", 0, &varCommand, 0);

    // Execute the command
    IWbemClassObject* pOutParams = NULL;
    hres = pSvc->ExecMethod(className, methodName, 0, NULL, pClassInstance, &pOutParams, NULL);

    // Error checking and cleanup
    SysFreeString(className);
    SysFreeString(methodName);
    SysFreeString(prefix);
    SysFreeString(argument);
    SysFreeString(command);

    // When you have finished using the credentials,
    // erase them from memory.
    SecureZeroMemory(&passwordW[0], passwordW.size() * sizeof(wchar_t));
    SecureZeroMemory(&usernameW[0], usernameW.size() * sizeof(wchar_t));
    SecureZeroMemory(&domainW[0], domainW.size() * sizeof(wchar_t));


    // Cleanup
    pSvc->Release();
    pLoc->Release();

    CoUninitialize();

    return 0;
}