#define _WIN32_DCOM

#include <iostream>
#include <string>
#include <map>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <ctime>
#include <Windows.h>
#include <comdef.h>
#include <Wbemidl.h>
#include "smb_connection.h"
#include "argument_utility.h"
#include "concat.h"
#include "output_handling.h"
#include "remote_command.h"
#include "usage_utility.h"

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "comsuppw.lib")
#pragma comment(lib, "Mpr.lib")

static inline void vprint(bool v, const std::string& s) { if (v) std::cout << s << std::endl; }

static void DumpProxyBlanket(IUnknown* pUnk, bool verbose) {
    if (!verbose || !pUnk) return;
    DWORD authn = 0, authz = 0, authnLevel = 0, impLevel = 0, caps = 0;
    OLECHAR* princ = NULL;
    HRESULT hr = CoQueryProxyBlanket(
        pUnk, &authn, &authz, &princ, &authnLevel, &impLevel, NULL, &caps);
    if (SUCCEEDED(hr)) {
        std::cout << "[auth] pSvc authn=" << authn
            << " authnLevel=" << authnLevel
            << " impLevel=" << impLevel
            << " caps=0x" << std::hex << caps << std::dec << std::endl;
    }
    if (princ) CoTaskMemFree(princ);
}

// Prefer Negotiate + SPN (still Kerberos, but avoids strict failures)
static HRESULT SetSvcBlanketKerbPreferred(IWbemServices* pSvc, const std::wstring& spn) {
    if (!pSvc) return E_POINTER;
    OLECHAR* princ = (spn.empty() ? NULL : (OLECHAR*)spn.c_str());
    return CoSetProxyBlanket(
        pSvc,
        RPC_C_AUTHN_GSS_NEGOTIATE,
        RPC_C_AUTHZ_NONE,
        princ,
        RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL,
        EOAC_DYNAMIC_CLOAKING
    );
}

// Hard Kerberos fallback
static HRESULT SetSvcBlanketKerberosHard(IWbemServices* pSvc) {
    if (!pSvc) return E_POINTER;
    return CoSetProxyBlanket(
        pSvc,
        RPC_C_AUTHN_GSS_KERBEROS,
        RPC_C_AUTHZ_NONE,
        NULL,
        RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL,
        EOAC_DYNAMIC_CLOAKING
    );
}

// Bind explicit DOMAIN\user\pass (for -u/-p path)
static HRESULT SetSvcBlanketUserPass(IWbemServices* pSvc,
    const std::wstring& domain,
    const std::wstring& user,
    const std::wstring& pass) {
    if (!pSvc) return E_POINTER;

    COAUTHIDENTITY ident{};
    ident.User = (USHORT*)user.c_str();
    ident.UserLength = (ULONG)user.size();
    ident.Domain = (USHORT*)domain.c_str();
    ident.DomainLength = (ULONG)domain.size();
    ident.Password = (USHORT*)pass.c_str();
    ident.PasswordLength = (ULONG)pass.size();
    ident.Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;

    return CoSetProxyBlanket(
        pSvc,
        RPC_C_AUTHN_WINNT, // SSPI/NTLM
        RPC_C_AUTHZ_NONE,
        NULL,
        RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        &ident,
        EOAC_NONE
    );
}

// ----------------- main -----------------

int __cdecl main(int argc, char** argv) {
    bool useKerberos = false;
    bool verbose = false;

    std::map<std::string, std::string> args;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "-h" || a == "--help") { print_help_and_exit(argv[0]); }
        else if (a == "-k" || a == "--kerberos") { useKerberos = true; }
        else if (a == "-v" || a == "--verbose") { verbose = true; }
        else if ((a == "-t" || a == "--target" ||
            a == "-d" || a == "--domain" ||
            a == "-u" || a == "--user" ||
            a == "-p" || a == "--password") && i + 1 < argc) {
            args[getArgKey(a)] = argv[++i];
        }
        else {
            std::cerr << "Invalid argument or missing value: " << a << std::endl;
            print_help_and_exit(argv[0]);
        }
    }

    if (args.find("-t") == args.end() || args.find("-d") == args.end()) {
        std::cerr << "Missing required arguments: -t and -d are required.\n";
        print_help_and_exit(argv[0]);
    }

    bool haveCreds = (args.find("-u") != args.end() && args.find("-p") != args.end());
    if (!useKerberos && !haveCreds) {
        std::cerr << "Provide -u and -p when not using --kerberos.\n";
        print_help_and_exit(argv[0]);
    }

    std::wstring targetW(args["-t"].begin(), args["-t"].end());
    std::wstring domainW(args["-d"].begin(), args["-d"].end());
    std::wstring usernameW = haveCreds ? std::wstring(args["-u"].begin(), args["-u"].end()) : L"";
    std::wstring passwordW = haveCreds ? std::wstring(args["-p"].begin(), args["-p"].end()) : L"";

    // COM init
    vprint(verbose, "[*] CoInitializeEx");
    HRESULT hr = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hr)) { std::cerr << "CoInitializeEx failed: 0x" << std::hex << hr << std::endl; return 1; }

    vprint(verbose, "[*] CoInitializeSecurity (dynamic cloaking)");
    hr = CoInitializeSecurity(
        NULL, -1, NULL, NULL,
        RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL, EOAC_DYNAMIC_CLOAKING, NULL
    );
    if (FAILED(hr)) {
        std::cerr << "CoInitializeSecurity failed: 0x" << std::hex << hr << std::endl;
        CoUninitialize(); return 1;
    }

    // IWbemLocator
    vprint(verbose, "[*] CoCreateInstance(IWbemLocator)");
    IWbemLocator* pLoc = nullptr;
    hr = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc);
    if (FAILED(hr) || !pLoc) {
        std::cerr << "CoCreateInstance(IWbemLocator) failed: 0x" << std::hex << hr << std::endl;
        CoUninitialize(); return 1;
    }

    // Connect to WMI
    IWbemServices* pSvc = nullptr;
    std::wstring wmiPath = L"\\\\" + targetW + L"\\root\\cimv2";
    BSTR bPath = SysAllocString(wmiPath.c_str());

    BSTR bUser = NULL, bPass = NULL, bAuthority = NULL;
    std::wstring spnW;
    if (useKerberos) {
        spnW = L"HOST/" + targetW;
        std::wstring authority = L"Kerberos:" + spnW;
        bAuthority = SysAllocString(authority.c_str());
        vprint(verbose, std::string("[*] Using authority ") + std::string(authority.begin(), authority.end()));
    }
    else {
        bUser = SysAllocString(usernameW.c_str());
        bPass = SysAllocString(passwordW.c_str());
    }

    vprint(verbose, "[*] IWbemLocator::ConnectServer");
    hr = pLoc->ConnectServer(
        bPath, bUser, bPass, NULL, 0, bAuthority, NULL, &pSvc
    );

    if (bPath)      SysFreeString(bPath);
    if (bUser)      SysFreeString(bUser);
    if (bPass)      SysFreeString(bPass);
    if (bAuthority) SysFreeString(bAuthority);

    if (FAILED(hr) || !pSvc) {
        std::cerr << "ConnectServer failed: 0x" << std::hex << hr << std::endl;
        pLoc->Release(); CoUninitialize(); return 1;
    }

    // Set proxy blanket
    HRESULT hrBlanket = S_OK;
    if (useKerberos) {
        vprint(verbose, "[*] SetSvcBlanketKerbPreferred");
        hrBlanket = SetSvcBlanketKerbPreferred(pSvc, spnW);
        if (FAILED(hrBlanket)) {
            vprint(verbose, "[*] Preferred failed; fallback to hard Kerberos");
            hrBlanket = SetSvcBlanketKerberosHard(pSvc);
        }
    }
    else {
        vprint(verbose, "[*] SetSvcBlanketUserPass");
        hrBlanket = SetSvcBlanketUserPass(pSvc, domainW, usernameW, passwordW);
    }
    if (FAILED(hrBlanket)) {
        std::cerr << "Setting IWbemServices security failed: 0x"
            << std::hex << hrBlanket << std::endl;
        pSvc->Release(); pLoc->Release(); CoUninitialize(); return 1;
    }
    DumpProxyBlanket(pSvc, verbose);

    // SMB ADMIN$ (for output retrieval)
    std::wstring smbSharePath = L"\\\\" + targetW + L"\\ADMIN$";
    if (!useKerberos) {
        std::wstring smbUser = domainW.empty() ? usernameW : (domainW + L"\\" + usernameW);
        DWORD dw = ConnectToSMBShare(smbSharePath, smbUser, passwordW);
        if (dw != NO_ERROR) {
            std::cerr << "Failed to connect to SMB share. Error code = " << dw << std::endl;
            pSvc->Release(); pLoc->Release(); CoUninitialize(); return 1;
        }
    }
    else {
        WIN32_FIND_DATAW fd{};
        HANDLE hFind = FindFirstFileW((smbSharePath + L"\\*").c_str(), &fd);
        if (hFind == INVALID_HANDLE_VALUE) {
            std::cerr << "SMB access test failed (ADMIN$). Check rights/UAC/policy." << std::endl;
            pSvc->Release(); pLoc->Release(); CoUninitialize(); return 1;
        }
        FindClose(hFind);
    }

    std::wcout << L"Connected to ROOT\\CIMV2 WMI namespace on " << targetW << std::endl;
    std::cout << "Enter commands to execute remotely (type 'exit' to quit):" << std::endl;

    // REPL
    std::string cmd;
    int counter = 0;
    while (true) {
        std::cout << "> ";
        if (!std::getline(std::cin, cmd)) break;
        if (cmd == "exit") break;
        if (cmd.empty()) continue;

        auto t = std::time(nullptr);
        std::tm tm{}; localtime_s(&tm, &t);

        std::wostringstream ws;
        ws << std::put_time(&tm, L"%Y%m%d%H%M%S") << L"_" << counter++;
        std::wstring stamp = ws.str();

        std::wstring outLocal = L"C:\\Windows\\Temp\\output_" + stamp + L".txt";
        std::wstring outRead = smbSharePath + L"\\Temp\\output_" + stamp + L".txt";

        std::wstring cmdW(cmd.begin(), cmd.end());
        if (ExecuteRemoteCommand(cmdW, pSvc, outLocal)) {
            Sleep(1000);
            ReadAndHandleOutput(outRead);
        }
        else {
            std::cerr << "Failed to execute command (HRESULT error logged above)." << std::endl;
        }
    }

    if (!passwordW.empty()) SecureZeroMemory(&passwordW[0], passwordW.size() * sizeof(wchar_t));
    if (!usernameW.empty()) SecureZeroMemory(&usernameW[0], usernameW.size() * sizeof(wchar_t));
    if (!domainW.empty())   SecureZeroMemory(&domainW[0], domainW.size() * sizeof(wchar_t));

    pSvc->Release();
    pLoc->Release();
    CoUninitialize();
    return 0;
}