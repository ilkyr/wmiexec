#include "remote_command.h"
#include <iostream>
#include <comdef.h>
#include <Wbemidl.h>

// Blanket application is optional here; pSvc blanket is authoritative.
// We keep this quiet helper to avoid noisy E_NOINTERFACE logs.
static inline void TrySetProxyBlanket(IUnknown* punk) {
    if (!punk) return;
    HRESULT hr = CoSetProxyBlanket(
        punk,
        RPC_C_AUTHN_GSS_NEGOTIATE,
        RPC_C_AUTHZ_NONE,
        NULL,
        RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL,
        EOAC_DYNAMIC_CLOAKING
    );
    if (hr == E_NOINTERFACE) return;
}

bool ExecuteRemoteCommand(const std::wstring& command,
    IWbemServices* pSvc,
    const std::wstring& outputLocalPath)
{
    if (!pSvc) return false;

    HRESULT hr = S_OK;

    _bstr_t className(L"Win32_Process");
    _bstr_t methodName(L"Create");

    IWbemClassObject* pClass = nullptr;
    IWbemClassObject* pInParamsDef = nullptr;
    IWbemClassObject* pInParams = nullptr;
    IWbemClassObject* pOutParams = nullptr;

    auto releaseAll = [&]() {
        if (pOutParams) { pOutParams->Release();   pOutParams = nullptr; }
        if (pInParams) { pInParams->Release();    pInParams = nullptr; }
        if (pInParamsDef) { pInParamsDef->Release(); pInParamsDef = nullptr; }
        if (pClass) { pClass->Release();       pClass = nullptr; }
        };

    // Win32_Process class
    hr = pSvc->GetObject(className, 0, nullptr, &pClass, nullptr);
    if (FAILED(hr) || !pClass) {
        std::cerr << "[remote_command] GetObject(Win32_Process) failed hr=0x"
            << std::hex << hr << std::dec << std::endl;
        releaseAll(); return false;
    }
    TrySetProxyBlanket(pClass);

    // Create method signature
    hr = pClass->GetMethod(methodName, 0, &pInParamsDef, nullptr);
    if (FAILED(hr) || !pInParamsDef) {
        std::cerr << "[remote_command] GetMethod(Create) failed hr=0x"
            << std::hex << hr << std::dec << std::endl;
        releaseAll(); return false;
    }
    TrySetProxyBlanket(pInParamsDef);

    // Spawn input instance
    hr = pInParamsDef->SpawnInstance(0, &pInParams);
    if (FAILED(hr) || !pInParams) {
        std::cerr << "[remote_command] SpawnInstance failed hr=0x"
            << std::hex << hr << std::dec << std::endl;
        releaseAll(); return false;
    }
    TrySetProxyBlanket(pInParams);

    // cmd.exe /C <cmd> > C:\Windows\Temp\output_....txt 2>&1
    const std::wstring full = L"cmd.exe /C " + command + L" > " + outputLocalPath + L" 2>&1";

    VARIANT varCmd; VariantInit(&varCmd);
    varCmd.vt = VT_BSTR;
    varCmd.bstrVal = SysAllocString(full.c_str());
    if (!varCmd.bstrVal) {
        std::cerr << "[remote_command] SysAllocString failed for command line" << std::endl;
        VariantClear(&varCmd);
        releaseAll(); return false;
    }

    hr = pInParams->Put(L"CommandLine", 0, &varCmd, 0);
    VariantClear(&varCmd);
    if (FAILED(hr)) {
        std::cerr << "[remote_command] Put(CommandLine) failed hr=0x"
            << std::hex << hr << std::dec << std::endl;
        releaseAll(); return false;
    }

    // Execute
    hr = pSvc->ExecMethod(className, methodName, 0, nullptr, pInParams, &pOutParams, nullptr);
    if (FAILED(hr) || !pOutParams) {
        std::cerr << "[remote_command] ExecMethod(Create) failed hr=0x"
            << std::hex << hr << std::dec << std::endl;
        releaseAll(); return false;
    }

    // Check ReturnValue
    VARIANT vRet; VariantInit(&vRet);
    hr = pOutParams->Get(L"ReturnValue", 0, &vRet, nullptr, 0);
    if (FAILED(hr)) {
        std::cerr << "[remote_command] Get(ReturnValue) failed hr=0x"
            << std::hex << hr << std::dec << std::endl;
        VariantClear(&vRet);
        releaseAll(); return false;
    }

    bool success = (vRet.vt == VT_I4 && vRet.lVal == 0);
    if (!success) {
        long rc = (vRet.vt == VT_I4 ? vRet.lVal : -1);
        std::cerr << "[remote_command] Win32_Process.Create ReturnValue=" << rc << std::endl;
    }
    VariantClear(&vRet);

    releaseAll();
    return success;
}