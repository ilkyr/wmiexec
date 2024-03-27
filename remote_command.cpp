#include "remote_command.h"
#include "concat.h"

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


