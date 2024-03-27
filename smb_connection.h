#ifndef SMB_CONNECTION_H
#define SMB_CONNECTION_H

#include <string>
#include <Windows.h>

DWORD ConnectToSMBShare(const std::wstring& remoteName, const std::wstring& username, const std::wstring& password);

#endif