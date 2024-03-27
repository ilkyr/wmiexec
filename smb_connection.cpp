#include "smb_connection.h"

DWORD ConnectToSMBShare(const std::wstring& remoteName, const std::wstring& username, const std::wstring& password) {
    // Function definition as you provided
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