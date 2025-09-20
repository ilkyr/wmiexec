#include "smb_connection.h"
#include <windows.h>
#include <winnetwk.h>
#include <vector>
#include <string>

static void BestEffortDisconnect(const std::wstring& unc) {
    (void)WNetCancelConnection2W(unc.c_str(), 0, TRUE);
}

static void BuildNameVariants(const std::wstring& remoteAdmin,
                              std::vector<std::wstring>& variantsAdmin,
                              std::vector<std::wstring>& variantsIpc)
{
    // remoteAdmin like: \\dc01.villanova.local\ADMIN$
    variantsAdmin.clear();
    variantsIpc.clear();

    variantsAdmin.push_back(remoteAdmin);

    // Extract host between leading "\\" and next "\"
    size_t hostStart = 2;
    size_t hostEnd = remoteAdmin.find(L'\\', hostStart);
    std::wstring host = (hostEnd != std::wstring::npos)
        ? remoteAdmin.substr(hostStart, hostEnd - hostStart)
        : L"";

    // Short host (strip domain)
    if (!host.empty()) {
        size_t dot = host.find(L'.');
        if (dot != std::wstring::npos) {
            std::wstring shortHost = host.substr(0, dot);
            variantsAdmin.push_back(L"\\\\" + shortHost + L"\\ADMIN$");
        }
        // If host is already short, try common “long” (no-op here) and add self
        variantsIpc.push_back(L"\\\\" + host + L"\\IPC$");
        if (dot != std::wstring::npos) {
            std::wstring shortHost = host.substr(0, dot);
            variantsIpc.push_back(L"\\\\" + shortHost + L"\\IPC$");
        }
    }

    // Also add ADMIN$ for what we added to IPC$
    for (const auto& ipc : variantsIpc) {
        std::wstring admin = ipc;
        admin.replace(admin.find(L"\\IPC$"), 5, L"\\ADMIN$");
        // avoid duplicates
        bool exists = false;
        for (auto& v : variantsAdmin) if (_wcsicmp(v.c_str(), admin.c_str()) == 0) { exists = true; break; }
        if (!exists) variantsAdmin.push_back(admin);
    }
}

static DWORD ConnectOnce(const std::wstring& unc,
                         const std::wstring& user,
                         const std::wstring& pass)
{
    NETRESOURCE nr{};
    nr.dwType       = RESOURCETYPE_DISK;
    nr.lpRemoteName = const_cast<LPWSTR>(unc.c_str());

    LPCWSTR pUser = user.empty() ? NULL : user.c_str();
    LPCWSTR pPass = pass.empty() ? NULL : pass.c_str();

    // Always clear first to avoid stale/implicit sessions
    BestEffortDisconnect(unc);

    DWORD dw = WNetAddConnection2W(&nr, pPass, pUser, 0);
    if (dw == ERROR_SESSION_CREDENTIAL_CONFLICT || dw == 1219) {
        // Try a second time after a harder cleanup
        BestEffortDisconnect(unc);
        dw = WNetAddConnection2W(&nr, pPass, pUser, 0);
    }
    return dw;
}

DWORD ConnectToSMBShare(const std::wstring& remoteName,
                        const std::wstring& username,
                        const std::wstring& password)
{
    std::vector<std::wstring> adminVariants, ipcVariants;
    BuildNameVariants(remoteName, adminVariants, ipcVariants);

    // 1) Tear down both IPC$ and ADMIN$ on all aliases
    for (const auto& v : adminVariants) BestEffortDisconnect(v);
    for (const auto& v : ipcVariants)  BestEffortDisconnect(v);

    // 2) Establish an IPC$ session first (many systems relax ADMIN$ once IPC$ is set)
    DWORD lastErr = NO_ERROR;
    bool ipcOk = false;
    for (const auto& ipc : ipcVariants) {
        lastErr = ConnectOnce(ipc, username, password);
        if (lastErr == NO_ERROR) { ipcOk = true; break; }
    }

    // 3) Now connect ADMIN$ on any alias
    for (const auto& adm : adminVariants) {
        lastErr = ConnectOnce(adm, username, password);
        if (lastErr == NO_ERROR) return NO_ERROR;
    }

    // If all variants failed, return the last error
    return lastErr;
}
