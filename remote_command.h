#ifndef REMOTE_COMMAND_H
#define REMOTE_COMMAND_H

#include <string>
#include <comdef.h>
#include <Wbemidl.h>

bool ExecuteRemoteCommand(const std::wstring& command, IWbemServices* pSvc, const std::wstring& outputFilePath);

#endif // !REMOTE_COMMAND_H
