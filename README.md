# Windows Management Instrumentation (WMI) Command Executor

This C++ program is inspired by Impacket's wmiexec.py and demonstrates how to use Windows Management Instrumentation (WMI) to execute a command on a remote Windows machine. It connects to a remote machine, sets up the necessary security settings, and then uses WMI to execute a command.

## Prerequisites

- Windows operating system
- Visual C++ development environment (Visual Studio recommended)

## Usage

1. Clone this repository or download the source code.
2. Open the project in your preferred C++ development environment (e.g., Visual Studio).
3. Build and compile the code.
4. Run the compiled executable with the following command-line arguments:

<Target-host> <Domain> <Username> <Password> <Command>

Replace each placeholder with the appropriate values:

- `<Target-host>`: The hostname or IP address of the target machine.
- `<Domain>`: The domain of the user account.
- `<Username>`: The username for authentication.
- `<Password>`: The password for authentication.
- `<Command>`: The command to be executed on the remote machine.

## Important Notes

- This program is in an initial stage with minimal functionality, inspired by Impacket's `wmiexec.py`.
- Ensure that you have the necessary permissions to execute remote commands on the target machine.
- This program uses Windows-specific APIs and is intended for Windows environments.

## Future Development

This project is in an early stage of development, and more features and functionality will be added in future updates.
