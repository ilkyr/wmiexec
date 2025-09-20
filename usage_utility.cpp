#include <iostream>

void print_help_and_exit(const char* exe) {
    std::cerr <<
        "Usage: " << exe << " -t <target-host> -d <domain> [options]\n"
        "Options:\n"
        "  -t, --target        Target host (IP address or NetBIOS name/FQDN)\n"
        "  -d, --domain        Domain name\n"
        "  -u, --user          Username (required if not using Kerberos)\n"
        "  -p, --password      Password (required if not using Kerberos)\n"
        "  -k, --kerberos      Use current session Kerberos TGT (NetBIOS name or FQDN)\n"
        "  -v, --verbose       Verbose diagnostics\n"
        "  -h, --help          Show this help\n\n"
        "Examples:\n"
        "  " << exe << " -t SRV01 -d EXAMPLE.LOCAL -u alice -p Passw0rd!\n"
        "  " << exe << " -t 192.168.1.200 -d EXAMPLE.LOCAL -u alice -p Passw0rd!\n"
        "  " << exe << " -t SRV01 -d EXAMPLE --kerberos\n";
    exit(1);
}