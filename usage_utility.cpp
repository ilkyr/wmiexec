#include "usage_utility.h"

// Prints usage information for the program
void printUsage(const char* programName) {
    std::cout << "Usage: " << programName << " -t <target-host> -d <domain> -u <user> -p <password>\n"
        << "Options:\n"
        << "  -t, --target  Target host IP or hostname\n"
        << "  -d, --domain  Domain\n"
        << "  -u, --user    Username\n"
        << "  -p, --password Password\n"
        << "  -h, --help    Show this help message\n";
}
