#include "argument_utility.h"

std::string getArgKey(const std::string& arg) {
    if (arg == "--target")   return "-t";
    if (arg == "--domain")   return "-d";
    if (arg == "--user")     return "-u";
    if (arg == "--password") return "-p";
    return arg; 
}
