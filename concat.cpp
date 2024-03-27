#include "concat.h"

// Concatenates two BSTR strings.
BSTR Concat(BSTR a, BSTR b) {
    if (a == NULL || b == NULL) return NULL;

    auto lengthA = SysStringLen(a);
    auto lengthB = SysStringLen(b);

    auto result = SysAllocStringLen(NULL, lengthA + lengthB);
    if (result == NULL) {
        return NULL;
    }

    if (lengthA > 0) {
        memcpy(result, a, lengthA * sizeof(OLECHAR));
    }
    if (lengthB > 0) {
        memcpy(result + lengthA, b, lengthB * sizeof(OLECHAR));
    }

    result[lengthA + lengthB] = 0;
    return result;
}
