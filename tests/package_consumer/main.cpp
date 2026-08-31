#include <binwalk/binwalk.hpp>

#include <cstdlib>

int main() {
    const binwalk::scanner scanner;
    return scanner.signature_count() > 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
