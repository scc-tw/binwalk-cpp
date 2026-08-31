#pragma once

#if defined(_WIN32) && defined(BINWALK_CORE_SHARED)
#    if defined(binwalk_core_EXPORTS)
#        define BINWALK_API __declspec(dllexport)
#    else
#        define BINWALK_API __declspec(dllimport)
#    endif
#else
#    define BINWALK_API
#endif
