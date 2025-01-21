add_library(encryption STATIC encryption.cc)
target_include_directories(encryption PUBLIC include)

find_package(OpenSSL CONFIG REQUIRED)
target_link_libraries(encryption PUBLIC openssl::openssl)

set_target_properties(encryption
    PROPERTIES
        CXX_STANDARD 23
        CXX_STANDARD_REQUIRED ON
        CXX_EXTENSIONS OFF)
