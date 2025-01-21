add_library(generate_key STATIC generate_key.cc)
target_include_directories(generate_key PUBLIC include)

find_package(OpenSSL CONFIG REQUIRED)
target_link_libraries(generate_key PUBLIC openssl::openssl)

set_target_properties(generate_key
    PROPERTIES
        CXX_STANDARD 23
        CXX_STANDARD_REQUIRED ON
        CXX_EXTENSIONS OFF)
