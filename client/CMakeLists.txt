add_executable(client
    main.cc)

find_package(enet CONFIG REQUIRED)
find_package(argparse CONFIG REQUIRED)
find_package(OpenSSL CONFIG REQUIRED)

target_link_libraries(client
    PRIVATE
        enet::enet
        argparse::argparse
        openssl::openssl
        generate_key
        encryption)

set_target_properties(client
    PROPERTIES
        CXX_STANDARD 23
        CXX_STANDARD_REQUIRED ON
        CXX_EXTENSIONS OFF)

install(TARGETS client DESTINATION "."
        RUNTIME DESTINATION bin
        ARCHIVE DESTINATION lib
        LIBRARY DESTINATION lib
        )
