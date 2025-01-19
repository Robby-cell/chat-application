add_executable(server
    main.cc)

find_package(enet CONFIG REQUIRED)
find_package(argparse CONFIG REQUIRED)

target_link_libraries(server PRIVATE enet::enet argparse::argparse)

set_target_properties(server
    PROPERTIES
        CXX_STANDARD 23
        CXX_STANDARD_REQUIRED ON
        CXX_EXTENSIONS OFF)

install(TARGETS server DESTINATION "."
        RUNTIME DESTINATION bin
        ARCHIVE DESTINATION lib
        LIBRARY DESTINATION lib
        )
