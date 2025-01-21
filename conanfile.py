from conan import ConanFile
from conan.tools.cmake import CMakeToolchain, CMake, cmake_layout, CMakeDeps


class pkgRecipe(ConanFile):
    name = "chat-application"
    version = "0.1"
    package_type = "application"

    # Optional metadata
    license = "MIT"
    author = "Robert Williamson"
    description = "A simple chat application in C++"
    topics = ("Chat", "Networking")

    # Binary configuration
    settings = "os", "compiler", "build_type", "arch"

    # Sources are located in the same place as this recipe, copy them to the recipe
    exports_sources = "CMakeLists.txt", "src/*"

    requirements_list = ["enet/1.3.18", "argparse/3.1", "openssl/3.3.2"]

    def requirements(self):
        for requirement in self.requirements_list:
            self.requires(requirement)

    def layout(self):
        cmake_layout(self)

    def generate(self):
        deps = CMakeDeps(self)
        deps.generate()
        tc = CMakeToolchain(self)
        tc.generate()

    def build(self):
        cmake = CMake(self)
        cmake.configure()
        cmake.build()

    def package(self):
        cmake = CMake(self)
        cmake.install()
