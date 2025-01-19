.PHONY: clean build

build:
	conan install . --build=missing && \
	cmake --preset=conan-release && \
	cmake --build build --preset=conan-release

clean:
	rm -rf build
