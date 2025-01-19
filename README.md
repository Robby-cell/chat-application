# Chat Application

## Building

Tooling required:

- A C++ compiler that can compile C++23 code
- git to clone the repo
- conan to grab dependencies and build them

```bash
git clone https://github.com/Robby-cell/chat-application.git
cd chat-application
make
```

conan may need to be set up. to create a conan profile:

```bash
conan profile detect
```

## Running

To run the server:

```bash
./build/Release/server/server --port=12345 --host=localhost
```

To run the client:

```bash
./build/Release/client/client --port=12345 --host=localhost
```

## Stuff that will be added

AES encryption, currently no encryption is being used. Implementing encryption soon.
