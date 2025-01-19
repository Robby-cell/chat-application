#include <argparse/argparse.hpp>
#include <enet/enet.h>

#include <cstdint>
#include <exception>
#include <iostream>
#include <memory>
#include <mutex>
#include <ostream>
#include <span>
#include <stop_token>
#include <string>
#include <thread>

static std::mutex print_mutex;

void broadcast_message(ENetHost *server, ENetPacket *packet) {
  std::lock_guard lock(print_mutex);
  for (auto &peer : std::span(server->peers, server->peerCount)) {
    if (peer.state == ENET_PEER_STATE_CONNECTED) {
      enet_host_broadcast(server, 0, packet);
    }
  }
}

void handle_client_messages(ENetHost *server, std::stop_token stop_token) {
  ENetEvent event;
  while (true) {
    if (stop_token.stop_requested()) {
      return;
    }
    while (enet_host_service(server, &event, 1000) > 0) {
      switch (event.type) {
      case ENET_EVENT_TYPE_RECEIVE: {
        std::println(std::cout, "Received message: {}",
                     reinterpret_cast<const char *>(event.packet->data));
        broadcast_message(server, event.packet);
        enet_packet_destroy(event.packet);
        break;
      }
      case ENET_EVENT_TYPE_DISCONNECT: {
        std::println(std::cerr, "A client disconnected.");
        break;
      }
      default: {
        break;
      }
      }
    }
  }
}

auto main(int argc, char **argv) -> int {
  using std::operator""sv;
  static constexpr auto port_flag = "--port"sv;
  static constexpr auto host_flag = "--host"sv;

  argparse::ArgumentParser program("server");

  program.add_argument(port_flag)
      .default_value<std::uint16_t>(12345)
      .scan<'i', std::uint16_t>()
      .help("Specify which port to listen on");
  program.add_argument(host_flag).default_value("0.0.0.0").help(
      "The host address to connect to");

  try {
    program.parse_args(argc, argv);
  } catch (const std::exception &e) {
    std::println(std::cerr, "{}", e.what());
    std::cerr << program;
    return -1;
  }

  if (enet_initialize() != 0) {
    std::println(std::cerr, "Failed to initialize enet");
    return -1;
  }
  struct _run_on_scope_exit {
    ~_run_on_scope_exit() { enet_deinitialize(); }
  } _run_on_exit;

  ENetAddress address;
  {
    const auto host = program.get<std::string>(host_flag);
    const auto port = program.get<std::uint16_t>(port_flag);
    enet_address_set_host(&address, host.c_str());
    address.port = port;
  }
  std::println(std::cerr, "Connecting on port {}", address.port);

  static constexpr auto host_deleter = [](auto host) {
    if (host) {
      enet_host_destroy(host);
    }
  };
  std::unique_ptr<ENetHost, decltype(host_deleter)> server{
      enet_host_create(&address, 32, 1, 57600 / 8, 14400 / 8), host_deleter};
  if (!server) {
    std::println(std::cerr, "Failed to create enet server...");
    return -1;
  }

  std::println(std::cerr, "Server started on port {}", address.port);

  std::stop_source stop_source;
  std::jthread client_handler{
      [server = server.get(), stop_token = stop_source.get_token()]() {
        handle_client_messages(server, stop_token);
      }};
}
