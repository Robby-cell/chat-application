#include <argparse/argparse.hpp>
#include <enet/enet.h>

#include <cstdint>
#include <exception>
#include <iostream>
#include <memory>
#include <mutex>
#include <ostream>
#include <stop_token>
#include <string>
#include <string_view>
#include <thread>

static std::mutex mutex;

void receive_messages(ENetPeer *peer, std::stop_token stop_token) {
  ENetEvent event;
  while (true) {
    if (stop_token.stop_requested()) {
      return;
    }
    while (enet_host_service(peer->host, &event, 1000) > 0) {
      switch (event.type) {
      case ENET_EVENT_TYPE_RECEIVE: {
        std::lock_guard lock{mutex};
        std::println(std::cout, "{}",
                     reinterpret_cast<const char *>(event.packet->data));
        enet_packet_destroy(event.packet);
        break;
      }
      case ENET_EVENT_TYPE_DISCONNECT: {
        std::println(std::cerr, "Disconnected from server.");
        return;
      }
      default: {
        break;
      }
      }
    }
  }
}

auto main(int argc, char **argv) -> int try {
  using std::operator""sv;
  static constexpr auto port_flag = "--port"sv;
  static constexpr auto host_flag = "--host"sv;

  if (enet_initialize() != 0) {
    std::cerr << "Failed to initialize enet\n";
    return -1;
  }

  // deinitialize will always happen.
  struct _run_on_scope_exit {
    ~_run_on_scope_exit() { enet_deinitialize(); }
  } _do_run_on_exit;

  argparse::ArgumentParser program("client");
  program.add_argument(port_flag)
      .default_value<std::uint16_t>(12345)
      .scan<'i', std::uint16_t>()
      .help("Port to connect to");
  program.add_argument(host_flag).default_value("0.0.0.0").help(
      "The host address to connect to");

  try {
    program.parse_args(argc, argv);
  } catch (const std::exception &e) {
    std::println(std::cerr, "{}", e.what());
    std::cerr << program;
    return -1;
  }

  ENetAddress address;
  {
    const auto host = program.get<std::string>(host_flag);
    const auto port = program.get<std::uint16_t>(port_flag);
    enet_address_set_host(&address, host.c_str());
    address.port = port;
  }
  std::println(std::cerr, "Connecting on port {}", address.port);

  static constexpr auto host_deleter = [](ENetHost *host) {
    if (host) {
      enet_host_destroy(host);
    }
  };
  using client_wrapper = std::unique_ptr<ENetHost, decltype(host_deleter)>;

  // client will always be destroyed, without adding verbose cleanups everywhere
  // to handle ever failure
  client_wrapper client(enet_host_create(nullptr, 1, 1, 57600 / 8, 14400 / 8),
                        host_deleter);

  if (!client.get()) {
    std::println(std::cerr, "Failed to connect to the server");
    return -1;
  }

  static constexpr auto peer_deleter = [](auto peer) {
    if (peer) {
      enet_peer_disconnect(peer, 0);
    }
  };

  std::unique_ptr<ENetPeer, decltype(peer_deleter)> peer{
      enet_host_connect(client.get(), &address, 2, 0), peer_deleter};
  if (!peer) {
    std::println(std::cerr, "Failed to connect to the server");
    return -1;
  }

  ENetEvent event;
  if (enet_host_service(client.get(), &event, 5000) > 0 &&
      event.type == ENET_EVENT_TYPE_CONNECT) {
    std::println(std::cerr, "Connected to the server");
  } else {
    std::println(std::cerr, "Connection failed");
    return -1;
  }

  std::stop_source stop_source;
  std::jthread receive_thread{
      [peer = peer.get(), stop_token = stop_source.get_token()]() {
        receive_messages(peer, stop_token);
      }};

  std::string message;
  while (true) {
    std::getline(std::cin, message);
    if (message == "exit"sv) {
      break;
    }

    ENetPacket *packet = enet_packet_create(
        message.c_str(), message.length() + 1, ENET_PACKET_FLAG_RELIABLE);
    enet_peer_send(peer.get(), 0, packet);
    enet_host_flush(client.get());
  }

  while (enet_host_service(client.get(), &event, 3000) > 0) {
    if (event.type == ENET_EVENT_TYPE_DISCONNECT) {
      std::println(std::cerr, "Disconnected from the server");
    }
  }

  stop_source.request_stop();
  receive_thread.join();
} catch (const std::exception &e) {
  std::cerr << e.what() << std::endl;
}
