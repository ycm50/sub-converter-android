#include "subconv/types.hpp"

#include <algorithm>
#include <array>

namespace subconv {
namespace {

struct ProtoName {
  Protocol proto;
  const char* canonical;
  const char* clash;
};

constexpr std::array<ProtoName, 13> kProtoNames{{
    {Protocol::Unknown, "unknown", "unknown"},
    {Protocol::Socks5, "socks5", "socks5"},
    {Protocol::Http, "http", "http"},
    {Protocol::Shadowsocks, "ss", "ss"},
    {Protocol::ShadowsocksR, "ssr", "ssr"},
    {Protocol::Vmess, "vmess", "vmess"},
    {Protocol::Vless, "vless", "vless"},
    {Protocol::Trojan, "trojan", "trojan"},
    {Protocol::Hysteria, "hysteria", "hysteria"},
    {Protocol::Hysteria2, "hysteria2", "hysteria2"},
    {Protocol::Tuic, "tuic", "tuic"},
    {Protocol::Snell, "snell", "snell"},
    {Protocol::WireGuard, "wireguard", "wireguard"},
}};

const ProtoName& lookup(Protocol p) {
  for (const auto& e : kProtoNames) {
    if (e.proto == p) return e;
  }
  return kProtoNames[0];
}

}  // namespace

const char* to_string(Protocol p) noexcept { return lookup(p).canonical; }
const char* clash_type(Protocol p) noexcept { return lookup(p).clash; }

std::optional<Protocol> protocol_from_string(std::string_view s) noexcept {
  std::string k;
  k.reserve(s.size());
  for (char c : s) {
    if (c >= 'A' && c <= 'Z') k.push_back(static_cast<char>(c - 'A' + 'a'));
    else k.push_back(c);
  }
  for (const auto& e : kProtoNames) {
    if (k == e.canonical || k == e.clash) return e.proto;
  }
  // 常见别名
  if (k == "shadowsocks") return Protocol::Shadowsocks;
  if (k == "shadowsocksr") return Protocol::ShadowsocksR;
  if (k == "hy2" || k == "hysteria-2") return Protocol::Hysteria2;
  if (k == "hy") return Protocol::Hysteria;
  if (k == "wg") return Protocol::WireGuard;
  if (k == "socks" || k == "socks4" || k == "socks5h") return Protocol::Socks5;
  if (k == "https" || k == "http(s)") return Protocol::Http;
  if (k == "vmess+ws") return Protocol::Vmess;
  return std::nullopt;
}

bool protocol_is_dialer(Protocol p) noexcept {
  switch (p) {
    case Protocol::Socks5:
    case Protocol::Http:
    case Protocol::Shadowsocks:
    case Protocol::ShadowsocksR:
    case Protocol::Vmess:
    case Protocol::Vless:
    case Protocol::Trojan:
    case Protocol::Hysteria:
    case Protocol::Hysteria2:
    case Protocol::Tuic:
    case Protocol::Snell:
      return true;
    default:
      return false;
  }
}

std::optional<Network> network_from_string(std::string_view s) noexcept {
  std::string k;
  k.reserve(s.size());
  for (char c : s) {
    if (c >= 'A' && c <= 'Z') k.push_back(static_cast<char>(c - 'A' + 'a'));
    else k.push_back(c);
  }
  if (k.empty() || k == "tcp" || k == "none" || k == "raw") return Network::Tcp;
  if (k == "ws" || k == "websocket") return Network::Ws;
  if (k == "grpc") return Network::Grpc;
  if (k == "h2" || k == "http") return Network::H2;
  if (k == "quic") return Network::Quic;
  if (k == "kcp" || k == "mkcp") return Network::Kcp;
  // Xray 25 起把 splithttp 改名 xhttp，两个名字都收
  if (k == "xhttp" || k == "splithttp") return Network::Xhttp;
  return std::nullopt;
}

const char* to_string(Network n) noexcept {
  switch (n) {
    case Network::Tcp: return "tcp";
    case Network::Ws: return "ws";
    case Network::Grpc: return "grpc";
    case Network::H2: return "h2";
    case Network::Http: return "http";
    case Network::Quic: return "quic";
    case Network::Kcp: return "kcp";
    case Network::Xhttp: return "xhttp";
  }
  return "unknown";
}

}  // namespace subconv
