#pragma once

namespace loader {

enum class Mode { None, Stomp, Apc, Doppel, Herpaderp };

Mode build_mode();
void run(Mode m);

} // namespace loader
