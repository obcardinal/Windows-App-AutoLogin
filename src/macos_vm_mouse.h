#ifndef WAAL_MACOS_VM_MOUSE_H
#define WAAL_MACOS_VM_MOUSE_H

#include <stdbool.h>
#include <stdint.h>

// Passive identity check across Spaces: 1 = owned window, 0 = absent/replaced,
// -1 = unavailable/incomplete snapshot. A failed read is not proof of closure.
int32_t waal_vm_window_presence(int32_t pid, uint32_t window_id);

// The caller verifies the client, session window and its AX remote-display view.
// The viewport uses global top-left coordinates in macOS points. The alternating
// points are one point apart. True reports submission, not receipt by the guest.
bool waal_post_vm_mouse_move(int32_t pid, uint32_t window_id,
                            double viewport_x, double viewport_y,
                            double viewport_width, double viewport_height,
                            bool move_right);

#endif
