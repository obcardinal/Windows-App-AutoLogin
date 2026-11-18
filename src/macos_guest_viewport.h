#ifndef WAAL_MACOS_GUEST_VIEWPORT_H
#define WAAL_MACOS_GUEST_VIEWPORT_H

#include <CoreGraphics/CoreGraphics.h>

// Input is the verified remote display view. Result is a rectangle in native
// pixels with a top-left origin. A visible overlay on padding returns CGRectNull.
CGRect waal_guest_content_rect(CGImageRef viewport);

#endif
