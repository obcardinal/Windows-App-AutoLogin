#ifndef WAAL_MACOS_MASKED_FIELD_H
#define WAAL_MACOS_MASKED_FIELD_H

#include <CoreGraphics/CoreGraphics.h>
#include <stdbool.h>

// Bounds use Vision's normalized coordinates, with the origin at bottom left.
bool waal_masked_field(CGImageRef image, CGRect *normalizedField);

#endif
