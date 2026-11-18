#ifndef WAAL_MACOS_MASKED_FIELD_H
#define WAAL_MACOS_MASKED_FIELD_H

#include <CoreGraphics/CoreGraphics.h>
#include <stdbool.h>

typedef enum {
    WaalFieldNone,
    WaalFieldPlaceholderCandidate,
    WaalFieldMasked,
    WaalFieldAmbiguous,
    WaalFieldUnavailable
} WaalFieldKind;

// A candidate only locates an editor for OCR. Its geometry cannot establish
// that it is a password field. Bounds use Vision's bottom-left coordinates.
// Ambiguous and unavailable scans must stop recognition for this frame.
WaalFieldKind waal_password_field(CGImageRef image, CGRect *normalizedField);

#endif
