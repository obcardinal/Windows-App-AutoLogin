#import <Foundation/Foundation.h>
#import <ApplicationServices/ApplicationServices.h>
#include <math.h>
#include "macos_vm_mouse.h"

static bool validViewport(CGRect viewport) {
    return isfinite(viewport.origin.x) && isfinite(viewport.origin.y) &&
           isfinite(viewport.size.width) && isfinite(viewport.size.height) &&
           isfinite(CGRectGetMaxX(viewport)) && isfinite(CGRectGetMaxY(viewport)) &&
           viewport.size.width >= 2 && viewport.size.height >= 2;
}

static bool currentWindowBounds(pid_t pid, CGWindowID windowID, CGRect *bounds) {
    NSArray *windows = CFBridgingRelease(CGWindowListCopyWindowInfo(
        kCGWindowListOptionIncludingWindow, windowID));
    if (windows.count != 1) return false;
    NSDictionary *window = windows.firstObject;
    NSNumber *number = window[(__bridge NSString *)kCGWindowNumber];
    NSNumber *owner = window[(__bridge NSString *)kCGWindowOwnerPID];
    NSNumber *layer = window[(__bridge NSString *)kCGWindowLayer];
    NSDictionary *geometry = window[(__bridge NSString *)kCGWindowBounds];
    return number && owner && layer && geometry &&
           number.unsignedIntValue == windowID && owner.intValue == pid &&
           layer.intValue == 0 &&
           CGRectMakeWithDictionaryRepresentation((__bridge CFDictionaryRef)geometry, bounds) &&
           validViewport(*bounds);
}

int32_t waal_vm_window_presence(int32_t pid, uint32_t window_id) {
    @autoreleasepool {
        if (pid <= 0 || !window_id) return -1;
        NSArray *windows = CFBridgingRelease(CGWindowListCopyWindowInfo(
            kCGWindowListOptionIncludingWindow, window_id));
        if (!windows) return -1;
        if (windows.count == 0) return 0;
        if (windows.count != 1) return -1;
        NSDictionary *window = windows.firstObject;
        NSNumber *number = window[(__bridge NSString *)kCGWindowNumber];
        NSNumber *owner = window[(__bridge NSString *)kCGWindowOwnerPID];
        if (!number || !owner) return -1;
        return number.unsignedIntValue == window_id && owner.intValue == pid ? 1 : 0;
    }
}

bool waal_post_vm_mouse_move(int32_t pid, uint32_t window_id,
                            double viewport_x, double viewport_y,
                            double viewport_width, double viewport_height,
                            bool move_right) {
    @autoreleasepool {
        CGRect viewport = CGRectMake(viewport_x, viewport_y, viewport_width, viewport_height);
        CGRect bounds;
        if (pid <= 0 || !window_id || !validViewport(viewport) ||
            !CGPreflightPostEventAccess() ||
            CGEventSourceButtonState(kCGEventSourceStateCombinedSessionState, kCGMouseButtonLeft) ||
            CGEventSourceButtonState(kCGEventSourceStateCombinedSessionState, kCGMouseButtonRight) ||
            !currentWindowBounds(pid, window_id, &bounds) ||
            !CGRectContainsRect(bounds, viewport)) return false;

        CGPoint screenPoint = CGPointMake(CGRectGetMidX(viewport) + (move_right ? 0.5 : -0.5),
                                          CGRectGetMidY(viewport));
        // The receiving process converts global coordinates to its own window.
        // Constructing NSEvent here with a foreign window number embeds stale
        // window-local coordinates even after changing its CGEvent location.
        CGEventRef event = CGEventCreateMouseEvent(NULL, kCGEventMouseMoved, screenPoint,
                                                   kCGMouseButtonLeft);
        if (!event) return false;
        CGEventSetFlags(event, 0);
        CGEventSetIntegerValueField(event, kCGMouseEventWindowUnderMousePointer, window_id);
        CGEventSetIntegerValueField(event, kCGMouseEventWindowUnderMousePointerThatCanHandleThisEvent,
                                    window_id);
        CGEventSetIntegerValueField(event, kCGMouseEventDeltaX, move_right ? 1 : -1);
        CGEventSetIntegerValueField(event, kCGMouseEventDeltaY, 0);
        CGEventPostToPid(pid, event);
        CFRelease(event);
        return true;
    }
}
