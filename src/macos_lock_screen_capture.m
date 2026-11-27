// ScreenCaptureKit and Vision operate in this process. Only the verified window
// is passed to the screenshot API. No frame or recognition result is serialized.
#import <AppKit/AppKit.h>
#import <ScreenCaptureKit/ScreenCaptureKit.h>
#import <Vision/Vision.h>
#include "macos_guest_viewport.h"
#include "macos_masked_field.h"

#import <ApplicationServices/ApplicationServices.h>
#import <os/log.h>
#include <dlfcn.h>
#include <math.h>
#include <stdatomic.h>
#include <stdint.h>

enum { OverviewText, MaskedField, VerifiedPlaceholder, EditorBounds, CornerText, AccountText, LayoutText,
       AmbiguousText, PairedAccountText };
typedef void (*WaalTextVisitor)(void *, int, const char *, size_t, float, double, double, double, double);

void waal_log_reconnect_event(const char *event) {
    static os_log_t log;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        log = os_log_create("com.obcardinal.WindowsAppAutoLogin", "Reconnect");
    });
    os_log(log, "%{public}s", event);
}

bool waal_lock_capture_supported(void) {
    if (@available(macOS 14.0, *)) return true;
    return false;
}

bool waal_lock_capture_allowed(void) {
    return waal_lock_capture_supported() && CGPreflightScreenCaptureAccess();
}

bool waal_lock_capture_request(void) {
    return waal_lock_capture_supported() && CGRequestScreenCaptureAccess();
}

bool waal_record_capture_request(void) {
    @autoreleasepool {
        // The UI and supervisor run in the same app bundle. Store only whether
        // the app has requested access; macOS is the authority on its status.
        NSUserDefaults *defaults = NSUserDefaults.standardUserDefaults;
        NSString *key = @"WAALLockedVMHasRequestedScreenCapture";
        bool previous = [defaults boolForKey:key];
        [defaults setBool:YES forKey:key];
        return previous;
    }
}

bool waal_open_capture_preferences(void) {
    @autoreleasepool {
        NSURL *pane = [NSURL URLWithString:
            @"x-apple.systempreferences:com.apple.preference.security?Privacy_ScreenCapture"];
        return pane && [NSWorkspace.sharedWorkspace openURL:pane];
    }
}

static bool isFrontmost(pid_t pid) {
    NSRunningApplication *app = NSWorkspace.sharedWorkspace.frontmostApplication;
    return app.processIdentifier == pid && [app.bundleIdentifier isEqualToString:@"com.microsoft.rdc.macos"];
}

static CGImageRef copyDetail(CGImageRef source, CGRect pixels, double scale);

typedef struct { CGRect window, viewport; } GuestViewport;

static bool validRect(CGRect r) {
    return isfinite(r.origin.x) && isfinite(r.origin.y) && isfinite(r.size.width) &&
           isfinite(r.size.height) && r.size.width > 0 && r.size.height > 0;
}

// AX and SCShareableContent both use global, top-left coordinates in points.
// The captured bitmap is local to the filter, including on a secondary screen.
CGRect waal_guest_viewport_pixels(CGRect window, CGRect viewport, CGRect content,
                                  size_t imageWidth, size_t imageHeight) {
    if (!validRect(window) || !validRect(viewport) || !validRect(content) || !imageWidth || !imageHeight ||
        !CGRectContainsRect(window, viewport) || !CGRectContainsRect(content, viewport))
        return CGRectNull;
    double sx = imageWidth / content.size.width, sy = imageHeight / content.size.height;
    double scaleError = fabs(sx - sy) * fmin(content.size.width, content.size.height);
    if (!isfinite(scaleError) || scaleError > 1.0) return CGRectNull;
    // Round inward so a fractional edge never includes an adjacent native control.
    double x = ceil((viewport.origin.x - content.origin.x) * sx);
    double y = ceil((viewport.origin.y - content.origin.y) * sy);
    double right = floor((CGRectGetMaxX(viewport) - content.origin.x) * sx);
    double bottom = floor((CGRectGetMaxY(viewport) - content.origin.y) * sy);
    CGRect r = CGRectMake(x, y, right - x, bottom - y);
    return validRect(r) ? r : CGRectNull;
}

static id axValue(AXUIElementRef element, CFStringRef key) {
    CFTypeRef value = NULL;
    if (AXUIElementCopyAttributeValue(element, key, &value) != kAXErrorSuccess) return nil;
    return CFBridgingRelease(value);
}

static bool axGeometry(AXUIElementRef element, CFStringRef key, AXValueType type, void *out) {
    id value = axValue(element, key);
    return value && CFGetTypeID((__bridge CFTypeRef)value) == AXValueGetTypeID() &&
           AXValueGetValue((__bridge AXValueRef)value, type, out);
}

static bool axBounds(AXUIElementRef element, CGRect *bounds) {
    return axGeometry(element, kAXPositionAttribute, kAXValueCGPointType, &bounds->origin) &&
           axGeometry(element, kAXSizeAttribute, kAXValueCGSizeType, &bounds->size) && validRect(*bounds);
}

static bool emptyRelationship(AXUIElementRef element, CFStringRef key) {
    CFTypeRef value = NULL;
    AXError error = AXUIElementCopyAttributeValue(element, key, &value);
    if (error == kAXErrorAttributeUnsupported || error == kAXErrorNoValue) return true;
    id objects = CFBridgingRelease(value);
    return error == kAXErrorSuccess && [objects isKindOfClass:NSArray.class] && [objects count] == 0;
}

static bool readWindowGuestViewport(pid_t pid, CGWindowID expected, AXUIElementRef window, GuestViewport *result) {
    typedef AXError (*GetWindowID)(AXUIElementRef, CGWindowID *);
    static GetWindowID getWindowID;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ getWindowID = (GetWindowID)dlsym(RTLD_DEFAULT, "_AXUIElementGetWindow"); });
    if (!getWindowID || !window) return false;
    CGWindowID wid = 0;
    pid_t owner = 0;
    if (AXUIElementGetPid(window, &owner) != kAXErrorSuccess || owner != pid ||
        getWindowID(window, &wid) != kAXErrorSuccess || wid != expected ||
        ![axValue(window, kAXRoleAttribute) isEqual:@"AXWindow"] ||
        ![axValue(window, kAXMinimizedAttribute) isEqual:@NO] ||
        !emptyRelationship(window, CFSTR("AXSheets")) || !axBounds(window, &result->window))
        return false;
    NSArray *children = axValue(window, kAXChildrenAttribute);
    if (![children isKindOfClass:NSArray.class] || children.count > 32) return false;
    CGRect viewport = CGRectNull;
    bool fullscreen = [axValue(window, CFSTR("AXFullScreen")) isEqual:@YES];
    CGRect chrome = CGRectNull;
    for (id child in children) {
        if (CFGetTypeID((__bridge CFTypeRef)child) != AXUIElementGetTypeID()) return false;
        AXUIElementRef node = (__bridge AXUIElementRef)child;
        if (AXUIElementGetPid(node, &owner) != kAXErrorSuccess || owner != pid) return false;
        id role = axValue(node, kAXRoleAttribute);
        if ([axValue(node, CFSTR("AXHidden")) isEqual:@YES]) continue;
        CGRect frame;
        if (!axBounds(node, &frame)) return false;
        if ([role isEqual:@"AXScrollArea"]) {
            CGSize canvas;
            if (!CGRectIsNull(viewport) ||
                !axGeometry(node, CFSTR("AXContentSize"), kAXValueCGSizeType, &canvas) ||
                !CGSizeEqualToSize(canvas, frame.size) ||
                !emptyRelationship(node, kAXHorizontalScrollBarAttribute) ||
                !emptyRelationship(node, kAXVerticalScrollBarAttribute) ||
                !emptyRelationship(node, kAXChildrenAttribute) ||
                !emptyRelationship(node, kAXContentsAttribute)) return false;
            viewport = frame;
        } else if (fullscreen && [role isEqual:@"AXStaticText"] &&
                   [axValue(window, kAXTitleUIElementAttribute) isEqual:child] &&
                   [axValue(window, kAXTitleAttribute) isEqual:axValue(node, kAXValueAttribute)] &&
                   CGRectContainsRect(result->window, frame) &&
                   CGRectGetMaxY(frame) - CGRectGetMinY(result->window) <= 32) {
            // Windows App keeps its native title in AX when the fullscreen
            // title bar retracts. Scan the canvas under it, including its top.
            continue;
        } else if ([role isEqual:@"AXButton"] || [role isEqual:@"AXStaticText"] || [role isEqual:@"AXToolbar"]) {
            chrome = CGRectUnion(chrome, frame);
        } else {
            return false;
        }
    }
    // A fullscreen session may expose only its native AXWindow. Never treat
    // a window containing other controls as an otherwise empty remote canvas.
    if (CGRectIsNull(viewport) && fullscreen && children.count == 0) viewport = result->window;
    if (!validRect(viewport) || !CGRectContainsRect(result->window, viewport) ||
        (!CGRectIsNull(chrome) && CGRectGetMaxY(chrome) > CGRectGetMinY(viewport)))
        return false;
    result->viewport = viewport;
    return true;
}

// Passive geometry lookup for a previously identified desktop, including a
// background Space. This never changes focus or captures the screen.
bool waal_background_guest_viewport(AXUIElementRef window, pid_t pid, CGWindowID expected, CGRect *viewport) {
    @autoreleasepool {
        GuestViewport layout;
        if (!viewport || !readWindowGuestViewport(pid, expected, window, &layout)) return false;
        *viewport = layout.viewport;
        return true;
    }
}

static bool readGuestViewport(pid_t pid, CGWindowID expected, GuestViewport *result) {
    if (!isFrontmost(pid)) return false;
    id app = CFBridgingRelease(AXUIElementCreateApplication(pid));
    if (!app) return false;
    AXUIElementSetMessagingTimeout((__bridge AXUIElementRef)app, 0.25);
    id focused = axValue((__bridge AXUIElementRef)app, kAXFocusedWindowAttribute);
    if (!focused || CFGetTypeID((__bridge CFTypeRef)focused) != AXUIElementGetTypeID()) return false;
    return readWindowGuestViewport(pid, expected, (__bridge AXUIElementRef)focused, result);
}

// Keep at most one ScreenCaptureKit operation outstanding, including callbacks
// that arrive after a timeout. Late callbacks never hold pointers into Rust.
static dispatch_semaphore_t captureGate(void) {
    static dispatch_semaphore_t gate;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ gate = dispatch_semaphore_create(1); });
    return gate;
}

// ScreenCaptureKit scales a whole independent window down to the requested size.
// Keep native pixels where possible and cap both dimensions and total allocation.
CGSize waal_lock_capture_size(CGSize points, double backingScale) {
    double nativeWidth = round(points.width * backingScale);
    double nativeHeight = round(points.height * backingScale);
    if (!isfinite(backingScale) || backingScale <= 0 || !isfinite(nativeWidth) ||
        !isfinite(nativeHeight) || nativeWidth < 1 || nativeHeight < 1) return CGSizeZero;
    double scale = fmin(1, fmin(16384.0 / nativeWidth, 16384.0 / nativeHeight));
    const double pixelBudget = 8192.0 * 4320.0;
    scale = fmin(scale, sqrt(pixelBudget / nativeWidth / nativeHeight));
    double w = floor(nativeWidth * scale), h = floor(nativeHeight * scale);
    return w >= 1 && h >= 1 ? CGSizeMake(w, h) : CGSizeZero;
}

static CGImageRef copyGuestPixels(CGImageRef image, GuestViewport layout, CGRect content) {
    size_t w = CGImageGetWidth(image), h = CGImageGetHeight(image);
    CGRect pixels = waal_guest_viewport_pixels(layout.window, layout.viewport, content, w, h);
    if (CGRectIsNull(pixels)) return NULL;
    CGImageRef view = CGImageCreateWithImageInRect(image, pixels);
    if (!view) return NULL;
    CGRect guest = waal_guest_content_rect(view);
    CGImageRelease(view);
    if (CGRectIsEmpty(guest) ||
        !CGRectContainsRect(CGRectMake(0, 0, pixels.size.width, pixels.size.height), guest)) return NULL;
    guest = CGRectOffset(guest, pixels.origin.x, pixels.origin.y);
    return CGRectEqualToRect(CGRectMake(0, 0, w, h), guest)
        ? CGImageRetain(image) : copyDetail(image, guest, 1.0);
}

API_AVAILABLE(macos(14.0))
static id copyWindowImage(pid_t pid, CGWindowID windowID) {
    dispatch_semaphore_t gate = captureGate();
    if (dispatch_semaphore_wait(gate, DISPATCH_TIME_NOW) != 0) return nil;

    dispatch_semaphore_t finished = dispatch_semaphore_create(0);
    __block id captured = nil;
    const dispatch_time_t deadline = dispatch_time(DISPATCH_TIME_NOW, 3 * NSEC_PER_SEC);
    [SCShareableContent getShareableContentExcludingDesktopWindows:YES onScreenWindowsOnly:YES
        completionHandler:^(SCShareableContent *content, NSError *error) {
        @autoreleasepool {
            SCWindow *window = nil;
            for (SCWindow *candidate in content.windows) {
                if (candidate.windowID == windowID && candidate.owningApplication.processID == pid &&
                    [candidate.owningApplication.bundleIdentifier isEqualToString:@"com.microsoft.rdc.macos"] &&
                    candidate.isOnScreen && candidate.windowLayer == 0) {
                    window = candidate;
                    break;
                }
            }
            const CGSize size = window.frame.size;
            if (error || !window || !isfinite(size.width) || !isfinite(size.height) ||
                size.width <= 0 || size.height <= 0 || dispatch_time(DISPATCH_TIME_NOW, 0) >= deadline ||
                !isFrontmost(pid)) {
                dispatch_semaphore_signal(finished);
                dispatch_semaphore_signal(gate);
                return;
            }
            SCContentFilter *filter = [[SCContentFilter alloc] initWithDesktopIndependentWindow:window];
            // The window's backing scale can change when it moves between displays.
            const CGRect contentRect = filter.contentRect;
            const CGSize output = waal_lock_capture_size(contentRect.size, filter.pointPixelScale);
            GuestViewport before;
            if (CGSizeEqualToSize(output, CGSizeZero) || !readGuestViewport(pid, windowID, &before) ||
                !CGRectEqualToRect(before.window, window.frame) || dispatch_time(DISPATCH_TIME_NOW, 0) >= deadline) {
                dispatch_semaphore_signal(finished);
                dispatch_semaphore_signal(gate);
                return;
            }
            SCStreamConfiguration *config = [[SCStreamConfiguration alloc] init];
            config.width = (size_t)output.width;
            config.height = (size_t)output.height;
            config.captureResolution = SCCaptureResolutionBest;
            config.preservesAspectRatio = YES;
            config.scalesToFit = NO;
            config.showsCursor = NO;
            config.ignoreShadowsSingleWindow = YES;
            config.ignoreGlobalClipSingleWindow = YES;
            if (@available(macOS 14.2, *)) config.includeChildWindows = NO;
            [SCScreenshotManager captureImageWithFilter:filter configuration:config
                completionHandler:^(CGImageRef image, NSError *captureError) {
                GuestViewport after;
                if (image && !captureError && CGImageGetWidth(image) == (size_t)output.width &&
                    CGImageGetHeight(image) == (size_t)output.height &&
                    dispatch_time(DISPATCH_TIME_NOW, 0) < deadline && readGuestViewport(pid, windowID, &after) &&
                    CGRectEqualToRect(before.window, after.window) && CGRectEqualToRect(before.viewport, after.viewport) &&
                    dispatch_time(DISPATCH_TIME_NOW, 0) < deadline)
                    captured = CFBridgingRelease(copyGuestPixels(image, before, contentRect));
                dispatch_semaphore_signal(finished);
                dispatch_semaphore_signal(gate);
            }];
        }
    }];
    if (dispatch_semaphore_wait(finished, deadline) != 0) return nil;
    return captured;
}

static atomic_bool accurateRecognitionStarted;

static VNRecognizeTextRequest *englishTextRequest(VNRequestTextRecognitionLevel level) {
    if (level == VNRequestTextRecognitionLevelAccurate)
        atomic_store_explicit(&accurateRecognitionStarted, true, memory_order_relaxed);
    VNRecognizeTextRequest *request = [[VNRecognizeTextRequest alloc] init];
    request.recognitionLevel = level;
    request.usesLanguageCorrection = NO;
    request.recognitionLanguages = @[@"en-US"];
    return request;
}

// The recovery subprocess receives no screenshot. A successful read of this
// fixed sample also proves that Vision can execute its newly prepared models.
bool waal_prepare_lock_recognition_sample(void) {
    @autoreleasepool {
        NSBitmapImageRep *sample = [[NSBitmapImageRep alloc] initWithBitmapDataPlanes:NULL
            pixelsWide:240 pixelsHigh:48 bitsPerSample:8 samplesPerPixel:4 hasAlpha:YES
            isPlanar:NO colorSpaceName:NSCalibratedRGBColorSpace bytesPerRow:0 bitsPerPixel:0];
        NSGraphicsContext *graphics = sample ? [NSGraphicsContext graphicsContextWithBitmapImageRep:sample] : nil;
        if (!graphics) return false;
        [NSGraphicsContext saveGraphicsState];
        NSGraphicsContext.currentContext = graphics;
        [NSColor.blackColor setFill];
        NSRectFill(NSMakeRect(0, 0, 240, 48));
        [@"Sample" drawAtPoint:NSMakePoint(8, 10) withAttributes:@{
            NSFontAttributeName: [NSFont systemFontOfSize:22],
            NSForegroundColorAttributeName: NSColor.whiteColor
        }];
        [NSGraphicsContext restoreGraphicsState];
        CGImageRef image = sample.CGImage;
        if (!image) return false;
        VNImageRequestHandler *handler = [[VNImageRequestHandler alloc] initWithCGImage:image options:@{}];
        VNRecognizeTextRequest *request = englishTextRequest(VNRequestTextRecognitionLevelAccurate);
        if (![handler performRequests:@[request] error:nil] || request.results.count != 1) return false;
        VNRecognizedText *word = [request.results.firstObject topCandidates:1].firstObject;
        return [word.string isEqualToString:@"Sample"];
    }
}

void waal_prepare_lock_recognition(void) {
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        // A real observation can start first. It never waits for this task.
        if (!atomic_exchange_explicit(&accurateRecognitionStarted, true, memory_order_relaxed))
            waal_prepare_lock_recognition_sample();
    });
}

// The overview and the crop cover the same captured frame. Only the overview
// is downsized. All observations passed to Rust use full-window Vision coordinates.
static CGImageRef copyBitmap(CGImageRef source, size_t width, size_t height) {
    CGColorSpaceRef space = CGColorSpaceCreateWithName(kCGColorSpaceSRGB);
    if (!space) return NULL;
    CGContextRef bitmap = CGBitmapContextCreate(NULL, width, height, 8, 0, space,
                                                 (CGBitmapInfo)kCGImageAlphaNoneSkipLast);
    CGColorSpaceRelease(space);
    if (!bitmap) return NULL;
    CGContextSetInterpolationQuality(bitmap, kCGInterpolationHigh);
    CGContextDrawImage(bitmap, CGRectMake(0, 0, width, height), source);
    CGImageRef image = CGBitmapContextCreateImage(bitmap);
    CGContextRelease(bitmap);
    return image;
}

static CGImageRef copyScaledImage(CGImageRef source, size_t width, size_t height) {
    if (width == CGImageGetWidth(source) && height == CGImageGetHeight(source))
        return CGImageRetain(source);
    return copyBitmap(source, width, height);
}

// A CGImage subimage can keep the parent's row stride. Give Vision a compact
// bitmap with complete rows even for a crop reaching the bottom-right edge.
static CGImageRef copyDetail(CGImageRef source, CGRect pixels, double scale) {
    CGImageRef crop = CGImageCreateWithImageInRect(source, pixels);
    if (!crop) return NULL;
    CGImageRef bitmap = copyBitmap(crop, lround(CGImageGetWidth(crop) * scale),
                                  lround(CGImageGetHeight(crop) * scale));
    CGImageRelease(crop);
    return bitmap;
}

// A failed Vision request is distinct from a successful read with no matches.
// Keep failures local to this captured frame, including optional detail reads.
static bool performTextRequest(VNImageRequestHandler *handler, VNRecognizeTextRequest *request,
                               bool *visionFailed) {
    if (*visionFailed) return false;
    if ([handler performRequests:@[request] error:nil] && request.results) return true;
    *visionFailed = true;
    return false;
}

static CGRect readPasswordPixels(CGImageRef source, CGRect pixels, double scale, WaalTextVisitor veto,
                                 void *context, float *confidence, bool *visionFailed) {
    size_t w = CGImageGetWidth(source), h = CGImageGetHeight(source);
    CGImageRef detail = copyDetail(source, pixels, scale);
    if (!detail) return CGRectNull;
    VNImageRequestHandler *handler = [[VNImageRequestHandler alloc] initWithCGImage:detail options:@{}];
    CGImageRelease(detail);
    VNRecognizeTextRequest *request = englishTextRequest(VNRequestTextRecognitionLevelAccurate);
    if (veto) request.minimumTextHeight = .004;
    if (!performTextRequest(handler, request, visionFailed) || request.results.count > (veto ? 8u : 1u)) return CGRectNull;
    CGRect result = CGRectNull;
    for (VNRecognizedTextObservation *observation in request.results) {
        VNRecognizedText *word = [observation topCandidates:1].firstObject;
        const char *utf8 = word.string.UTF8String;
        size_t length = [word.string lengthOfBytesUsingEncoding:NSUTF8StringEncoding];
        if (!utf8 || !length || length > 512) return CGRectNull;
        CGRect box = observation.boundingBox;
        CGRect normalized = CGRectMake((pixels.origin.x + box.origin.x * pixels.size.width) / w,
                        1 - (CGRectGetMaxY(pixels) - box.origin.y * pixels.size.height) / h,
                        box.size.width * pixels.size.width / w, box.size.height * pixels.size.height / h);
        if ([word.string caseInsensitiveCompare:@"Password"] != NSOrderedSame) {
            // The same conflict-only visitor handles accurately read account tiles.
            if (veto) veto(context, CornerText, utf8, length, word.confidence,
                           CGRectGetMidX(normalized), CGRectGetMidY(normalized), normalized.size.width, normalized.size.height);
            continue;
        }
        if (!CGRectIsNull(result) || word.confidence < 0.50) return CGRectNull;
        result = normalized;
        *confidence = word.confidence;
    }
    return result;
}

static CGRect readPassword(CGImageRef source, CGRect region, float *confidence, bool *visionFailed) {
    size_t w = CGImageGetWidth(source), h = CGImageGetHeight(source);
    // CGImage crops have their origin at the top left; Vision's is at the bottom left.
    CGRect pixels = CGRectIntegral(CGRectMake(CGRectGetMinX(region) * w, (1 - CGRectGetMaxY(region)) * h,
                                              region.size.width * w, region.size.height * h));
    pixels = CGRectIntersection(pixels, CGRectMake(0, 0, w, h));
    if (CGRectIsEmpty(pixels)) return CGRectNull;
    // Give Vision a readable raster for small controls on low-resolution sessions.
    return readPasswordPixels(source, pixels, fmin(4.0, fmax(1.0, 48.0 / pixels.size.height)), NULL, NULL, confidence, visionFailed);
}

static bool visitDetailText(CGImageRef source, CGRect pixels, double scale, int kind, NSUInteger limit,
                            WaalTextVisitor visitor, void *context, bool *visionFailed) {
    double w = CGImageGetWidth(source), h = CGImageGetHeight(source);
    pixels = CGRectIntersection(CGRectIntegral(pixels), CGRectMake(0, 0, w, h));
    if (CGRectIsEmpty(pixels)) return false;
    CGImageRef detail = copyDetail(source, pixels, scale);
    if (!detail) return false;
    VNImageRequestHandler *handler = [[VNImageRequestHandler alloc] initWithCGImage:detail options:@{}];
    CGImageRelease(detail);
    VNRecognizeTextRequest *request = englishTextRequest(VNRequestTextRecognitionLevelAccurate);
    if (!performTextRequest(handler, request, visionFailed)) return false;
    if (request.results.count > limit) {
        if (kind != AccountText) return false;
        visitor(context, AmbiguousText, NULL, 0, 1.0, CGRectGetMidX(pixels) / w,
                1.0 - CGRectGetMidY(pixels) / h, pixels.size.width / w, pixels.size.height / h);
        return true;
    }
    if (kind == AccountText && request.results.count == 2) kind = PairedAccountText;
    for (VNRecognizedTextObservation *observation in request.results) {
        VNRecognizedText *candidate = [observation topCandidates:1].firstObject;
        NSString *text = candidate.string;
        const char *utf8 = text.UTF8String;
        size_t length = [text lengthOfBytesUsingEncoding:NSUTF8StringEncoding];
        if (!utf8 || !length || length > 512) return false;
        CGRect box = observation.boundingBox;
        visitor(context, kind, utf8, length, candidate.confidence,
                (pixels.origin.x + CGRectGetMidX(box) * pixels.size.width) / w,
                1.0 - (CGRectGetMaxY(pixels) - CGRectGetMidY(box) * pixels.size.height) / h,
                box.size.width * pixels.size.width / w, box.size.height * pixels.size.height / h);
    }
    return true;
}

static VNRecognizeTextRequest *overviewRequest(CGImageRef image, bool *visionFailed) {
    VNImageRequestHandler *handler = [[VNImageRequestHandler alloc] initWithCGImage:image options:@{}];
    VNRecognizeTextRequest *request = englishTextRequest(VNRequestTextRecognitionLevelFast);
    if (!performTextRequest(handler, request, visionFailed) || request.results.count > 64)
        return nil;
    return request;
}

// Core and crop are top-left pixel rectangles on the overview. Each line is
// owned by the core containing its midpoint. The crop extends beyond that
// core so text at an internal boundary can be recognized as a complete line.
static bool visitOverviewText(VNRecognizeTextRequest *request, CGRect core, CGRect crop,
                              CGSize size, CGRect masked, size_t *count, WaalTextVisitor visitor, void *context) {
    for (VNRecognizedTextObservation *observation in request.results) {
        CGRect local = observation.boundingBox;
        CGRect pixels = CGRectMake(crop.origin.x + local.origin.x * crop.size.width,
                                   crop.origin.y + (1.0 - CGRectGetMaxY(local)) * crop.size.height,
                                   local.size.width * crop.size.width, local.size.height * crop.size.height);
        double x = CGRectGetMidX(pixels), y = CGRectGetMidY(pixels);
        if (x < core.origin.x || x >= CGRectGetMaxX(core) || y < core.origin.y || y >= CGRectGetMaxY(core))
            continue;
        if (++*count > 64) return false;
        CGRect box = CGRectMake(pixels.origin.x / size.width, 1.0 - CGRectGetMaxY(pixels) / size.height,
                                pixels.size.width / size.width, pixels.size.height / size.height);
        if (!CGRectIsNull(masked) && CGRectContainsRect(masked, box)) continue;
        VNRecognizedText *candidate = [observation topCandidates:1].firstObject;
        NSString *text = candidate.string;
        const char *utf8 = text.UTF8String;
        size_t length = [text lengthOfBytesUsingEncoding:NSUTF8StringEncoding];
        if (!utf8 || !length || length > 512) return false;
        visitor(context, OverviewText, utf8, length, candidate.confidence, CGRectGetMidX(box),
                CGRectGetMidY(box), box.size.width, box.size.height);
    }
    return true;
}

static bool visitOverview(CGImageRef image, VNRecognizeTextRequest *existing, CGRect masked,
                          WaalTextVisitor visitor, void *context, bool *visionFailed) {
    size_t w = CGImageGetWidth(image), h = CGImageGetHeight(image);
    CGSize size = CGSizeMake(w, h);
    CGRect full = CGRectMake(0, 0, w, h);
    size_t count = 0;
    if (w <= 4096 && h <= 2400) {
        VNRecognizeTextRequest *request = existing ?: overviewRequest(image, visionFailed);
        return request && visitOverviewText(request, full, full, size, masked, &count, visitor, context);
    }
    // Fast Vision can omit a fixed-size account name on a whole 8K image.
    // Use an odd grid so the centered Windows account and editor stay together.
    size_t cols = ((w + 1919) / 1920) | 1, rows = ((h + 1439) / 1440) | 1;
    for (size_t row = 0; row < rows; row++) {
        for (size_t col = 0; col < cols; col++) {
            @autoreleasepool {
                size_t left = col * w / cols, right = (col + 1) * w / cols;
                size_t top = row * h / rows, bottom = (row + 1) * h / rows;
                CGRect core = CGRectMake(left, top, right - left, bottom - top);
                CGRect crop = CGRectIntersection(full, CGRectInset(core, -256, -96));
                CGImageRef bitmap = copyDetail(image, crop, 1.0);
                if (!bitmap) return false;
                VNRecognizeTextRequest *request = overviewRequest(bitmap, visionFailed);
                CGImageRelease(bitmap);
                if (!request || !visitOverviewText(request, core, crop, size, masked, &count, visitor, context))
                    return false;
            }
        }
    }
    return true;
}

// At low guest DPI the fast overview may miss both the name and the prompt.
// Restrict an accurate read to the left half of the centered editor band.
// Full guest context is still checked after recovering the native word.
static CGRect findSmallPassword(CGImageRef source, WaalTextVisitor veto, void *context, float *confidence, bool *visionFailed) {
    double w = CGImageGetWidth(source), h = CGImageGetHeight(source);
    double left = fmax(0.06 * w, 0.50 * w - 1024);
    CGRect pixels = CGRectIntegral(CGRectMake(left, 0.42 * h, 0.51 * w - left, 0.38 * h));
    double scale = fmin(4.0, fmax(1.0, 1536.0 / pixels.size.width));
    return readPasswordPixels(source, pixels, scale, veto, context, confidence, visionFailed);
}

// The unfocused editor can lose both its blue underline and a reliable fast
// OCR reading of the placeholder. Use the centered account caption to choose
// a native search region. Its pixel height tracks the guest DPI.
static CGRect unfocusedPassword(CGImageRef source, VNRecognizeTextRequest *overview,
                               WaalTextVisitor veto, void *context, double *editorCenter, float *confidence, bool *visionFailed) {
    double w = CGImageGetWidth(source), h = CGImageGetHeight(source);
    CGRect caption = CGRectNull, fastWord = CGRectNull;
    unsigned centeredCaptions = 0;
    for (VNRecognizedTextObservation *observation in overview.results) {
        CGRect box = observation.boundingBox;
        NSString *word = [observation topCandidates:1].firstObject.string;
        // Preserve the direct native re-read when fast OCR already locates
        // Password, including the common single-letter misread of its P.
        if (word.length == 8 && [[word substringFromIndex:1] caseInsensitiveCompare:@"assword"] == NSOrderedSame) {
            if (!CGRectIsNull(fastWord)) return CGRectNull;
            fastWord = CGRectInset(box, -.012, -.009);
        }
        double centerTolerance = fmax(.035, fmin(.08, .16 * box.size.width));
        if (fabs(CGRectGetMidX(box) - 0.5) > centerTolerance || CGRectGetMidY(box) < 0.34 ||
            CGRectGetMidY(box) > 0.63 || box.size.width < box.size.height * h / w * 2) continue;
        // The placeholder starts to the left of center. The account caption
        // spans it; a second centered caption makes the screen ambiguous.
        if (CGRectGetMinX(box) >= 0.5 || CGRectGetMaxX(box) <= 0.5) continue;
        centeredCaptions++;
        caption = box;
    }
    *editorCenter = centeredCaptions == 1 ? CGRectGetMidX(caption) : 0.5;
    if (!CGRectIsNull(fastWord)) {
        CGRect exact = readPassword(source, fastWord, confidence, visionFailed);
        if (!CGRectIsEmpty(exact)) return exact;
    }
    if (centeredCaptions == 0 && overview.results.count <= 8) return findSmallPassword(source, veto, context, confidence, visionFailed);
    if (centeredCaptions != 1) return CGRectNull;
    double font = caption.size.height * h, cx = *editorCenter * w;
    double top = (1.0 - CGRectGetMinY(caption)) * h;
    // Enough space for the left-aligned prompt for both compact usernames
    // and long domain names, without including the centered name above it.
    CGRect pixels = CGRectIntersection(CGRectIntegral(CGRectMake(cx - 11 * font, top + .10 * font,
                                             12 * font, 4 * font)), CGRectMake(0, 0, w, h));
    if (CGRectIsEmpty(pixels)) return CGRectNull;
    return readPasswordPixels(source, pixels, fmin(4.0, fmax(1.0, 36.0 / font)), veto, context, confidence, visionFailed);
}

static bool recognizeFrame(CGImageRef source, WaalTextVisitor visitor, void *context, bool *visionFailed) {
    if (!source || !visitor || !context) return false;
    size_t w = CGImageGetWidth(source), h = CGImageGetHeight(source);
    if (!w || !h) return false;
    CGRect field = CGRectNull;
    WaalFieldKind kind = waal_password_field(source, &field);
    if (kind == WaalFieldUnavailable) return false;
    if (kind == WaalFieldAmbiguous) return true;
    bool measuredField = !CGRectIsEmpty(field);
    double scale = fmin(1920.0 / w, 1440.0 / h);
    if (!CGRectIsEmpty(field)) {
        // A 100% Windows desktop on a 5K monitor can still have a 290px editor.
        // Preserve enough pixels to read the account name and competing labels.
        scale = fmax(scale, 290.0 / (field.size.width * w));
    }
    // A near-identity resample can erase a one-pixel stroke for no useful savings.
    if (scale >= 0.95) scale = 1.0;
    float confidence = 0;
    CGRect placeholder = CGRectNull;
    if (kind == WaalFieldPlaceholderCandidate) {
        CGRect region = field;
        region.size.width *= .75; // Exclude the reveal and submit buttons.
        placeholder = readPassword(source, region, &confidence, visionFailed);
        if (CGRectIsEmpty(placeholder)) return true;
    }
    id overview = CFBridgingRelease(copyScaledImage(source, lround(w * scale), lround(h * scale)));
    if (!overview) return false;
    VNRecognizeTextRequest *existing = nil;
    if (kind == WaalFieldNone) {
        existing = overviewRequest((__bridge CGImageRef)overview, visionFailed);
        if (!existing) return false;
        double editorCenter;
        placeholder = unfocusedPassword(source, existing, visitor, context, &editorCenter, &confidence, visionFailed);
        if (CGRectIsEmpty(placeholder)) return true;
        field = waal_neutral_password_field(source, placeholder);
        measuredField = !CGRectIsEmpty(field);
        if (!measuredField) {
            // On a centered form the measured word inset gives the scale for
            // the context reads. A shifted form requires its visible outline.
            if (fabs(editorCenter - .5) > .035) return true;
            double ew = (editorCenter - CGRectGetMinX(placeholder)) * w / 0.46;
            double eh = 0.118 * ew;
            if (ew < 90 || ew > .85 * w || placeholder.size.width * w < ew * .10 ||
                placeholder.size.width * w > ew * .46 || placeholder.size.height * h < eh * .15 ||
                placeholder.size.height * h > eh * .90) return true;
            field = CGRectMake(editorCenter - .5 * ew / w, CGRectGetMidY(placeholder) - .5 * eh / h,
                               ew / w, eh / h);
        }
        kind = WaalFieldPlaceholderCandidate;
        double contextScale = fmin(1.0, fmax(scale, 290.0 / (field.size.width * w)));
        if (contextScale >= .95) contextScale = 1.0;
        if (contextScale != scale) {
            overview = CFBridgingRelease(copyScaledImage(source, lround(w * contextScale), lround(h * contextScale)));
            if (!overview) return false;
            existing = nil;
        }
    }
    CGRect masked = kind == WaalFieldMasked ? CGRectInset(field, -.002, -.002) : CGRectNull;
    if (!visitOverview((__bridge CGImageRef)overview, existing, masked, visitor, context, visionFailed)) return false;
    double ew = field.size.width * w, eh = field.size.height * h;
    // The overview may omit small account tiles, including "Other user".
    double cornerHeight = fmin(floor(h / 3.0), ew);
    CGRect corner = CGRectMake(0, h - cornerHeight, fmin(w / 3.0, 1.5 * ew), cornerHeight);
    double detailScale = eh < 32 ? fmin(5.0, 48.0 / eh) : 1.0;
    if (!visitDetailText(source, corner, detailScale, CornerText, 16, visitor, context, visionFailed)) return false;
    // Vision can turn the input-language abbreviation into a longer word
    // when the guest is scaled to fit a window. Re-read the indicator in
    // original pixels. This optional read can only repair a matching line.
    CGRect layout = CGRectMake(w - 0.38 * ew, h - 1.51 * eh, 0.13 * ew, 0.64 * eh);
    visitDetailText(source, layout, detailScale, LayoutText, 1, visitor, context, visionFailed);
    // Fast can misread a centered name even on a large remote display
    // resized to a wide window. Read its native pixels at every guest DPI.
    CGRect name = CGRectMake(CGRectGetMidX(field) * w - 0.8 * ew,
                             (1.0 - CGRectGetMidY(field)) * h - 3.1 * eh,
                             1.6 * ew, 2.45 * eh);
    // A two-line caption needs an independent editor measurement to anchor both lines.
    if (!visitDetailText(source, name, 1.0, AccountText, measuredField ? 2 : 1, visitor, context, visionFailed)) return false;
    if (eh < 32) {
        // A compressed "Other user" or instruction just below the editor
        // may also disappear from the fast window-wide pass.
        CGRect below = CGRectMake(CGRectGetMidX(field) * w - 0.85 * ew,
                                  (1.0 - field.origin.y) * h + 0.05 * eh,
                                  1.7 * ew, 3.8 * eh);
        if (!visitDetailText(source, below, detailScale, OverviewText, 16, visitor, context, visionFailed)) return false;
    }
    CGRect box = kind == WaalFieldMasked ? field : placeholder;
    if (kind == WaalFieldPlaceholderCandidate) {
        visitor(context, EditorBounds, NULL, 0, 1.0, CGRectGetMidX(field), CGRectGetMidY(field),
                field.size.width, field.size.height);
    }
    visitor(context, kind == WaalFieldMasked ? MaskedField : VerifiedPlaceholder, NULL, 0,
            kind == WaalFieldMasked ? 1.0 : confidence, CGRectGetMidX(box), CGRectGetMidY(box),
            box.size.width, box.size.height);
    return true;
}

// Rust discards all observations for a failed frame. -1 additionally allows
// the supervisor to repair Vision after macOS evicts compiled model files.
static int frameStatus(CGImageRef source, WaalTextVisitor visitor, void *context) {
    bool visionFailed = false;
    bool read = recognizeFrame(source, visitor, context, &visionFailed);
    return visionFailed ? -1 : read;
}

// In-memory frame fixtures share the same failure semantics as a live capture.
bool waal_recognize_lock_frame(CGImageRef source, WaalTextVisitor visitor, void *context) {
    return frameStatus(source, visitor, context) == 1;
}

int waal_observe_lock_screen(pid_t pid, uint32_t windowID, WaalTextVisitor visitor, void *context) {
    @autoreleasepool {
        if (!visitor || !context || !windowID || pid <= 0 || !waal_lock_capture_allowed() ||
            !isFrontmost(pid)) return false;
        if (@available(macOS 14.0, *)) {
            id image = copyWindowImage(pid, windowID);
            if (!image || !isFrontmost(pid)) return false;
            int status = frameStatus((__bridge CGImageRef)image, visitor, context);
            return isFrontmost(pid) ? status : 0;
        }
        return false;
    }
}
