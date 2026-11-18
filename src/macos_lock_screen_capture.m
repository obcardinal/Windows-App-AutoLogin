// ScreenCaptureKit and Vision operate in this process. Only the verified window
// is passed to the screenshot API. No frame or recognition result is serialized.
#import <AppKit/AppKit.h>
#import <ScreenCaptureKit/ScreenCaptureKit.h>
#import <Vision/Vision.h>
#include "macos_masked_field.h"

#include <math.h>
#include <stdint.h>

enum { OverviewText, MaskedField, VerifiedPlaceholder, EditorBounds, CornerText, AccountText };
typedef void (*WaalTextVisitor)(void *, int, const char *, size_t, float, double, double, double, double);

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

// Keep at most one ScreenCaptureKit operation outstanding, including callbacks
// that arrive after a timeout. Late callbacks never hold pointers into Rust.
static dispatch_semaphore_t captureGate(void) {
    static dispatch_semaphore_t gate;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ gate = dispatch_semaphore_create(1); });
    return gate;
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
                size.width < 500 || size.height < 350 || dispatch_time(DISPATCH_TIME_NOW, 0) >= deadline ||
                !isFrontmost(pid)) {
                dispatch_semaphore_signal(finished);
                dispatch_semaphore_signal(gate);
                return;
            }
            SCContentFilter *filter = [[SCContentFilter alloc] initWithDesktopIndependentWindow:window];
            // The window's backing scale can change when it moves between displays.
            const CGSize contentSize = filter.contentRect.size;
            const double backingScale = filter.pointPixelScale;
            const double width = round(contentSize.width * backingScale);
            const double height = round(contentSize.height * backingScale);
            // Bound a single BGRA capture to a DCI 8K frame's pixel count.
            if (!(backingScale > 0 && width >= 1 && height >= 1 &&
                  width <= 16384 && height <= 16384 && width * height <= 8192.0 * 4320.0)) {
                dispatch_semaphore_signal(finished);
                dispatch_semaphore_signal(gate);
                return;
            }
            SCStreamConfiguration *config = [[SCStreamConfiguration alloc] init];
            config.width = (size_t)width;
            config.height = (size_t)height;
            config.captureResolution = SCCaptureResolutionBest;
            config.scalesToFit = NO;
            config.showsCursor = NO;
            config.ignoreShadowsSingleWindow = YES;
            config.ignoreGlobalClipSingleWindow = YES;
            [SCScreenshotManager captureImageWithFilter:filter configuration:config
                completionHandler:^(CGImageRef image, NSError *captureError) {
                if (image && !captureError && isFrontmost(pid) &&
                    dispatch_time(DISPATCH_TIME_NOW, 0) < deadline) {
                    captured = CFBridgingRelease(CGImageRetain(image));
                }
                dispatch_semaphore_signal(finished);
                dispatch_semaphore_signal(gate);
            }];
        }
    }];
    if (dispatch_semaphore_wait(finished, deadline) != 0) return nil;
    return captured;
}

static VNRecognizeTextRequest *englishTextRequest(VNRequestTextRecognitionLevel level) {
    VNRecognizeTextRequest *request = [[VNRecognizeTextRequest alloc] init];
    request.recognitionLevel = level;
    request.usesLanguageCorrection = NO;
    request.recognitionLanguages = @[@"en-US"];
    return request;
}

// Fast OCR can read the empty field's "Password" as "kassword". A near
// match only triggers a second read. It is never itself evidence of a lock.
static bool needsPlaceholderConfirmation(NSString *text) {
    if (text.length != 8 || ![text hasSuffix:@"assword"]) return false;
    unichar first = [text characterAtIndex:0];
    return ((first >= 'a' && first <= 'z') || (first >= 'A' && first <= 'Z')) &&
           first != 'P' && first != 'p';
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

static CGRect readPassword(CGImageRef source, CGRect region, float *confidence) {
    size_t w = CGImageGetWidth(source), h = CGImageGetHeight(source);
    // CGImage crops have their origin at the top left; Vision's is at the bottom left.
    CGRect pixels = CGRectIntegral(CGRectMake(CGRectGetMinX(region) * w, (1 - CGRectGetMaxY(region)) * h,
                                              region.size.width * w, region.size.height * h));
    pixels = CGRectIntersection(pixels, CGRectMake(0, 0, w, h));
    if (CGRectIsEmpty(pixels)) return CGRectNull;
    // Give Vision a readable raster for small controls on low-resolution sessions.
    double scale = fmin(4.0, fmax(1.0, 48.0 / pixels.size.height));
    CGImageRef detail = copyDetail(source, pixels, scale);
    if (!detail) return CGRectNull;
    VNImageRequestHandler *handler = [[VNImageRequestHandler alloc] initWithCGImage:detail options:@{}];
    CGImageRelease(detail);
    VNRecognizeTextRequest *request = englishTextRequest(VNRequestTextRecognitionLevelAccurate);
    if (![handler performRequests:@[request] error:nil] || request.results.count != 1) return CGRectNull;
    VNRecognizedTextObservation *observation = request.results.firstObject;
    VNRecognizedText *candidate = [observation topCandidates:1].firstObject;
    if (!candidate || candidate.confidence < 0.50 ||
        [candidate.string caseInsensitiveCompare:@"Password"] != NSOrderedSame) return CGRectNull;
    *confidence = candidate.confidence;
    CGRect local = observation.boundingBox;
    return CGRectMake((pixels.origin.x + local.origin.x * pixels.size.width) / w,
                      1 - (CGRectGetMaxY(pixels) - local.origin.y * pixels.size.height) / h,
                      local.size.width * pixels.size.width / w, local.size.height * pixels.size.height / h);
}

static bool visitDetailText(CGImageRef source, CGRect pixels, double scale, int kind,
                            WaalTextVisitor visitor, void *context) {
    double w = CGImageGetWidth(source), h = CGImageGetHeight(source);
    pixels = CGRectIntersection(CGRectIntegral(pixels), CGRectMake(0, 0, w, h));
    if (CGRectIsEmpty(pixels)) return false;
    CGImageRef detail = copyDetail(source, pixels, scale);
    if (!detail) return false;
    VNImageRequestHandler *handler = [[VNImageRequestHandler alloc] initWithCGImage:detail options:@{}];
    CGImageRelease(detail);
    VNRecognizeTextRequest *request = englishTextRequest(VNRequestTextRecognitionLevelAccurate);
    NSUInteger limit = kind == AccountText ? 1 : 16;
    if (![handler performRequests:@[request] error:nil] || !request.results || request.results.count > limit)
        return false;
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

static VNRecognizeTextRequest *overviewRequest(CGImageRef image) {
    VNImageRequestHandler *handler = [[VNImageRequestHandler alloc] initWithCGImage:image options:@{}];
    VNRecognizeTextRequest *request = englishTextRequest(VNRequestTextRecognitionLevelFast);
    if (![handler performRequests:@[request] error:nil] || !request.results || request.results.count > 64)
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
                          WaalTextVisitor visitor, void *context) {
    size_t w = CGImageGetWidth(image), h = CGImageGetHeight(image);
    CGSize size = CGSizeMake(w, h);
    CGRect full = CGRectMake(0, 0, w, h);
    size_t count = 0;
    if (w <= 4096 && h <= 2400) {
        VNRecognizeTextRequest *request = existing ?: overviewRequest(image);
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
                VNRecognizeTextRequest *request = overviewRequest(bitmap);
                CGImageRelease(bitmap);
                if (!request || !visitOverviewText(request, core, crop, size, masked, &count, visitor, context))
                    return false;
            }
        }
    }
    return true;
}

bool waal_recognize_lock_frame(CGImageRef source, WaalTextVisitor visitor, void *context) {
    if (!source || !visitor || !context) return false;
    size_t w = CGImageGetWidth(source), h = CGImageGetHeight(source);
    if (!w || !h) return false;
    CGRect field = CGRectNull;
    WaalFieldKind kind = waal_password_field(source, &field);
    if (kind == WaalFieldUnavailable) return false;
    if (kind == WaalFieldAmbiguous) return true;
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
        placeholder = readPassword(source, region, &confidence);
        if (CGRectIsEmpty(placeholder)) return true;
    }
    id overview = CFBridgingRelease(copyScaledImage(source, lround(w * scale), lround(h * scale)));
    if (!overview) return false;
    VNRecognizeTextRequest *existing = nil;
    if (kind == WaalFieldNone) {
        // An editor without an underline uses the bounded whole-window overview.
        // Locate a likely placeholder and verify it in the original pixels.
        existing = overviewRequest((__bridge CGImageRef)overview);
        if (!existing) return false;
        CGRect region = CGRectNull;
        for (VNRecognizedTextObservation *observation in existing.results) {
            VNRecognizedText *candidate = [observation topCandidates:1].firstObject;
            NSString *text = candidate.string;
            if (text && ([text caseInsensitiveCompare:@"Password"] == NSOrderedSame ||
                         needsPlaceholderConfirmation(text))) {
                if (!CGRectIsNull(region)) return true;
                region = CGRectInset(observation.boundingBox, -.012, -.009);
            }
        }
        if (CGRectIsNull(region)) return true;
        placeholder = readPassword(source, region, &confidence);
        if (CGRectIsEmpty(placeholder)) return true;
    }
    CGRect masked = kind == WaalFieldMasked ? CGRectInset(field, -.002, -.002) : CGRectNull;
    if (!visitOverview((__bridge CGImageRef)overview, existing, masked, visitor, context)) return false;
    if (kind != WaalFieldNone) {
        double ew = field.size.width * w, eh = field.size.height * h;
        // The overview may omit small account tiles, including "Other user".
        double cornerHeight = fmin(floor(h / 3.0), ew);
        CGRect corner = CGRectMake(0, h - cornerHeight, fmin(w / 3.0, 1.5 * ew), cornerHeight);
        double detailScale = eh < 32 ? fmin(5.0, 48.0 / eh) : 1.0;
        if (!visitDetailText(source, corner, detailScale, CornerText, visitor, context)) return false;
        if (eh < 32) {
            // On a downsampled desktop, Fast can merge the words of the name.
            // Anchor the native read to the actual editor directly below it.
            CGRect name = CGRectMake(CGRectGetMidX(field) * w - 0.8 * ew,
                                     (1.0 - CGRectGetMidY(field)) * h - 3.1 * eh,
                                     1.6 * ew, 2.45 * eh);
            if (!visitDetailText(source, name, 1.0, AccountText, visitor, context)) return false;
            // A compressed "Other user" or instruction just below the editor
            // may also disappear from the fast window-wide pass.
            CGRect below = CGRectMake(CGRectGetMidX(field) * w - 0.85 * ew,
                                      (1.0 - field.origin.y) * h + 0.05 * eh,
                                      1.7 * ew, 3.8 * eh);
            if (!visitDetailText(source, below, detailScale, OverviewText, visitor, context)) return false;
        }
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

bool waal_observe_lock_screen(pid_t pid, uint32_t windowID, WaalTextVisitor visitor, void *context) {
    @autoreleasepool {
        if (!visitor || !context || !windowID || pid <= 0 || !waal_lock_capture_allowed() ||
            !isFrontmost(pid)) return false;
        if (@available(macOS 14.0, *)) {
            id image = copyWindowImage(pid, windowID);
            if (!image || !isFrontmost(pid)) return false;
            return waal_recognize_lock_frame((__bridge CGImageRef)image, visitor, context) && isFrontmost(pid);
        }
        return false;
    }
}
