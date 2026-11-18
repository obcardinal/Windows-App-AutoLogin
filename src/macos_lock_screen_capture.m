// ScreenCaptureKit and Vision operate in this process. Only the verified window
// is passed to the screenshot API. No frame or recognition result is serialized.
#import <AppKit/AppKit.h>
#import <ScreenCaptureKit/ScreenCaptureKit.h>
#import <Vision/Vision.h>
#include "macos_masked_field.h"

#include <math.h>
#include <stdint.h>

typedef void (*WaalTextVisitor)(void *, const char *, size_t, float, double, double, double, double);

bool waal_lock_capture_supported(void) {
    if (@available(macOS 14.0, *)) return true;
    return false;
}

bool waal_lock_capture_allowed(void) {
    return waal_lock_capture_supported() && CGPreflightScreenCaptureAccess();
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
            SCStreamConfiguration *config = [[SCStreamConfiguration alloc] init];
            double scale = MIN(2.0, MIN(1920.0 / size.width, 1440.0 / size.height));
            config.width = (size_t)lround(size.width * scale);
            config.height = (size_t)lround(size.height * scale);
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

bool waal_observe_lock_screen(pid_t pid, uint32_t windowID, WaalTextVisitor visitor, void *context) {
    @autoreleasepool {
        if (!visitor || !context || !windowID || pid <= 0 || !waal_lock_capture_allowed() ||
            !isFrontmost(pid)) return false;
        if (@available(macOS 14.0, *)) {
            id image = copyWindowImage(pid, windowID);
            if (!image || !isFrontmost(pid)) return false;

            CGRect masked = CGRectNull;
            bool hasMaskedField = waal_masked_field((__bridge CGImageRef)image, &masked);
            VNRecognizeTextRequest *request = [[VNRecognizeTextRequest alloc] init];
            request.recognitionLevel = VNRequestTextRecognitionLevelFast;
            request.usesLanguageCorrection = NO;
            request.recognitionLanguages = @[@"en-US"];
            VNImageRequestHandler *handler = [[VNImageRequestHandler alloc]
                initWithCGImage:(__bridge CGImageRef)image options:@{}];
            if (![handler performRequests:@[request] error:nil] || !isFrontmost(pid) ||
                request.results.count > 64) return false;
            if (hasMaskedField) {
                // A null text pointer represents pixel-confirmed field geometry.
                visitor(context, NULL, 0, 1.0, CGRectGetMidX(masked), CGRectGetMidY(masked),
                        masked.size.width, masked.size.height);
            }
            for (VNRecognizedTextObservation *observation in request.results) {
                CGRect box = observation.boundingBox;
                if (hasMaskedField && CGRectContainsRect(
                    CGRectInset(masked, -0.002, -0.002), box)) continue;
                VNRecognizedText *candidate = [observation topCandidates:1].firstObject;
                NSString *string = candidate.string;
                const char *utf8 = string.UTF8String;
                size_t length = [string lengthOfBytesUsingEncoding:NSUTF8StringEncoding];
                if (!utf8 || !length || length > 512) return false;
                visitor(context, utf8, length, candidate.confidence, CGRectGetMidX(box),
                        CGRectGetMidY(box), box.size.width, box.size.height);
            }
            return isFrontmost(pid);
        }
        return false;
    }
}
