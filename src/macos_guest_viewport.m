#include "macos_guest_viewport.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

typedef struct { uint8_t r, g, b, a; } Pixel;
typedef struct { int first, last; } Padding;
typedef struct { CGImageRef image; CGColorSpaceRef space; } View;

static CGContextRef readPixels(View view, int x, int y, int w, int h) {
    CGImageRef part = CGImageCreateWithImageInRect(view.image, CGRectMake(x, y, w, h));
    if (!part) return NULL;
    CGContextRef bitmap = CGBitmapContextCreate(NULL, w, h, 8, (size_t)w * sizeof(Pixel),
        view.space, kCGImageAlphaPremultipliedLast | kCGBitmapByteOrder32Big);
    if (bitmap) {
        CGContextSetBlendMode(bitmap, kCGBlendModeCopy);
        CGContextSetInterpolationQuality(bitmap, kCGInterpolationNone);
        CGContextDrawImage(bitmap, CGRectMake(0, 0, w, h), part);
    }
    CGImageRelease(part);
    return bitmap;
}

static bool black(Pixel p) {
    return p.r == 0 && p.g == 0 && p.b == 0 && p.a == 255;
}

// Sample two center lines first. A normal desktop only requires width+height
// pixels. Take exact first/last counts independently for odd-sized windows.
static Padding samplePadding(View view, int w, int h, bool horizontal) {
    int n = horizontal ? w : h;
    CGContextRef bitmap = horizontal ? readPixels(view, 0, h / 2, w, 1)
                                      : readPixels(view, w / 2, 0, 1, h);
    Padding result = {0};
    if (!bitmap) return result;
    const Pixel *p = CGBitmapContextGetData(bitmap);
    if (p && black(p[0]) && black(p[n - 1])) {
        while (result.first < n && black(p[result.first])) result.first++;
        while (result.last < n && black(p[n - 1 - result.last])) result.last++;
    }
    CGContextRelease(bitmap);
    if (result.first < 4 || result.last < 4 || abs(result.first - result.last) > 1 ||
        result.first + result.last > n * .80) return (Padding){0};
    return result;
}

// Verify every pixel of a proposed bar. Scratch storage is at most 512 KiB.
static bool emptyBar(View view, int x, int y, int width, int height) {
    int rows = (128 * 1024) / width;
    for (int dy = 0; dy < height; dy += rows) {
        int count = height - dy < rows ? height - dy : rows;
        CGContextRef bitmap = readPixels(view, x, y + dy, width, count);
        if (!bitmap) return false;
        const Pixel *p = CGBitmapContextGetData(bitmap);
        bool empty = p != NULL;
        for (int i = 0; empty && i < width * count; i++) empty = black(p[i]);
        CGContextRelease(bitmap);
        if (!empty) return false;
    }
    return true;
}

// A sharp transition along most of the inner edge distinguishes a rectangular
// desktop from isolated glyphs on a nearly black or uniformly black background.
static bool hasDesktopEdge(View view, int x, int y, int w, int h) {
    CGContextRef bitmap = readPixels(view, x, y, w, h);
    if (!bitmap) return false;
    const Pixel *p = CGBitmapContextGetData(bitmap);
    int bright = 0, count = w * h;
    for (int i = 0; p && i < count; i++) {
        if (p[i].a == 255 && (p[i].r >= 16 || p[i].g >= 16 || p[i].b >= 16)) bright++;
    }
    CGContextRelease(bitmap);
    return bright >= count * .75;
}

CGRect waal_guest_content_rect(CGImageRef viewport) {
    if (!viewport) return CGRectNull;
    size_t width = CGImageGetWidth(viewport), height = CGImageGetHeight(viewport);
    CGRect full = CGRectMake(0, 0, width, height);
    if (width < 160 || height < 85 || width > 16384 || height > 16384 ||
        width * height > 8192u * 4320u) return full;
    View view = {viewport, CGColorSpaceCreateWithName(kCGColorSpaceSRGB)};
    if (!view.space) return full;
    int w = (int)width, h = (int)height;
    Padding x = samplePadding(view, w, h, true), y = samplePadding(view, w, h, false);
    int gw = w - x.first - x.last, gh = h - y.first - y.last;
    bool hasFrame = gw >= 160 && gh >= 85 && (x.first || y.first) &&
        (!x.first || (hasDesktopEdge(view, x.first, y.first, 1, gh) &&
                      hasDesktopEdge(view, w - x.last - 1, y.first, 1, gh))) &&
        (!y.first || (hasDesktopEdge(view, x.first, y.first, gw, 1) &&
                      hasDesktopEdge(view, x.first, h - y.last - 1, gw, 1)));
    CGRect result = full;
    if (hasFrame) {
        // An overlay on an otherwise letterboxed frame makes both possible
        // coordinate systems unsafe for locating the account tiles.
        bool clear = (!x.first || (emptyBar(view, 0, 0, x.first, h) &&
                                   emptyBar(view, w - x.last, 0, x.last, h))) &&
                     (!y.first || (emptyBar(view, x.first, 0, gw, y.first) &&
                                   emptyBar(view, x.first, h - y.last, gw, y.last)));
        result = clear ? CGRectMake(x.first, y.first, gw, gh) : CGRectNull;
    }
    CGColorSpaceRelease(view.space);
    return result;
}
