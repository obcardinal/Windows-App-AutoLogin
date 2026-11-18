#include "macos_masked_field.h"
#include <math.h>
#include <stdint.h>
#include <stdlib.h>

typedef struct { uint8_t r, g, b, a; } Pixel;
typedef struct { const Pixel *pixels; int width, height; } Frame;
typedef struct { int left, top, right, bottom, count, brightest; } Ink;

static const Pixel *at(Frame frame, int x, int y) {
    return &frame.pixels[(size_t)y * frame.width + x];
}

// Windows' focused password editor has a saturated blue underline beneath a
// dark fill. Bright neutral glyphs carry the mask, reveal icon and submit arrow.
static bool blue(Pixel p) {
    return p.b > 116 && p.g > p.r + 26 && p.b > p.g + 26;
}

static bool darkAboveLine(Pixel line, Pixel above) {
    return above.r <= 107 && above.g <= 110 && above.b <= 123 &&
           (line.b - above.b > 37 || line.g - above.g > 34);
}

static bool hasUnderline(Frame frame, int x, int y) {
    Pixel line = *at(frame, x, y);
    if (!blue(line)) return false;
    // Blue wallpaper can touch the accent. Require a dark editor pixel
    // immediately above a thin underline, or above a thicker scaled one.
    return darkAboveLine(line, *at(frame, x, y - 2)) ||
           darkAboveLine(line, *at(frame, x, y - 5));
}

static int neutralBrightness(Pixel p) {
    int min = fmin(p.r, fmin(p.g, p.b));
    int max = fmax(p.r, fmax(p.g, p.b));
    return max - min < 65 ? min : 0;
}

enum { brightInk = 109 };

static bool ink(Pixel p) { return neutralBrightness(p) > brightInk; }

static Ink measure(Frame frame, int left, int right, int top, int bottom, int threshold) {
    Ink glyph = {right, bottom, left, top, 0, 0};
    for (int y = top; y <= bottom; y++) {
        for (int x = left; x <= right; x++) {
            int brightness = neutralBrightness(*at(frame, x, y));
            if (brightness <= threshold) continue;
            if (brightness > glyph.brightest) glyph.brightest = brightness;
            if (x < glyph.left) glyph.left = x;
            if (x > glyph.right) glyph.right = x;
            if (y < glyph.top) glyph.top = y;
            if (y > glyph.bottom) glyph.bottom = y;
            glyph.count++;
        }
    }
    return glyph;
}

static bool submitArrow(Frame frame, Ink arrow, int mid, int height, int threshold, int background) {
    if (!arrow.count) return false;
    int w = arrow.right - arrow.left + 1, h = arrow.bottom - arrow.top + 1;
    if (w < height * .23 || w > height * .49 || h < height * .18 || h > height * .48 ||
        abs((arrow.bottom + arrow.top) / 2 - mid) > height * .10 + 1) return false;
    // A solid horizontal shaft, with two diagonal wings rooted on its right.
    int thickest = 0, upper = 0, lower = 0;
    for (int y = arrow.top; y <= arrow.bottom; y++) {
        int run = 0, maximum = 0;
        for (int x = arrow.left; x <= arrow.right; x++) {
            int brightness = neutralBrightness(*at(frame, x, y));
            bool lit = brightness > threshold;
            bool shaft = lit;
            // A subpixel horizontal stroke can split its coverage across two
            // adjacent rows. Sum their contrast only at the expected shaft.
            if (!lit && background >= 0 && brightness > background && abs(y - mid) <= 1) {
                int above = y > arrow.top ? neutralBrightness(*at(frame, x, y - 1)) : 0;
                int below = y < arrow.bottom ? neutralBrightness(*at(frame, x, y + 1)) : 0;
                shaft = brightness + fmax(above, below) - background > threshold;
            }
            if (shaft) {
                if (++run > maximum) maximum = run;
            } else run = 0;
            if (lit) {
                if (x < arrow.left + w * .36 && abs(y - mid) > h * .26 + 1) return false;
                if (x > arrow.left + w * .36 && x < arrow.left + w * .85) {
                    if (y <= arrow.top + h * .24) upper++;
                    if (y >= arrow.bottom - h * .24) lower++;
                }
            }
        }
        if (abs(y - mid) <= h * .25 + 1 && maximum > thickest) thickest = maximum;
    }
    return thickest >= w * .70 && upper > 0 && lower > 0;
}

static bool revealIcon(Frame frame, Ink eye, int mid, int height) {
    if (!eye.count) return false;
    int w = eye.right - eye.left + 1, h = eye.bottom - eye.top + 1;
    if (w < height * .23 || w > height * .52 || h < height * .15 || h > height * .43 ||
        w < h * 1.05 || abs((eye.top + eye.bottom) / 2 - mid) > height * .10 + 1)
        return false;
    int maxGroups = 0;
    for (int y = eye.top; y <= eye.bottom; y++) {
        int groups = 0;
        bool previous = false;
        for (int x = eye.left; x <= eye.right; x++) {
            bool current = ink(*at(frame, x, y));
            if (current && !previous) groups++;
            previous = current;
        }
        if (groups > maxGroups) maxGroups = groups;
    }
    // Outline and pupil must be separate on at least one row.
    return maxGroups >= 3 && eye.count < w * h * .75;
}

static bool maskDots(Frame frame, int left, int width, int mid, int height) {
    int start = left + (int)(width * .012), end = left + (int)(width * .765);
    int top = mid - (int)(height * .32), bottom = mid + (int)(height * .32);
    int count = 0, firstWidth = 0, previousCenter = 0, spacing = 0;
    bool caret = false;
    for (int x = start; x <= end;) {
        int begin = x;
        while (x <= end) {
            bool lit = false;
            for (int y = top; y <= bottom && !lit; y++) lit = ink(*at(frame, x, y));
            if (!lit) break;
            x++;
        }
        if (x == begin) { x++; continue; }
        Ink mark = measure(frame, begin, x - 1, top, bottom, brightInk);
        int w = x - begin, h = mark.bottom - mark.top + 1, center = (begin + x - 1) / 2;
        if (w <= height * .065 + 1 && h >= height * .38) {
            if (caret) return false;
            caret = true;
            continue;
        }
        int cy = (mark.top + mark.bottom) / 2;
        if (w < height * .105 || w > height * .27 || h < height * .105 || h > height * .27 ||
            w < h * .69 || h < w * .69 || abs((mark.top + mark.bottom) / 2 - mid) > height * .10 + 1 ||
            mark.count < w * h * .48 || mark.count > w * h * .95 + 1 ||
            !ink(*at(frame, center, cy))) return false;
        if (!count) {
            if (center - left < width * .020 || center - left > width * .073) return false;
            firstWidth = w;
        } else {
            int gap = center - previousCenter;
            if (abs(w - firstWidth) > height * .042 + 1 || gap < height * .16 || gap > height * .36 ||
                (spacing && abs(spacing - gap) > height * .050 + 1)) return false;
            if (!spacing) spacing = gap;
        }
        previousCenter = center;
        count++;
    }
    return count > 0;
}

static WaalFieldKind editor(Frame frame, int left, int right, int y, CGRect *result) {
    int w = right - left + 1;
    if (w < 90 || w > frame.width * .85 ||
        abs((left + right) / 2 - frame.width / 2) > frame.width * .10) return WaalFieldNone;
    // The stock Windows control is roughly 280 × 34 logical pixels at each DPI.
    int h = (int)lround(w * .118), top = y - h, mid = y - (int)lround(h * .48);
    if (top < 0) return WaalFieldNone;
    for (int i = 0; i < 3; i++) {
        int x = left + (int)(w * (.36 + .16 * i));
        Pixel background = *at(frame, x, top + (int)(h * .17));
        Pixel base = *at(frame, x, y - 2);
        if (background.r > 93 || background.g > 98 || background.b > 108 ||
            base.r > 110 || base.g > 110 || base.b > 122) return WaalFieldNone;
    }
    int glyphTop = mid - (int)(h * .30), glyphBottom = mid + (int)(h * .30);
    int arrowLeft = left + (int)(w * .894), arrowRight = left + (int)(w * .982);
    Ink arrow = measure(frame, arrowLeft, arrowRight, glyphTop, glyphBottom, brightInk);
    if (!submitArrow(frame, arrow, mid, h, brightInk, -1)) {
        // On small controls the subpixel shaft blends into the dark fill.
        // Require a bright core, then check the same shaft and wings with
        // a threshold one third of the way from the fill to that core.
        if (h > 30 || !arrow.count) return WaalFieldNone;
        Pixel fill = *at(frame, arrowLeft, glyphTop);
        int base = fmin(fill.r, fmin(fill.g, fill.b));
        if (arrow.brightest - base < 64) return WaalFieldNone;
        int threshold = base + (arrow.brightest - base) / 3;
        if (threshold >= brightInk) return WaalFieldNone;
        arrow = measure(frame, arrowLeft, arrowRight, glyphTop, glyphBottom, threshold);
        if (!submitArrow(frame, arrow, mid, h, threshold, base)) return WaalFieldNone;
    }
    *result = CGRectMake(left, y + 1 - h, w, h);
    Ink eye = measure(frame, left + (int)(w * .774), left + (int)(w * .887), glyphTop, glyphBottom, brightInk);
    return revealIcon(frame, eye, mid, h) && maskDots(frame, left, w, mid, h)
        ? WaalFieldMasked : WaalFieldPlaceholderCandidate;
}

typedef struct {
    WaalFieldKind kind;
    CGRect bounds; // Top-left origin in the full source image.
    int lastY;
} Match;

static void scanRows(Frame frame, int firstY, int sourceTop, Match *match) {
    // Every eligible underline intersects this band because its midpoint
    // must be within 10% of the window center. Measure each full run.
    int firstX = (int)(frame.width * .40) - 1, lastX = (int)(frame.width * .60) + 1;
    for (int y = firstY; y < frame.height; y++) {
        for (int x = firstX; x <= lastX;) {
            if (!hasUnderline(frame, x, y)) { x++; continue; }
            int left = x++;
            if (left == firstX) {
                while (left > 0 && hasUnderline(frame, left - 1, y)) left--;
            }
            while (x < frame.width && hasUnderline(frame, x, y)) x++;
            CGRect box;
            WaalFieldKind kind = editor(frame, left, x - 1, y, &box);
            if (kind == WaalFieldNone) continue;
            box.origin.y += sourceTop;
            int sourceY = sourceTop + y;
            if (match->kind != WaalFieldNone) {
                // Adjacent rows on rounded corners can have slightly different
                // lengths. Two disjoint runs are distinct even on an ultrawide.
                CGRect overlap = CGRectIntersection(match->bounds, box);
                if (sourceY - match->lastY > 5 || CGRectIsNull(overlap) ||
                    overlap.size.width < .50 * fmax(box.size.width, match->bounds.size.width)) {
                    match->kind = WaalFieldAmbiguous;
                    return;
                }
            }
            if (match->kind == WaalFieldNone || (match->kind != WaalFieldMasked && kind == WaalFieldMasked) ||
                (match->kind == kind && box.size.width > match->bounds.size.width)) {
                match->bounds = box;
                match->kind = kind;
            }
            match->lastY = sourceY;
        }
    }
}

WaalFieldKind waal_password_field(CGImageRef image, CGRect *normalizedField) {
    if (!image || !normalizedField) return WaalFieldUnavailable;
    size_t sourceWidth = CGImageGetWidth(image), sourceHeight = CGImageGetHeight(image);
    if (sourceWidth < 160 || sourceHeight < 85 || sourceWidth > 16384 || sourceHeight > 16384 ||
        sourceWidth * sourceHeight > 8192u * 4320u) return WaalFieldUnavailable;
    int w = (int)sourceWidth, h = (int)sourceHeight;
    CGColorSpaceRef space = CGColorSpaceCreateWithName(kCGColorSpaceSRGB);
    if (!space) return WaalFieldUnavailable;
    // Scan the original pixel grid. Limit temporary storage by drawing strips
    // with enough preceding rows for the tallest eligible editor at a boundary.
    int end = (int)ceil(h * .91), lookback = (int)ceil(w * .85 * .118);
    int step = (4 * 1024 * 1024) / w;
    Match match = {0};
    for (int start = (int)(h * .24); start < end; start += step) {
        int top = (int)fmax(0, start - lookback), bottom = (int)fmin(end, start + step);
        CGImageRef strip = CGImageCreateWithImageInRect(image, CGRectMake(0, top, w, bottom - top));
        CGContextRef bitmap = strip ? CGBitmapContextCreate(NULL, w, bottom - top, 8,
            (size_t)w * sizeof(Pixel), space, kCGImageAlphaNoneSkipLast | kCGBitmapByteOrder32Big) : NULL;
        Pixel *pixels = bitmap ? CGBitmapContextGetData(bitmap) : NULL;
        if (pixels) {
            CGContextDrawImage(bitmap, CGRectMake(0, 0, w, bottom - top), strip);
            Frame frame = {pixels, w, bottom - top};
            scanRows(frame, start - top, top, &match);
        } else {
            match.kind = WaalFieldUnavailable;
        }
        if (bitmap) CGContextRelease(bitmap);
        if (strip) CGImageRelease(strip);
        if (match.kind == WaalFieldAmbiguous || match.kind == WaalFieldUnavailable) break;
    }
    CGColorSpaceRelease(space);
    if (match.kind == WaalFieldMasked || match.kind == WaalFieldPlaceholderCandidate) {
        CGRect box = match.bounds;
        *normalizedField = CGRectMake(box.origin.x / w, 1.0 - CGRectGetMaxY(box) / h,
                                      box.size.width / w, box.size.height / h);
    }
    return match.kind;
}

// A small desktop may place the sign-in controls to one side to leave room for
// user tiles. Measure the unfocused control's outline around the native word
// before using that offset. Edges are read from original guest pixels.
static int edgeContrast(Pixel a, Pixel b) {
    return abs(a.r - b.r) + abs(a.g - b.g) + abs(a.b - b.b);
}

static bool continuousEdge(Frame frame, bool vertical, int edge, int start, int end, int span) {
    int hits = 0, samples = 0, missed = 0;
    int step = (int)fmax(1, (end - start) / 48);
    for (int pos = start; pos <= end; pos += step) {
        Pixel a = *at(frame, vertical ? edge + span - 1 : pos, vertical ? pos : edge + span - 1);
        Pixel b = *at(frame, vertical ? edge - span : pos, vertical ? pos : edge - span);
        if (edgeContrast(a, b) >= 18) {
            hits++;
            missed = 0;
        } else if (++missed > 5) return false;
        samples++;
    }
    return hits >= samples * .80;
}

// Find one border in its word-relative band. A parallel inner border is
// common. Reject separate outlines instead of selecting either rectangle.
static int findEdge(Frame frame, bool vertical, int first, int last, int start, int end, int thickness, bool preferLast) {
    int firstHit = 0, lastHit = 0;
    for (int edge = first; edge <= last; edge++) {
        if (!continuousEdge(frame, vertical, edge, start, end, 1)) continue;
        if (!firstHit) firstHit = edge;
        if (edge - firstHit > thickness) return 0;
        lastHit = edge;
    }
    return preferLast ? lastHit : firstHit;
}

// Compression can soften a side into the wallpaper. Locate both corners at
// the ends of the independent horizontal borders and verify the vertical
// transition between them at the same position with a wider pixel baseline.
static int horizontalEnd(Frame frame, int row, int start, int last, int step) {
    for (int x = start; x + 2 * step <= last; x += step) {
        int hits = 0;
        for (int i = 0; i < 2 * step; i++) {
            if (edgeContrast(*at(frame, x + i, row), *at(frame, x + i, row - 1)) >= 18) hits++;
        }
        if (hits < step / 2) return x;
    }
    return 0;
}

CGRect waal_neutral_password_field(CGImageRef image, CGRect verifiedPassword) {
    if (!image || CGRectIsEmpty(verifiedPassword) ||
        !CGRectContainsRect(CGRectMake(0, 0, 1, 1), verifiedPassword)) return CGRectNull;
    size_t w = CGImageGetWidth(image), h = CGImageGetHeight(image);
    if (w < 160 || h < 85 || w > 16384 || h > 16384 || w * h > 8192u * 4320u ||
        verifiedPassword.size.width < .045 || verifiedPassword.size.width > .20) return CGRectNull;
    double textX = verifiedPassword.origin.x * w, textW = verifiedPassword.size.width * w;
    double mid = (1.0 - CGRectGetMidY(verifiedPassword)) * h, textH = verifiedPassword.size.height * h;
    if (textH < 5 || textH > 128 || textW < 3 * textH || textW > 10 * textH) return CGRectNull;
    int y0 = (int)floor(mid - 2.4 * textH) - 1, y1 = (int)ceil(mid + 2.4 * textH) + 1;
    int firstLeft = (int)floor(textX - .29 * textW), lastRight = (int)ceil(textX + 6.1 * textW);
    if (y0 < 0 || y1 >= (int)h || firstLeft < 1) return CGRectNull;
    lastRight = (int)fmin(lastRight, w - 1);
    CGImageRef strip = CGImageCreateWithImageInRect(image, CGRectMake(0, y0, w, y1 - y0 + 1));
    CGColorSpaceRef space = CGColorSpaceCreateWithName(kCGColorSpaceSRGB);
    CGContextRef ctx = strip && space ? CGBitmapContextCreate(NULL, w, y1 - y0 + 1, 8,
        w * sizeof(Pixel), space, kCGImageAlphaNoneSkipLast | kCGBitmapByteOrder32Big) : NULL;
    if (space) CGColorSpaceRelease(space);
    CGRect result = CGRectNull;
    if (ctx && CGBitmapContextGetData(ctx)) {
        CGContextDrawImage(ctx, CGRectMake(0, 0, w, y1 - y0 + 1), strip);
        Frame frame = {CGBitmapContextGetData(ctx), (int)w, y1 - y0 + 1};
        mid -= y0;
        int thickness = (int)fmax(3, .32 * textH);
        int top = findEdge(frame, false, 1, (int)(mid - .77 * textH), (int)textX,
                           (int)fmin(lastRight, textX + 3.5 * textW), thickness, true);
        int bottom = findEdge(frame, false, (int)ceil(mid + .77 * textH), frame.height - 1,
                              (int)textX, (int)fmin(lastRight, textX + 3.5 * textW), thickness, false);
        if (top && bottom && fabs((top + bottom) * .5 - mid) <= textH * .34) {
            int inset = (int)ceil((bottom - top) * .20);
            int left = findEdge(frame, true, firstLeft, (int)(textX - .025 * textW),
                                top + inset, bottom - inset, thickness, false);
            int right = findEdge(frame, true, (int)ceil(textX + 3.7 * textW), lastRight,
                                 top + inset, bottom - inset, thickness, false);
            if (!right && left) {
                int step = (int)fmax(2, lround((bottom - top) * .07));
                int scan = (int)ceil(textX + 3.1 * textW);
                int upper = horizontalEnd(frame, top, scan, lastRight, step);
                int lower = horizontalEnd(frame, bottom, scan, lastRight, step);
                int side = (upper + lower) / 2, span = (int)fmax(2, lround((bottom - top) * .12));
                if (upper && lower && abs(upper - lower) <= 3 * step && side > span &&
                    side + span < frame.width && continuousEdge(frame, true, side,
                        (int)(mid - .65 * textH), (int)(mid + .65 * textH), span)) right = side;
            }
            double width = right - left, height = bottom - top;
            if (left && right && width >= 90 && width <= w * .85 && height >= .095 * width &&
                height <= .15 * width && fabs((left + right) * .5 / w - .5) <= .08 &&
                continuousEdge(frame, false, top, left + inset, right - inset, 1) &&
                continuousEdge(frame, false, bottom, left + inset, right - inset, 1)) {
                result = CGRectMake(left / (double)w, 1.0 - (y0 + bottom) / (double)h,
                                    width / w, height / h);
            }
        }
    }
    if (ctx) CGContextRelease(ctx);
    if (strip) CGImageRelease(strip);
    return result;
}
