#include "macos_masked_field.h"
#include <math.h>
#include <stdint.h>
#include <stdlib.h>

typedef struct { uint8_t r, g, b, a; } Pixel;
typedef struct { const Pixel *pixels; int width, height; } Frame;
typedef struct { int left, top, right, bottom, count; } Ink;

static const Pixel *at(Frame frame, int x, int y) {
    return &frame.pixels[(size_t)y * frame.width + x];
}

// Windows' focused password editor has a saturated blue underline beneath a
// dark fill. Bright neutral glyphs carry the mask, reveal icon and submit arrow.
static bool blue(Pixel p) {
    return p.b > 116 && p.g > p.r + 26 && p.b > p.g + 26;
}

static bool hasUnderline(Frame frame, int x, int y) {
    Pixel line = *at(frame, x, y);
    if (!blue(line)) return false;
    // Blue wallpaper can touch the accent and make the raw blue run extend far
    // outside the field. Keep the pixels whose upper neighbor is the dark editor.
    Pixel above = *at(frame, x, y - 5);
    return above.r <= 107 && above.g <= 110 && above.b <= 123 &&
           (line.b - above.b > 37 || line.g - above.g > 34);
}

static bool ink(Pixel p) {
    int min = fmin(p.r, fmin(p.g, p.b));
    int max = fmax(p.r, fmax(p.g, p.b));
    return min > 109 && max - min < 65;
}

static Ink measure(Frame frame, int left, int right, int top, int bottom) {
    Ink glyph = {right, bottom, left, top, 0};
    for (int y = top; y <= bottom; y++) {
        for (int x = left; x <= right; x++) {
            if (!ink(*at(frame, x, y))) continue;
            if (x < glyph.left) glyph.left = x;
            if (x > glyph.right) glyph.right = x;
            if (y < glyph.top) glyph.top = y;
            if (y > glyph.bottom) glyph.bottom = y;
            glyph.count++;
        }
    }
    return glyph;
}

static bool submitArrow(Frame frame, Ink arrow, int mid, int height) {
    if (!arrow.count) return false;
    int w = arrow.right - arrow.left + 1, h = arrow.bottom - arrow.top + 1;
    if (w < height * .23 || w > height * .49 || h < height * .18 || h > height * .48 ||
        abs((arrow.bottom + arrow.top) / 2 - mid) > height * .10 + 1) return false;
    // A solid horizontal shaft, with two diagonal wings rooted on its right.
    int thickest = 0, upper = 0, lower = 0;
    for (int y = arrow.top; y <= arrow.bottom; y++) {
        int run = 0, maximum = 0;
        for (int x = arrow.left; x <= arrow.right; x++) {
            if (ink(*at(frame, x, y))) {
                if (++run > maximum) maximum = run;
                if (x < arrow.left + w * .36 && abs(y - mid) > h * .26 + 1) return false;
                if (x > arrow.left + w * .36 && x < arrow.left + w * .85) {
                    if (y <= arrow.top + h * .24) upper++;
                    if (y >= arrow.bottom - h * .24) lower++;
                }
            } else run = 0;
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
        Ink mark = measure(frame, begin, x - 1, top, bottom);
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

static bool editor(Frame frame, int left, int right, int y, CGRect *result) {
    int w = right - left + 1;
    if (w < 90 || w < frame.width * .08 || w > frame.width * .85 ||
        abs((left + right) / 2 - frame.width / 2) > frame.width * .10) return false;
    // The stock Windows control is roughly 280 × 34 logical pixels at each DPI.
    int h = (int)lround(w * .118), top = y - h, mid = y - (int)lround(h * .48);
    if (top < 0 || mid + h / 3 >= frame.height) return false;
    for (int i = 0; i < 3; i++) {
        int x = left + (int)(w * (.36 + .16 * i));
        Pixel background = *at(frame, x, top + (int)(h * .17));
        Pixel base = *at(frame, x, y - 2);
        if (background.r > 93 || background.g > 98 || background.b > 108 ||
            base.r > 110 || base.g > 110 || base.b > 122) return false;
    }
    int glyphTop = mid - (int)(h * .30), glyphBottom = mid + (int)(h * .30);
    Ink arrow = measure(frame, left + (int)(w * .894), left + (int)(w * .982), glyphTop, glyphBottom);
    Ink eye = measure(frame, left + (int)(w * .774), left + (int)(w * .887), glyphTop, glyphBottom);
    if (!submitArrow(frame, arrow, mid, h) || !revealIcon(frame, eye, mid, h) ||
        !maskDots(frame, left, w, mid, h)) return false;
    *result = CGRectMake((double)left / frame.width, 1.0 - (double)(y + 1) / frame.height,
                         (double)w / frame.width, (double)h / frame.height);
    return true;
}

static bool findEditor(Frame frame, CGRect *result) {
    bool found = false;
    int lastY = -frame.height;
    for (int y = (int)(frame.height * .24); y < frame.height * .91; y++) {
        for (int x = 0; x < frame.width;) {
            int left = x;
            while (x < frame.width && hasUnderline(frame, x, y)) x++;
            if (x == left) { x++; continue; }
            CGRect candidate;
            if (!editor(frame, left, x - 1, y, &candidate)) continue;
            if (found && (y - lastY > 5 || fabs(candidate.origin.x - result->origin.x) > .025))
                return false;
            if (!found) *result = candidate;
            found = true;
            lastY = y;
        }
    }
    return found;
}

bool waal_masked_field(CGImageRef image, CGRect *normalizedField) {
    if (!image || !normalizedField) return false;
    size_t sourceWidth = CGImageGetWidth(image), sourceHeight = CGImageGetHeight(image);
    if (sourceWidth < 160 || sourceHeight < 85 || sourceWidth > 16384 || sourceHeight > 16384) return false;
    // Preserve the capture's native pixel grid. A second resize below the
    // ScreenCaptureKit limit can erase a one-pixel eye or submit-arrow stroke.
    double scale = fmin(1., fmin(1920. / sourceWidth, 1440. / sourceHeight));
    int w = (int)lround(sourceWidth * scale), h = (int)lround(sourceHeight * scale);
    CGColorSpaceRef space = CGColorSpaceCreateWithName(kCGColorSpaceSRGB);
    if (!space) return false;
    CGContextRef bitmap = CGBitmapContextCreate(NULL, w, h, 8, (size_t)w * sizeof(Pixel), space,
                                              kCGImageAlphaNoneSkipLast | kCGBitmapByteOrder32Big);
    CGColorSpaceRelease(space);
    if (!bitmap) return false;
    CGContextSetInterpolationQuality(bitmap, kCGInterpolationMedium);
    CGContextDrawImage(bitmap, CGRectMake(0, 0, w, h), image);
    Frame frame = {CGBitmapContextGetData(bitmap), w, h};
    CGRect result = CGRectZero;
    bool matched = frame.pixels && findEditor(frame, &result);
    CGContextRelease(bitmap);
    if (matched) *normalizedField = result;
    return matched;
}
