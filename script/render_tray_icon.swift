import AppKit

// Render the source vector directly, preserving its transparent background.
let sourceURL = URL(fileURLWithPath: "assets/icon_tray.svg")
let outputURL = URL(fileURLWithPath: "assets/icon_tray.png")
guard let image = NSImage(contentsOf: sourceURL) else {
  fatalError("Could not load the menu-bar SVG")
}
let size = image.size
guard let bitmap = NSBitmapImageRep(
    bitmapDataPlanes: nil, pixelsWide: Int(size.width), pixelsHigh: Int(size.height),
    bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true,
    isPlanar: false, colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0
  ),
  let context = NSGraphicsContext(bitmapImageRep: bitmap)
else {
  fatalError("Could not prepare the menu-bar icon renderer")
}
NSGraphicsContext.saveGraphicsState()
NSGraphicsContext.current = context
let bounds = NSRect(origin: .zero, size: size)
NSColor.clear.setFill()
bounds.fill(using: .copy)
image.draw(in: bounds, from: .zero, operation: .sourceOver, fraction: 1)
context.flushGraphics()
NSGraphicsContext.restoreGraphicsState()
guard let data = bitmap.representation(using: .png, properties: [:]) else {
  fatalError("Could not encode the menu-bar icon")
}
try data.write(to: outputURL)
