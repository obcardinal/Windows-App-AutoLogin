# Application icons

- `icon.png` is the original user-provided `windows-app-autologin-logo.png`, copied without alteration. It supplies the application bundle, Windows executable/window/tray icons, and About.
- `icon_tray.svg` traces the landscape card and rounded arrow from `icon.png` as a single-color menu-bar symbol. The stroke sits outside the card and opens where the arrow enters.
- `icon_tray.png` is the 128×94 raster of that SVG. Its visible outline is about 14.5 points high within the 18-point macOS template. The template adapts to light and dark menu bars.

Regenerate the menu-bar PNG on macOS with `swift script/render_tray_icon.swift` from the repository root. The packaging scripts generate platform icon sizes from `icon.png`.
