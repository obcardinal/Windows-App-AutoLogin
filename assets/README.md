# Application icons

- `icon.png` is the original user-provided `windows-app-autologin-logo.png`, copied without alteration. It supplies the application bundle, Windows executable/window/tray icons, and About.
- `icon_tray.svg` is the simplified monochrome menu-bar mark: an arrow entering a rounded window. Its negative space is transparent.
- `icon_tray.png` is the 128×128 raster of that SVG. macOS displays it at 18 points as a template, automatically adapting it to light and dark menu bars.

Regenerate the menu-bar PNG on macOS with `swift script/render_tray_icon.swift` from the repository root. The packaging scripts generate platform icon sizes from `icon.png`.
