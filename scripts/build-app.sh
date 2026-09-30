#!/bin/zsh
set -euo pipefail
project_dir="${0:A:h:h}"
swift "$project_dir/scripts/generate-icon.swift" "$project_dir/assets/rvi-pktap-correlator-logo.png" "$project_dir/assets/AppIcon-1024.png"
mkdir -p "$project_dir/assets/AppIcon.iconset"
for icon_size in 16 32 128 256 512; do
    sips -z "$icon_size" "$icon_size" "$project_dir/assets/AppIcon-1024.png" --out "$project_dir/assets/AppIcon.iconset/icon_${icon_size}x${icon_size}.png" >/dev/null
    retina_size=$((icon_size * 2))
    sips -z "$retina_size" "$retina_size" "$project_dir/assets/AppIcon-1024.png" --out "$project_dir/assets/AppIcon.iconset/icon_${icon_size}x${icon_size}@2x.png" >/dev/null
done
iconutil -c icns "$project_dir/assets/AppIcon.iconset" -o "$project_dir/assets/AppIcon.icns"
cp "$project_dir/assets/rvi-pktap-correlator-logo.png" "$project_dir/Sources/CorrelatorApp/BrandLogo.png"
swift build --package-path "$project_dir" -c release
product_dir="$(swift build --package-path "$project_dir" -c release --show-bin-path)"
app_dir="$project_dir/dist/RVI + PKTAP Correlator.app"
mkdir -p "$app_dir/Contents/MacOS" "$app_dir/Contents/Resources"
cp "$product_dir/RVICorrelator" "$app_dir/Contents/MacOS/RVICorrelator"
cp "$product_dir/RVICaptureHelper" "$app_dir/Contents/MacOS/RVICaptureHelper"
cp -R "$product_dir/RVICorrelator_CorrelatorApp.bundle" "$app_dir/Contents/Resources/"
cp "$project_dir/assets/AppIcon.icns" "$app_dir/Contents/Resources/AppIcon.icns"
cat > "$app_dir/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleDevelopmentRegion</key><string>en</string>
<key>CFBundleExecutable</key><string>RVICorrelator</string>
<key>CFBundleIconFile</key><string>AppIcon</string>
<key>CFBundleIdentifier</key><string>com.local.rvisentinel.correlator</string>
<key>CFBundleInfoDictionaryVersion</key><string>6.0</string>
<key>CFBundleName</key><string>RVI + PKTAP Correlator</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleShortVersionString</key><string>0.1.0</string>
<key>CFBundleVersion</key><string>1</string>
<key>LSMinimumSystemVersion</key><string>14.0</string>
<key>NSHighResolutionCapable</key><true/>
</dict></plist>
PLIST
printf '%s\n' "$app_dir"
