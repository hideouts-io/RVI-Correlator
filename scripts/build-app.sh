#!/bin/zsh
set -euo pipefail
project_dir="${0:A:h:h}"
cp "$project_dir/assets/branding-v2/in-app/brand-logo.png" "$project_dir/Sources/CorrelatorApp/BrandLogo.png"
swift build --package-path "$project_dir" -c release
product_dir="$(swift build --package-path "$project_dir" -c release --show-bin-path)"
app_dir="$project_dir/dist/RVI + PKTAP Correlator.app"
mkdir -p "$app_dir/Contents/MacOS" "$app_dir/Contents/Resources"
cp "$product_dir/RVICorrelator" "$app_dir/Contents/MacOS/RVICorrelator"
cp "$product_dir/RVICaptureHelper" "$app_dir/Contents/MacOS/RVICaptureHelper"
cp -R "$product_dir/RVICorrelator_CorrelatorApp.bundle" "$app_dir/Contents/Resources/"
cp "$project_dir/assets/branding-v2/icons/macos/RVI-Correlator.icns" "$app_dir/Contents/Resources/AppIcon.icns"
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
