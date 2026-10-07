# Aligned Evidence asset family

Selected identity: **01 · Aligned Evidence**, approved 2026-10-04. Three independent packet/log paths share a reference marker. The symbol represents aligned evidence, not established causation.

The production icon is an editable vector reconstruction of [concept 01](source/approved-concept-01.png). Its geometry is consistent across every export. The selected identity supplies the production app icon and sidebar, README header, GitHub social preview, and project-specific hideouts.io placements. Previous production artwork is preserved under `assets/branding-v1/`.

## Ready-to-use placements

- **App, Finder and Dock:** `icons/macos/RVI-Correlator.icns`, its ten-file iconset, and `in-app/brand-logo.png`.
- **Logo/wordmark:** transparent light/dark and genuine monochrome treatments under `logos/`.
- **GitHub:** `github/social-preview-1280x640.png`; solid background, under 1 MB. Upload through repository Settings → Social preview. `github/readme-banner.png` is a separate header illustration.
- **hideouts.io:** three responsive heroes, background-only artwork, a project-card cover, 1200×630 sharing image, PNG/WebP exports, browser favicon, full-bleed 180px touch icon and 192/512px bookmark icons. Project-specific favicons must not replace the website's global favicon.
- **Preview:** `presentation/asset-overview.png`. Promotional images are conceptual illustrations, not app screenshots or capture results.

## Editable sources and regeneration

| Input or captured preview | Pixels | Purpose |
| --- | ---: | --- |
| [Approved concept](source/approved-concept-01.png) | 1536×1024 | Selected design reference |
| [Wide background](source/hero-background-desktop.png) | 2172×724 | Original generated raster source |
| [Portrait background](source/hero-background-mobile.png) | 941×1672 | Original generated raster source |
| [Packaged app](screenshots/app-overview-synthetic.png) | 2582×1760 | Real synthetic-demo screenshot |

SVG siblings accompany the master icon, every logo, wordmark, hero, social image and review board. The symbol and typography are vector elements; generated hero backgrounds are embedded raster images. SVG text uses installed Helvetica Neue/Helvetica/Arial; no font files are redistributed. The two original generated backgrounds and exact built-in image generation prompts are in `source/`.

Run `node scripts/build-branding.mjs` from the project root. Export tools: Node, rsvg-convert and cwebp; macOS iconutil can verify the container; these are artwork-development tools, not runtime app dependencies. This command regenerates only this asset family.

## Use and limits

Keep the three paths, hollow nodes and reference spine intact. Do not stretch, recolor individual streams or add success/check symbols. Keep clear space of at least one node diameter around the standalone mark. Use the navy/turquoise mark on light backgrounds and ice/turquoise on dark backgrounds; use genuine one-color variants for printing. Palette: midnight `#111823`, ice `#F0F5FC`, turquoise `#59E0DC`.

No private captures, logs, identifiers or screenshots are included in generated promotional art. Original captures and clocks were not changed. Correlation remains experimental; temporal proximity does not prove causation, Mac process labels attribute Mac traffic, and RVI coverage remains limited. No App Store, iOS-native-app or verified-attribution claims are made.

Dimensions follow the [current GitHub upload guidance](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/customizing-your-repositorys-social-media-preview), [Apple's iconset specification](https://developer.apple.com/library/archive/documentation/Xcode/Reference/xcode_ref-Asset_Catalog_Format/IconSetType.html), and the existing hideouts.io responsive hero component. These are project-local original assets; no third-party project artwork or fonts are redistributed. The existing project license remains unchanged.

## Export inventory

PNG logo/wordmark/icon assets have alpha; full-bleed touch, hero and sharing artwork have opaque backgrounds. SVG files have the dimensions of their PNG siblings. ICNS contains 16/32/64/128/256/512/1024px representations with the ten standard filenames; ICO contains 16/32/48/64/128/256px PNG images. ICNS uses original PNG payloads to retain transparent-edge colors. The machine-readable inventory records SHA-256 hashes and byte sizes. A [real app screenshot](screenshots/app-overview-synthetic.png), 2582×1760, shows the branded packaged app with clearly labeled fabricated demonstration data; it is not a live-capture validation.

| File | Pixels | Placement |
| --- | ---: | --- |
| [source/app-icon-master.png](source/app-icon-master.png) | 1024×1024 | Editable macOS icon master; concept 01 production reconstruction |
| [logos/mark-on-light.png](logos/mark-on-light.png) | 1024×1024 | Transparent standalone observation mark |
| [logos/logo-on-light.png](logos/logo-on-light.png) | 720×240 | Transparent horizontal logo and full app name |
| [logos/wordmark-on-light.png](logos/wordmark-on-light.png) | 1050×112 | Transparent wordmark without symbol |
| [logos/mark-on-dark.png](logos/mark-on-dark.png) | 1024×1024 | Transparent standalone observation mark |
| [logos/logo-on-dark.png](logos/logo-on-dark.png) | 720×240 | Transparent horizontal logo and full app name |
| [logos/wordmark-on-dark.png](logos/wordmark-on-dark.png) | 1050×112 | Transparent wordmark without symbol |
| [logos/mark-mono-black.png](logos/mark-mono-black.png) | 1024×1024 | Transparent standalone observation mark |
| [logos/logo-mono-black.png](logos/logo-mono-black.png) | 720×240 | Transparent horizontal logo and full app name |
| [logos/wordmark-mono-black.png](logos/wordmark-mono-black.png) | 1050×112 | Transparent wordmark without symbol |
| [logos/mark-mono-white.png](logos/mark-mono-white.png) | 1024×1024 | Transparent standalone observation mark |
| [logos/logo-mono-white.png](logos/logo-mono-white.png) | 720×240 | Transparent horizontal logo and full app name |
| [logos/wordmark-mono-white.png](logos/wordmark-mono-white.png) | 1050×112 | Transparent wordmark without symbol |
| [icons/app-icon-light.png](icons/app-icon-light.png) | 1024×1024 | Light-surface alternate icon, matching concept proof |
| [in-app/brand-logo.png](in-app/brand-logo.png) | 1024×1024 | SwiftUI sidebar, welcome panel and runtime Dock image |
| [github/social-preview-1280x640.png](github/social-preview-1280x640.png) | 1280×640 | GitHub repository social preview upload |
| [website/social-sharing-1200x630.png](website/social-sharing-1200x630.png) | 1200×630 | hideouts.io Open Graph and link sharing |
| [website/hero-desktop.png](website/hero-desktop.png) | 2000×667 | Responsive wide hideouts.io app-page hero |
| [website/hero-tablet.png](website/hero-tablet.png) | 1536×1024 | Responsive tablet hideouts.io hero |
| [website/hero-mobile.png](website/hero-mobile.png) | 941×1672 | Portrait mobile hideouts.io app-page hero |
| [website/hero-background.png](website/hero-background.png) | 2000×667 | Background-only website artwork; no logo or claims |
| [website/project-card-1200x675.png](website/project-card-1200x675.png) | 1200×675 | Editorial project-card and gallery cover |
| [github/readme-banner.png](github/readme-banner.png) | 1600×480 | README or release page header; conceptual artwork |
| [icons/app-icon-16.png](icons/app-icon-16.png) | 16×16 | macOS app icon, Finder, Dock and small UI uses |
| [icons/app-icon-24.png](icons/app-icon-24.png) | 24×24 | macOS app icon, Finder, Dock and small UI uses |
| [icons/app-icon-32.png](icons/app-icon-32.png) | 32×32 | macOS app icon, Finder, Dock and small UI uses |
| [icons/app-icon-48.png](icons/app-icon-48.png) | 48×48 | macOS app icon, Finder, Dock and small UI uses |
| [icons/app-icon-64.png](icons/app-icon-64.png) | 64×64 | macOS app icon, Finder, Dock and small UI uses |
| [icons/app-icon-96.png](icons/app-icon-96.png) | 96×96 | macOS app icon, Finder, Dock and small UI uses |
| [icons/app-icon-128.png](icons/app-icon-128.png) | 128×128 | macOS app icon, Finder, Dock and small UI uses |
| [icons/app-icon-256.png](icons/app-icon-256.png) | 256×256 | macOS app icon, Finder, Dock and small UI uses |
| [icons/app-icon-512.png](icons/app-icon-512.png) | 512×512 | macOS app icon, Finder, Dock and small UI uses |
| [icons/app-icon-1024.png](icons/app-icon-1024.png) | 1024×1024 | macOS app icon, Finder, Dock and small UI uses |
| [icons/macos/RVI-Correlator.iconset/icon_16x16.png](icons/macos/RVI-Correlator.iconset/icon_16x16.png) | 16×16 | Apple macOS iconset representation |
| [icons/macos/RVI-Correlator.iconset/icon_16x16@2x.png](icons/macos/RVI-Correlator.iconset/icon_16x16@2x.png) | 32×32 | Apple macOS iconset representation |
| [icons/macos/RVI-Correlator.iconset/icon_32x32.png](icons/macos/RVI-Correlator.iconset/icon_32x32.png) | 32×32 | Apple macOS iconset representation |
| [icons/macos/RVI-Correlator.iconset/icon_32x32@2x.png](icons/macos/RVI-Correlator.iconset/icon_32x32@2x.png) | 64×64 | Apple macOS iconset representation |
| [icons/macos/RVI-Correlator.iconset/icon_128x128.png](icons/macos/RVI-Correlator.iconset/icon_128x128.png) | 128×128 | Apple macOS iconset representation |
| [icons/macos/RVI-Correlator.iconset/icon_128x128@2x.png](icons/macos/RVI-Correlator.iconset/icon_128x128@2x.png) | 256×256 | Apple macOS iconset representation |
| [icons/macos/RVI-Correlator.iconset/icon_256x256.png](icons/macos/RVI-Correlator.iconset/icon_256x256.png) | 256×256 | Apple macOS iconset representation |
| [icons/macos/RVI-Correlator.iconset/icon_256x256@2x.png](icons/macos/RVI-Correlator.iconset/icon_256x256@2x.png) | 512×512 | Apple macOS iconset representation |
| [icons/macos/RVI-Correlator.iconset/icon_512x512.png](icons/macos/RVI-Correlator.iconset/icon_512x512.png) | 512×512 | Apple macOS iconset representation |
| [icons/macos/RVI-Correlator.iconset/icon_512x512@2x.png](icons/macos/RVI-Correlator.iconset/icon_512x512@2x.png) | 1024×1024 | Apple macOS iconset representation |
| [website/favicons/favicon-16.png](website/favicons/favicon-16.png) | 16×16 | Project-specific browser favicon |
| [website/favicons/favicon-32.png](website/favicons/favicon-32.png) | 32×32 | Project-specific browser favicon |
| [website/favicons/favicon-48.png](website/favicons/favicon-48.png) | 48×48 | Project-specific browser favicon |
| [website/favicons/favicon-64.png](website/favicons/favicon-64.png) | 64×64 | Project-specific browser favicon |
| [website/favicons/favicon-128.png](website/favicons/favicon-128.png) | 128×128 | Project-specific browser favicon |
| [website/favicons/favicon-256.png](website/favicons/favicon-256.png) | 256×256 | Project-specific browser favicon |
| [website/favicons/apple-touch-icon.png](website/favicons/apple-touch-icon.png) | 180×180 | Website touch/bookmark image; not an iOS app icon |
| [website/favicons/web-app-icon-192.png](website/favicons/web-app-icon-192.png) | 192×192 | Website touch/bookmark image; not an iOS app icon |
| [website/favicons/web-app-icon-512.png](website/favicons/web-app-icon-512.png) | 512×512 | Website touch/bookmark image; not an iOS app icon |
| [website/social-sharing-1200x630.webp](website/social-sharing-1200x630.webp) | 1200×630 | hideouts.io Open Graph and link sharing |
| [website/hero-desktop.webp](website/hero-desktop.webp) | 2000×667 | Responsive wide hideouts.io app-page hero |
| [website/hero-tablet.webp](website/hero-tablet.webp) | 1536×1024 | Responsive tablet hideouts.io hero |
| [website/hero-mobile.webp](website/hero-mobile.webp) | 941×1672 | Portrait mobile hideouts.io app-page hero |
| [website/hero-background.webp](website/hero-background.webp) | 2000×667 | Background-only website artwork; no logo or claims |
| [website/project-card-1200x675.webp](website/project-card-1200x675.webp) | 1200×675 | Editorial project-card and gallery cover |
| [presentation/asset-overview.png](presentation/asset-overview.png) | 1800×1740 | Asset review board; conceptual artwork, not an app screenshot |

| Container | Contents | Placement |
| --- | --- | --- |
| [RVI-Correlator.icns](icons/macos/RVI-Correlator.icns) | Ten standard representations | macOS app bundle, Finder and Dock |
| [favicon.ico](website/favicons/favicon.ico) | Six resolutions | Browser favicon |
