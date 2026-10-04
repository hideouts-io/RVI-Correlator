/** Export the approved Aligned Evidence identity. Requires Node, rsvg-convert and cwebp. */
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';

const root = fileURLToPath(new URL('../assets/branding-v2/', import.meta.url));
const navy = '#111823';
const ice = '#F0F5FC';
const cyan = '#59E0DC';
const font = 'Helvetica Neue,Helvetica,Arial,sans-serif';
const defs = `<defs><linearGradient id="tile" x2="0.75" y2="1"><stop stop-color="#263546"/><stop offset="0.55" stop-color="#16212D"/><stop offset="1" stop-color="#0C151F"/></linearGradient><linearGradient id="rim" x2="1" y2="1"><stop stop-color="#6B7A8D" stop-opacity="0.55"/><stop offset="1" stop-color="#243444" stop-opacity="0.2"/></linearGradient><linearGradient id="signal" gradientUnits="userSpaceOnUse" x1="664" y1="196" x2="664" y2="836"><stop stop-color="#59E0DC"/><stop offset="1" stop-color="#29D2CE"/></linearGradient></defs>`;

/** @param {number} width @param {number} height @param {string} body @returns {string} */
function svg(width, height, body) {
  return `<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="${width}" height="${height}" viewBox="0 0 ${width} ${height}">${defs}${body}</svg>`;
}

/** @param {string} track @param {string} nodes @param {string} hole @returns {string} */
function mark(track, nodes, hole) {
  const mask = hole === 'none' ? `<defs><mask id="mark-holes" maskUnits="userSpaceOnUse" x="0" y="0" width="1024" height="1024"><rect width="1024" height="1024" fill="white"/>${[382,516,650].map(y => `<circle cx="664" cy="${y}" r="29" fill="black"/>`).join('')}</mask></defs>` : '';
  return `${mask}<g ${hole==='none'?'mask="url(#mark-holes)"':''} stroke-linecap="round" stroke-linejoin="round"><g fill="none" stroke="${track}" stroke-width="48"><path d="M168 296H330C402 296 410 382 488 382H830"/><path d="M168 516H830"/><path d="M168 736H330C402 736 410 650 488 650H830"/></g><path d="M664 196V836" fill="none" stroke="${nodes}" stroke-width="30"/>${[382,516,650].map(y => `<circle cx="664" cy="${y}" r="58" fill="${nodes}"/><circle cx="664" cy="${y}" r="29" fill="${hole}"/>`).join('')}</g>`;
}

/** @returns {string} */
function appIcon() {
  return `<rect x="64" y="68" width="896" height="896" rx="216" fill="#000" opacity="0.12"/><rect x="64" y="64" width="896" height="896" rx="216" fill="url(#tile)"/><rect x="67" y="67" width="890" height="890" rx="213" fill="none" stroke="url(#rim)" stroke-width="6"/>${mark(ice,'url(#signal)',navy)}`;
}

/** @param {number} x @param {number} y @param {number} scale @param {string} body @returns {string} */
function place(x,y,scale,body) { return `<g transform="translate(${x} ${y}) scale(${scale})">${body}</g>`; }

/** @param {number} x @param {number} y @param {number} size @param {string} fill @param {string} weight @param {string} value @returns {string} */
function text(x,y,size,fill,weight,value) { return `<text x="${x}" y="${y}" fill="${fill}" font-family="${font}" font-size="${size}" font-weight="${weight}">${value}</text>`; }

/** @param {number} width @param {number} height @param {string} filename @returns {Promise<string>} */
async function background(width,height,filename) {
  const data = await readFile(join(root,'source',filename));
  return `<image width="${width}" height="${height}" preserveAspectRatio="xMidYMid slice" xlink:href="data:image/png;base64,${data.toString('base64')}"/>`;
}

/** @param {string} color @param {string} nodes @returns {string} */
function lockup(color,nodes) {
  return `${place(-4,-18,0.23,mark(color,nodes,'none'))}${text(257,105,64,color,'700','RVI + PKTAP')}${text(257,178,64,color,'700','Correlator')}`;
}

/** @param {number} width @param {number} height @returns {string} */
function social(width,height) {
  const scale = width / 1280;
  return `<rect width="${width}" height="${height}" fill="#0B131C"/><defs><radialGradient id="glow"><stop stop-color="#18515B" stop-opacity="0.65"/><stop offset="1" stop-color="#0B131C" stop-opacity="0"/></radialGradient><pattern id="grid" width="48" height="48" patternUnits="userSpaceOnUse"><path d="M48 0H0V48" fill="none" stroke="#82D3D9" stroke-opacity="0.035"/></pattern></defs><rect width="${width}" height="${height}" fill="url(#grid)"/>${place(0,(height-640*scale)/2,scale,`<ellipse cx="1060" cy="290" rx="550" ry="450" fill="url(#glow)"/><g fill="none" stroke="${cyan}" stroke-opacity="0.16" stroke-width="1.5"><path d="M760 195H835Q870 195 900 248H1240"/><path d="M780 310H1240"/><path d="M760 425H835Q870 425 900 372H1240"/><circle cx="1050" cy="310" r="210"/><circle cx="1050" cy="310" r="244" stroke-dasharray="3 9"/></g>${text(76,100,17,cyan,'500','NETWORK EVIDENCE / NATIVE MACOS')}${text(76,230,68,ice,'700','RVI + PKTAP')}${text(76,310,76,ice,'700','Correlator')}${text(78,377,31,'#C5D1DE','400','Connected evidence. Clear uncertainty.')}${text(78,439,22,'#8FADBD','400','iPhone RVI · Mac PKTAP · Unified Log')}${place(875,132,0.31,appIcon())}<rect x="76" y="550" width="133" height="30" rx="15" fill="#1D3940"/>${text(91,570,15,cyan,'500','Experimental')}${text(226,570,16,'#AFC2CF','400','Correlation is a lead, not proof of causation.')}${text(1090,587,16,'#AFC2CF','400','hideouts.io')}`)}`;
}

/** @typedef {{file:string,width:number,height:number,body:string,purpose:string}} Artwork */
/** @type {Artwork[]} */
const art = [
  {file:'source/app-icon-master',width:1024,height:1024,body:appIcon(),purpose:'Editable macOS icon master; concept 01 production reconstruction'},
  ...[{name:'on-light',color:navy},{name:'on-dark',color:ice},{name:'mono-black',color:'#000000'},{name:'mono-white',color:'#FFFFFF'}].flatMap(({name,color}) => [
    {file:`logos/mark-${name}`,width:1024,height:1024,body:mark(color,name.startsWith('mono')?color:cyan,'none'),purpose:'Transparent standalone observation mark'},
    {file:`logos/logo-${name}`,width:720,height:240,body:lockup(color,name.startsWith('mono')?color:cyan),purpose:'Transparent horizontal logo and full app name'},
    {file:`logos/wordmark-${name}`,width:1050,height:112,body:text(0,82,80,color,'700','RVI + PKTAP Correlator'),purpose:'Transparent wordmark without symbol'},
  ]),
  {file:'icons/app-icon-light',width:1024,height:1024,body:`<rect x="64" y="64" width="896" height="896" rx="216" fill="${ice}"/><rect x="67" y="67" width="890" height="890" rx="213" fill="none" stroke="#E2EAF3" stroke-width="6"/>${mark(navy,navy,ice)}`,purpose:'Light-surface alternate icon, matching concept proof'},
  {file:'in-app/brand-logo',width:1024,height:1024,body:appIcon(),purpose:'SwiftUI sidebar, welcome panel and runtime Dock image'},
  {file:'github/social-preview-1280x640',width:1280,height:640,body:social(1280,640),purpose:'GitHub repository social preview upload'},
  {file:'website/social-sharing-1200x630',width:1200,height:630,body:social(1200,630),purpose:'hideouts.io Open Graph and link sharing'},
  {file:'website/hero-desktop',width:2000,height:667,body:`${await background(2000,667,'hero-background-desktop.png')}${text(120,100,23,'#397880','500','NATIVE MACOS / NETWORK INVESTIGATION')}${text(115,246,96,navy,'700','RVI + PKTAP')}${text(115,355,96,navy,'700','Correlator')}${text(120,444,40,'#375369','400','Connected evidence. Clear uncertainty.')}${text(122,512,28,'#42657A','400','iPhone RVI · Mac PKTAP · Unified Log')}${text(122,593,23,'#537487','400','Correlation is an investigative lead.')}${place(1310,20,0.61,appIcon())}`,purpose:'Responsive wide hideouts.io app-page hero'},
  {file:'website/hero-tablet',width:1536,height:1024,body:`${await background(1536,1024,'hero-background-desktop.png')}${text(90,130,21,'#397880','500','NATIVE MACOS / NETWORK INVESTIGATION')}${text(85,310,86,navy,'700','RVI + PKTAP')}${text(85,409,86,navy,'700','Correlator')}${text(90,528,35,'#375369','400','Connected evidence.')}${text(90,578,35,'#375369','400','Clear uncertainty.')}${text(92,780,27,'#42657A','400','iPhone RVI · Mac PKTAP')}${text(92,824,27,'#42657A','400','Unified Log evidence')}${text(92,935,23,'#537487','400','Correlation is an investigative lead.')}${place(795,230,0.64,appIcon())}`,purpose:'Responsive tablet hideouts.io hero'},
  {file:'website/hero-mobile',width:941,height:1672,body:`${await background(941,1672,'hero-background-mobile.png')}${text(82,134,25,'#397880','500','NATIVE MACOS / NETWORK INVESTIGATION')}${text(76,300,95,navy,'700','RVI + PKTAP')}${text(76,410,95,navy,'700','Correlator')}${place(129,510,0.67,appIcon())}${text(81,1270,43,'#375369','400','Connected evidence.')}${text(81,1327,43,'#375369','400','Clear uncertainty.')}${text(83,1425,29,'#42657A','400','iPhone RVI · Mac PKTAP · Unified Log')}${text(83,1534,26,'#537487','400','Correlation is an investigative lead.')}`,purpose:'Portrait mobile hideouts.io app-page hero'},
  {file:'website/hero-background',width:2000,height:667,body:await background(2000,667,'hero-background-desktop.png'),purpose:'Background-only website artwork; no logo or claims'},
  {file:'website/project-card-1200x675',width:1200,height:675,body:`${await background(1200,675,'hero-background-desktop.png')}${place(750,170,0.37,appIcon())}${text(67,112,19,'#397880','500','NATIVE MACOS / NETWORK EVIDENCE')}${text(64,270,68,navy,'700','RVI + PKTAP')}${text(64,350,68,navy,'700','Correlator')}${text(68,443,30,'#375369','400','Connected evidence.')}${text(68,487,30,'#375369','400','Clear uncertainty.')}${text(68,601,20,'#537487','400','Experimental correlation · hideouts.io')}`,purpose:'Editorial project-card and gallery cover'},
  {file:'github/readme-banner',width:1600,height:480,body:`${await background(1600,480,'hero-background-desktop.png')}${place(60,45,0.36,appIcon())}${text(480,185,81,navy,'700','RVI + PKTAP')}${text(480,282,81,navy,'700','Correlator')}${text(484,360,32,'#375369','400','Connected evidence. Clear uncertainty.')}`,purpose:'README or release page header; conceptual artwork'},
];

/** @param {Artwork} item @returns {Promise<{file:string,width:number,height:number,purpose:string}>} */
async function exportArtwork(item) {
  const path = join(root,item.file);
  await mkdir(dirname(path),{recursive:true});
  await writeFile(`${path}.svg`,svg(item.width,item.height,item.body));
  execFileSync('rsvg-convert',['--output',`${path}.png`,`${path}.svg`]);
  return {file:`${item.file}.png`,width:item.width,height:item.height,purpose:item.purpose};
}

const artwork = await Promise.all(art.map(exportArtwork));

/** @param {string} file @param {number} size @param {string} purpose @returns {Promise<{file:string,width:number,height:number,purpose:string}>} */
async function exportIcon(file,size,purpose) {
  const path = join(root,file);
  await mkdir(dirname(path),{recursive:true});
  execFileSync('rsvg-convert',['--width',String(size),'--height',String(size),'--output',path,join(root,'source/app-icon-master.svg')]);
  return {file,width:size,height:size,purpose};
}

const icons = await Promise.all([16,24,32,48,64,96,128,256,512,1024].map(size => exportIcon(`icons/app-icon-${size}.png`,size,'macOS app icon, Finder, Dock and small UI uses')));
const iconset = await Promise.all([16,32,128,256,512].flatMap(size => [1,2].map(scale => exportIcon(`icons/macos/RVI-Correlator.iconset/icon_${size}x${size}${scale===2?'@2x':''}.png`,size*scale,'Apple macOS iconset representation'))));
// Keep original PNG payloads intact, including small-icon translucent edges.
const icnsKinds = ['icp4','ic11','icp5','ic12','ic07','ic13','ic08','ic14','ic09','ic10'];
const icnsChunks = await Promise.all(iconset.map(async (item,index) => {
  const png = await readFile(join(root,item.file));
  const header = Buffer.alloc(8);
  header.write(icnsKinds[index],0,4,'ascii');
  header.writeUInt32BE(png.length+8,4);
  return Buffer.concat([header,png]);
}));
const icnsHeader = Buffer.alloc(8);
icnsHeader.write('icns',0,4,'ascii');
icnsHeader.writeUInt32BE(8+icnsChunks.reduce((sum,chunk)=>sum+chunk.length,0),4);
await writeFile(join(root,'icons/macos/RVI-Correlator.icns'),Buffer.concat([icnsHeader,...icnsChunks]));

const favicons = await Promise.all([16,32,48,64,128,256].map(size => exportIcon(`website/favicons/favicon-${size}.png`,size,'Project-specific browser favicon')));
const webIcons = await Promise.all([180,192,512].map(size => exportIcon(`website/favicons/${size===180?'apple-touch-icon':`web-app-icon-${size}`}.png`,size,'Website touch/bookmark image; not an iOS app icon')));
const touchPath = join(root,'website/favicons/apple-touch-icon.png');
await writeFile(join(root,'website/favicons/apple-touch-icon.svg'),svg(180,180,`<rect width="180" height="180" fill="${navy}"/>${place(0,0,180/1024,mark(ice,cyan,navy))}`));
execFileSync('rsvg-convert',['--output',touchPath,join(root,'website/favicons/apple-touch-icon.svg')]);

const faviconBuffers = await Promise.all([16,32,48,64,128,256].map(size => readFile(join(root,`website/favicons/favicon-${size}.png`))));
const icoHeader = Buffer.alloc(6);
icoHeader.writeUInt16LE(1,2);
icoHeader.writeUInt16LE(faviconBuffers.length,4);
const icoEntries = faviconBuffers.map((data,index) => {
  const size = [16,32,48,64,128,256][index];
  const entry = Buffer.alloc(16);
  entry[0] = size === 256 ? 0 : size;
  entry[1] = entry[0];
  entry.writeUInt16LE(1,4);
  entry.writeUInt16LE(32,6);
  entry.writeUInt32LE(data.length,8);
  entry.writeUInt32LE(6+16*faviconBuffers.length+faviconBuffers.slice(0,index).reduce((sum,buffer)=>sum+buffer.length,0),12);
  return entry;
});
await writeFile(join(root,'website/favicons/favicon.ico'),Buffer.concat([icoHeader,...icoEntries,...faviconBuffers]));

const webp = art.filter(item => item.file.startsWith('website/') && !item.file.includes('favicon')).map(item => {
  execFileSync('cwebp',['-quiet','-q','90',join(root,`${item.file}.png`),'-o',join(root,`${item.file}.webp`)]);
  return {file:`${item.file}.webp`,width:item.width,height:item.height,purpose:item.purpose};
});

/** @param {string} file @param {number} x @param {number} y @param {number} width @param {number} height @returns {Promise<string>} */
async function previewImage(file,x,y,width,height) {
  const data = await readFile(join(root,file));
  return `<image x="${x}" y="${y}" width="${width}" height="${height}" xlink:href="data:image/png;base64,${data.toString('base64')}"/>`;
}

const board = await exportArtwork({file:'presentation/asset-overview',width:1800,height:1740,purpose:'Asset review board; conceptual artwork, not an app screenshot',body:`<rect width="1800" height="1740" fill="#F3F7FB"/>${text(80,105,58,navy,'700','01 · Aligned Evidence')}${text(83,157,27,'#537487','400','RVI + PKTAP Correlator / complete visual identity')}${await previewImage('source/app-icon-master.png',80,200,310,310)}${await previewImage('icons/app-icon-light.png',450,200,310,310)}${await previewImage('logos/logo-on-light.png',875,246,750,250)}${text(112,535,23,'#537487','500','Primary app icon')}${text(472,535,23,'#537487','500','Light alternate')}${text(896,535,23,'#537487','500','Transparent logo and wordmark')}${await previewImage('website/hero-desktop.png',80,585,1640,547)}${text(82,1171,24,'#537487','500','hideouts.io / responsive hero family')}${await previewImage('github/social-preview-1280x640.png',80,1240,880,440)}${await previewImage('website/hero-mobile.png',1030,1230,241,428)}${text(80,1720,23,'#537487','500','GitHub social preview')}${text(1030,1701,23,'#537487','500','Mobile hero')}${await previewImage('logos/mark-mono-black.png',1360,1210,190,190)}${await previewImage('icons/app-icon-128.png',1360,1450,128,128)}${await previewImage('icons/app-icon-64.png',1540,1482,64,64)}${await previewImage('icons/app-icon-32.png',1630,1498,32,32)}${text(1340,1630,22,'#537487','500','Monochrome / small icons')}`});

const rows = [...artwork,...icons,...iconset,...favicons,...webIcons,...webp,board];
const inventory = await Promise.all(rows.map(async item => {
  const data = await readFile(join(root,item.file));
  return {...item,bytes:data.length,sha256:createHash('sha256').update(data).digest('hex')};
}));
const socialData = await readFile(join(root,'github/social-preview-1280x640.png'));
if (socialData.length >= 1000000) throw new Error(`GitHub social preview exceeds 1 MB: ${socialData.length} bytes. Simplify the source before export.`);
await writeFile(join(root,'asset-inventory.json'),JSON.stringify({identity:'01 · Aligned Evidence',date:'2026-10-04',assets:inventory},null,2)+'\n');
const manifest = `# Aligned Evidence asset family\n\nSelected identity: **01 · Aligned Evidence**, approved 2026-10-04. Three independent packet/log paths share a reference marker. The symbol represents aligned evidence, not established causation.\n\nThe production icon is an editable vector reconstruction of [concept 01](source/approved-concept-01.png). Its geometry is consistent across every export. The selected identity supplies the production app icon and sidebar, README header, GitHub social preview, and project-specific hideouts.io placements. Previous production artwork is preserved under \`assets/branding-v1/\`.\n\n## Ready-to-use placements\n\n- **App, Finder and Dock:** \`icons/macos/RVI-Correlator.icns\`, its ten-file iconset, and \`in-app/brand-logo.png\`.\n- **Logo/wordmark:** transparent light/dark and genuine monochrome treatments under \`logos/\`.\n- **GitHub:** \`github/social-preview-1280x640.png\`; solid background, under 1 MB. Upload through repository Settings → Social preview. \`github/readme-banner.png\` is a separate header illustration.\n- **hideouts.io:** three responsive heroes, background-only artwork, a project-card cover, 1200×630 sharing image, PNG/WebP exports, browser favicon, full-bleed 180px touch icon and 192/512px bookmark icons. Project-specific favicons must not replace the website's global favicon.\n- **Preview:** \`presentation/asset-overview.png\`. Promotional images are conceptual illustrations, not app screenshots or capture results.\n\n## Editable sources and regeneration\n\n| Input or captured preview | Pixels | Purpose |\n| --- | ---: | --- |\n| [Approved concept](source/approved-concept-01.png) | 1536×1024 | Selected design reference |\n| [Wide background](source/hero-background-desktop.png) | 2172×724 | Original generated raster source |\n| [Portrait background](source/hero-background-mobile.png) | 941×1672 | Original generated raster source |\n| [Packaged app](screenshots/app-overview-synthetic.png) | 2582×1760 | Real synthetic-demo screenshot |\n\nSVG siblings accompany the master icon, every logo, wordmark, hero, social image and review board. The symbol and typography are vector elements; generated hero backgrounds are embedded raster images. SVG text uses installed Helvetica Neue/Helvetica/Arial; no font files are redistributed. The two original generated backgrounds and exact built-in image generation prompts are in \`source/\`.\n\nRun \`node scripts/build-branding.mjs\` from the project root. Export tools: Node, rsvg-convert and cwebp; macOS iconutil can verify the container; these are artwork-development tools, not runtime app dependencies. This command regenerates only this asset family.\n\n## Use and limits\n\nKeep the three paths, hollow nodes and reference spine intact. Do not stretch, recolor individual streams or add success/check symbols. Keep clear space of at least one node diameter around the standalone mark. Use the navy/turquoise mark on light backgrounds and ice/turquoise on dark backgrounds; use genuine one-color variants for printing. Palette: midnight \`#111823\`, ice \`#F0F5FC\`, turquoise \`#59E0DC\`.\n\nNo private captures, logs, identifiers or screenshots are included in generated promotional art. Original captures and clocks were not changed. Correlation remains experimental; temporal proximity does not prove causation, Mac process labels attribute Mac traffic, and RVI coverage remains limited. No App Store, iOS-native-app or verified-attribution claims are made.\n\nDimensions follow the [current GitHub upload guidance](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/customizing-your-repositorys-social-media-preview), [Apple's iconset specification](https://developer.apple.com/library/archive/documentation/Xcode/Reference/xcode_ref-Asset_Catalog_Format/IconSetType.html), and the existing hideouts.io responsive hero component. These are project-local original assets; no third-party project artwork or fonts are redistributed. The existing project license remains unchanged.\n\n## Export inventory\n\nPNG logo/wordmark/icon assets have alpha; full-bleed touch, hero and sharing artwork have opaque backgrounds. SVG files have the dimensions of their PNG siblings. ICNS contains 16/32/64/128/256/512/1024px representations with the ten standard filenames; ICO contains 16/32/48/64/128/256px PNG images. ICNS uses original PNG payloads to retain transparent-edge colors. The machine-readable inventory records SHA-256 hashes and byte sizes. A [real app screenshot](screenshots/app-overview-synthetic.png), 2582×1760, shows the branded packaged app with clearly labeled fabricated demonstration data; it is not a live-capture validation.\n\n| File | Pixels | Placement |\n| --- | ---: | --- |\n${inventory.map(item=>`| [${item.file}](${item.file}) | ${item.width}×${item.height} | ${item.purpose} |`).join('\n')}\n\n| Container | Contents | Placement |\n| --- | --- | --- |\n| [RVI-Correlator.icns](icons/macos/RVI-Correlator.icns) | Ten standard representations | macOS app bundle, Finder and Dock |\n| [favicon.ico](website/favicons/favicon.ico) | Six resolutions | Browser favicon |\n`;
await writeFile(join(root,'ASSET-MANIFEST.md'),manifest);
console.log(`Exported ${inventory.length} raster/icon representations plus editable SVG sources, ICNS and ICO. GitHub preview: ${socialData.length} bytes.`);
