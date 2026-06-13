// assets/logo-src.png (ejderha logosu) -> icon.png (512) + icon.ico (çoklu boyut)
const fs = require('fs');
const path = require('path');
const sharp = require('sharp');
const pngToIco = require('png-to-ico').default || require('png-to-ico');

const src = path.join(__dirname, 'assets', 'logo-src.png');
const pngOut = path.join(__dirname, 'assets', 'icon.png');
const icoOut = path.join(__dirname, 'assets', 'icon.ico');

(async () => {
  await sharp(src).resize(512, 512).png().toFile(pngOut);
  const sizes = [16, 32, 48, 64, 128, 256];
  const buffers = [];
  for (const s of sizes) buffers.push(await sharp(src).resize(s, s).png().toBuffer());
  const ico = await pngToIco(buffers);
  fs.writeFileSync(icoOut, ico);
  console.log('icon.png ve icon.ico ejderha logosundan üretildi.');
})();
