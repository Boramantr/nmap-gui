// simple-icons'tan üretici marka logolarını çıkarıp renderer için global bir harita üretir.
const si = require('simple-icons');
const fs = require('fs');
const path = require('path');

// vendor anahtar kelimesi -> simple-icons slug
const MAP = {
  cisco: 'cisco', dell: 'dell', apple: 'apple', lenovo: 'lenovo', hp: 'hp', hewlett: 'hp',
  microsoft: 'microsoft', synology: 'synology', ubiquiti: 'ubiquiti', canon: 'canon',
  lg: 'lg', 'tp-link': 'tplink', tplink: 'tplink', samsung: 'samsung', intel: 'intel',
  netgear: 'netgear', asus: 'asus', huawei: 'huawei', xiaomi: 'xiaomi', google: 'google',
  raspberry: 'raspberrypi', vmware: 'vmware', 'd-link': 'dlink', dlink: 'dlink',
  fortinet: 'fortinet', realtek: 'realtek', tcl: 'tcl', sony: 'sony', acer: 'acer',
  zyxel: 'zyxel', mikrotik: 'mikrotik', qnap: 'qnap', philips: 'philips', oneplus: 'oneplus',
};

function get(slug) {
  const key = 'si' + slug.charAt(0).toUpperCase() + slug.slice(1);
  return si[key] || si['si' + slug];
}

const out = {};
for (const [kw, slug] of Object.entries(MAP)) {
  const ic = get(slug);
  if (ic) out[kw] = { p: ic.path, c: '#' + ic.hex };
}

const js = 'window.VENDOR_LOGOS = ' + JSON.stringify(out) + ';\n';
fs.writeFileSync(path.join(__dirname, 'src', 'renderer', 'vendor-logos.js'), js);
console.log('vendor-logos.js üretildi:', Object.keys(out).length, 'marka');
