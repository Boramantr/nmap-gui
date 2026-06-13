// JSX'i build zamanında saf JS'e derler (runtime'da Babel gerekmez).
const fs = require('fs');
const path = require('path');
const Babel = require('./src/renderer/vendor/babel.js');

const src = path.join(__dirname, 'src', 'renderer', 'app.jsx');
const out = path.join(__dirname, 'src', 'renderer', 'app.js');
const code = fs.readFileSync(src, 'utf8');
const result = Babel.transform(code, { presets: ['react'] });
fs.writeFileSync(out, result.code);
console.log('app.jsx -> app.js derlendi (' + result.code.length + ' byte)');
