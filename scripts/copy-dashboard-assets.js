const fs = require('fs');
const path = require('path');

const root = path.resolve(__dirname, '..');
const assets = [
  ['src/dashboard/combined.html', 'dist/dashboard/combined.html'],
  ['src/dashboard/dashboard-react.html', 'dist/dashboard/dashboard-react.html'],
];

for (const [from, to] of assets) {
  const source = path.join(root, from);
  const target = path.join(root, to);
  if (!fs.existsSync(source)) {
    throw new Error(`Missing dashboard asset: ${from}`);
  }
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.copyFileSync(source, target);
  console.log(`Copied ${from} -> ${to}`);
}
