// tiny local server for smoke-testing verify.mjs without SSH/Qualys
import { createServer } from 'node:http';

const palette = [
  [200, 30, 30], [30, 90, 200], [30, 200, 90], [250, 200, 0], [150, 60, 200], [20, 180, 180],
];

createServer((req, res) => {
  const t = Date.now();
  const [r, g, b] = palette[t % palette.length];
  res.setHeader('content-type', 'text/html');
  res.end(`<!doctype html><html><body style="margin:0">
    <div id="bar" style="background:rgb(${r},${g},${b});height:220px;width:100%"></div>
    <div style="font:bold 60px monospace;padding:30px">tick=${t}</div>
    <table style="border-collapse:collapse;margin:30px">
      <tr><td style="border:1px solid #000;padding:20px">row A</td><td style="border:1px solid #000;padding:20px">${t % 7}</td></tr>
      <tr><td style="border:1px solid #000;padding:20px">row B</td><td style="border:1px solid #000;padding:20px">${(t >> 3) % 9}</td></tr>
    </table>
  </body></html>`);
}).listen(8989, () => console.log('smoke server on http://127.0.0.1:8989'));