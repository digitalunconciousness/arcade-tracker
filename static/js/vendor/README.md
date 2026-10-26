# Third-party scripts

Served from here because the Content-Security-Policy allows scripts from this site only
(`script-src 'self'`). Each file is the package's own build, byte for byte; check it against
the hashes below before replacing it.

| File | Package | License | Used by |
|---|---|---|---|
| `jsQR.js` | [jsQR](https://github.com/cozmo/jsQR) 1.4.0, `dist/jsQR.js` | Apache-2.0, `jsQR.LICENSE.txt` | `static/js/scan.js`, phone camera scanning on browsers without `BarcodeDetector` (Safari, Firefox). Loaded only when needed. |

`jsQR.js`
- npm integrity of `jsqr-1.4.0.tgz`: `sha512-dxLob7q65Xg2DvstYkRpkYtmKm2sPJ9oFhrhmudT1dZvNFFTlroai3AWSpLey/w5vMcLBXRgOJsbXpdN9HzU/A==`
- SHA-256 of the file: `bc40c8a15196236b2314db0856f72ca0b49980cd5413b8c852a7349f5fee0859`

Chart.js 3.9.1 (MIT, header in the file) predates this folder and stays at `static/js/chart.min.js`.
