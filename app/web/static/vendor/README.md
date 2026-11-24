# Vendored front-end assets

Served from our own origin so the Content-Security-Policy can stay `'self'` only, the
console works offline, and no third-party CDN sees analyst traffic. No build step.

| File | Package | npm integrity of the package tarball |
| --- | --- | --- |
| pico-2.1.1.min.css | @picocss/pico 2.1.1 (MIT) | sha512-kIDugA7Ps4U+2BHxiNHmvgPIQDWPDU4IeU6TNRdvXQM1uZX+FibqDQT2xUOnnO2yq/LUHcwnGlu1hvf4KfXnMg== |
| htmx-2.0.11.min.js | htmx.org 2.0.11 (0BSD) | sha512-Thx/WtpeOQqSrqBCw/A1cwGJGg4UrVa3+sW0GmrM3p4gJgO89ecH4qtbnyzDDWFvBTqjnIMCgELTNt636dtamA== |

SHA-256 of the files as committed:

```
fbc9a63fc9fc9f72d12fd7fc9806e11fa9f77ae4f9cad146b27003a1119ba3db  pico-2.1.1.min.css
d6fdc75f204e6bdefa99b69bf1e6d4ac69b8a364f77929f45c13476b4000f717  htmx-2.0.11.min.js
```
