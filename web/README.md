# postern web frontend

React + Vite + TypeScript. Çıktı `dist/`e derlenir ve Go binary'sine
`go:embed` ile gömülür — dağıtım yine tek binary.

```
npm install
npm run build        # dist/ üretir; sonra go build
npm run dev          # hot-reload; /api ve /auth 127.0.0.1:8088'e proxy'lenir
```
