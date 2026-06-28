export const dynamic = "force-static";

const favicon = `<svg width="48" height="52" viewBox="0 0 48 52" fill="none" xmlns="http://www.w3.org/2000/svg">
  <path d="M4 8L18 24L4 40" stroke="#19BA5D" stroke-width="8" stroke-linecap="round" stroke-linejoin="round" fill="none"/>
  <path d="M20 8L34 24L20 40" stroke="#19BA5D" stroke-width="8" stroke-linecap="round" stroke-linejoin="round" fill="none"/>
  <rect x="4" y="46" width="30" height="5" rx="2.5" fill="#19BA5D"/>
</svg>`;

export function GET() {
  return new Response(favicon, {
    headers: {
      "content-type": "image/svg+xml",
      "cache-control": "public, max-age=31536000, immutable",
    },
  });
}
