// middleware.ts
import { type NextRequest, NextResponse } from "next/server"

export function middleware(_req: NextRequest) {
  const res = NextResponse.next()

  // Security headers common to both envs
  res.headers.set("X-Frame-Options", "DENY")
  res.headers.set("X-Content-Type-Options", "nosniff")
  res.headers.set("Referrer-Policy", "strict-origin-when-cross-origin")
  // (X-XSS-Protection is deprecated; modern browsers ignore it)

  res.headers.set(
    "Permissions-Policy",
    "geolocation=(), microphone=(), camera=(), payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=()",
  )

  if (process.env.NODE_ENV === "development") {
    // ✅ Looser CSP for local dev (allows HMR, eval, inline styles, etc.)
    const devCsp = [
      "default-src 'self'",
      // Next dev HMR uses eval + inline scripts
      "script-src 'self' 'unsafe-eval' 'unsafe-inline' blob: data:",
      // You use many inline style attributes in components
      "style-src 'self' 'unsafe-inline'",
      // HMR/websocket + any API you call locally
      "connect-src * ws: wss:",
      // Allow images/fonts from anywhere in dev
      "img-src * data: blob:",
      "font-src * data:",
      "frame-ancestors 'none'",
      "base-uri 'self'",
      "form-action 'self'",
    ].join("; ")
    res.headers.set("Content-Security-Policy", devCsp)
  } else {
    // 🔒 Stricter CSP for production
    // NOTE: Because your components use inline styles (style={{ ... }}),
    // you must keep 'unsafe-inline' for style-src **OR** refactor to classes.
    const prodCsp = [
      "default-src 'self'",
      // No inline/eval scripts in prod
      "script-src 'self'",
      // Keep 'unsafe-inline' because you use inline styles everywhere
      "style-src 'self' 'unsafe-inline'",
      "img-src 'self' https: data:",
      "font-src 'self' data:",
      // Include your API and any 3rd-party origins as needed
      "connect-src 'self' https:",
      "frame-ancestors 'none'",
      "base-uri 'self'",
      "form-action 'self'",
    ].join("; ")
    res.headers.set("Content-Security-Policy", prodCsp)
  }

  return res
}

export const config = {
  matcher: [
    "/((?!_next/static|_next/image|favicon.ico).*)",
  ],
}
