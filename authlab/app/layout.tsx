import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "AuthLab — Secure vs Insecure OAuth & Sessions",
  description:
    "An educational, sandboxed playground for OAuth 2.0 Authorization Code + PKCE, refresh-token rotation, and secure session cookies. No real credentials are ever used.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
