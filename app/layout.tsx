import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  metadataBase: new URL(process.env.NEXT_PUBLIC_SITE_URL || "http://localhost:3000"),
  title: "Cargo — Your AI life, owned by you",
  description: "An open-source, local-first encrypted vault for carrying AI connections and memory between Claude, Cursor, and Codex.",
  openGraph: {
    title: "Cargo — Your AI life, owned by you",
    description: "Open-source, local-first AI portability.",
    images: [{ url: "/cargo-og.png", width: 1731, height: 909, alt: "Cargo — your AI life, owned by you" }],
  },
  twitter: { card: "summary_large_image", title: "Cargo — Your AI life, owned by you", description: "Open-source, local-first AI portability.", images: ["/cargo-og.png"] },
  icons: {
    icon: "/favicon.svg",
    shortcut: "/favicon.svg",
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body
        className={`${geistSans.variable} ${geistMono.variable} antialiased`}
      >
        {children}
      </body>
    </html>
  );
}
