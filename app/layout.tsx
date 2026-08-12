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
  title: "Kord — One identity for every AI capability",
  description: "Connect your plugins, MCP servers, tools, and credentials to every AI through one secure control plane.",
  openGraph: {
    title: "One Kord. Every AI.",
    description: "Connections, tools, and memory that move with you.",
    images: [{ url: "/og.png", width: 1200, height: 630, alt: "Kord — the portable AI connection layer" }],
  },
  twitter: { card: "summary_large_image", title: "One Kord. Every AI.", description: "Connections, tools, and memory that move with you.", images: ["/og.png"] },
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
