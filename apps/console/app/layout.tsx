import type { Metadata } from "next";
import "./globals.css";
import { auth } from "@/lib/auth";
import { Sidebar } from "./Sidebar";
import { Providers } from "./Providers";

export const metadata: Metadata = {
  title: "Groundwork Console",
  description: "AI runtime control and security telemetry for regulated enterprise AI.",
};

export default async function RootLayout({ children }: { children: React.ReactNode }) {
  const session = await auth();
  return (
    <html lang="en">
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="" />
        <link
          href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap"
          rel="stylesheet"
        />
      </head>
      <body>
        <Sidebar />
        <Providers session={session}>{children}</Providers>
      </body>
    </html>
  );
}
