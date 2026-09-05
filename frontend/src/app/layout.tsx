import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: 'Sentinel-GRC | Enterprise Security',
  description: 'Enterprise Governance, Risk & Compliance Platform',
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body className="antialiased text-white min-h-screen">
        {/* Global Liquid Morphism Background */}
        <div className="liquid-bg">
          <div className="blob blob-1"></div>
          <div className="blob blob-2"></div>
        </div>
        
        {children}
      </body>
    </html>
  );
}
