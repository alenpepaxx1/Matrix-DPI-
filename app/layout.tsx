/**
 * Copyright (c) 2026 Alen Pepa
 * All rights reserved.
 */
import type { Metadata } from 'next'
import { Inter, JetBrains_Mono } from 'next/font/google'
import './globals.css'

const inter = Inter({ subsets: ['latin'], variable: '--font-sans' })
const jetbrainsMono = JetBrains_Mono({ subsets: ['latin'], variable: '--font-mono' })

export const metadata: Metadata = {
  title: 'MATRIX DPI',
  description: 'Advanced Deep Packet Inspection Engine',
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en" className={`${inter.variable} ${jetbrainsMono.variable} dark`}>
      <body className="font-sans antialiased bg-[#020502] text-[#d4d4d4] overflow-hidden">
        {children}
      </body>
    </html>
  )
}
