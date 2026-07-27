import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: 'FUGA — prueba y repara fugas de datos en Firestore',
  description:
    'FUGA no solo advierte: lanza un atacante anónimo contra tus reglas de Firestore, te muestra los datos que se filtrarían y genera el fix verificado.',
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="es">
      <body>{children}</body>
    </html>
  );
}
