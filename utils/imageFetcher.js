// backend/utils/imageFetcher.js
const path = require('path');

// Configura tu dominio base de Netlify aquí o en variables de entorno
const FRONTEND_BASE_URL = process.env.FRONTEND_URL || 'https://ethereal-frontend.netlify.app';

/**
 * Descarga una imagen desde una URL y la devuelve como Buffer.
 * Maneja errores para no romper la generación del PDF.
 */
async function fetchImageBuffer(imageUrl) {
    if (!imageUrl) return null;

    try {
        // 1. Normalizar URL: Si viene relativa (/img/...), agregar dominio.
        let fullUrl = imageUrl;
        if (!imageUrl.startsWith('http')) {
            // Aseguramos que no haya dobles slashes
            const cleanPath = imageUrl.startsWith('/') ? imageUrl.substring(1) : imageUrl;
            fullUrl = `${FRONTEND_BASE_URL}/${cleanPath}`;
        }

        console.log(`⬇️ Descargando asset: ${fullUrl}`);

        // 2. Fetch nativo (Node 18+)
        const response = await fetch(fullUrl);

        if (!response.ok) {
            console.warn(`⚠️ Error ${response.status} al descargar imagen: ${fullUrl}`);
            return null;
        }

        // 3. Convertir a ArrayBuffer y luego a Buffer de Node
        const arrayBuffer = await response.arrayBuffer();
        return Buffer.from(arrayBuffer);

    } catch (error) {
        console.error(`❌ Error de red al descargar imagen: ${error.message}`);
        return null;
    }
}

module.exports = { fetchImageBuffer };