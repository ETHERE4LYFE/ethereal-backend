// src/services/trackingService.js
const axios = require('axios');

const normalizeStatus = (text = '') => {
    const s = text.toLowerCase();
    if (s.includes('entregado') || s.includes('delivered')) return 'delivered';
    if (s.includes('reparto')) return 'out_for_delivery';
    if (s.includes('tránsito') || s.includes('transit')) return 'in_transit';
    if (s.includes('recolectado') || s.includes('picked')) return 'shipped';
    return 'processing';
};

async function fetchRealTracking(carrier, trackingNumber) {
    // 🔴 MOCK CONTROLADO (NO producción aún)
    // Esto te permite avanzar sin API Key
    return [
        {
            status: 'En tránsito',
            details: 'Llegó al centro de distribución',
            location: 'Querétaro, MX',
            timestamp: new Date(Date.now() - 86400000).toISOString()
        },
        {
            status: 'En reparto',
            details: 'Salida a ruta de entrega',
            location: 'CDMX, MX',
            timestamp: new Date(Date.now() - 14400000).toISOString()
        }
    ];
}

module.exports = {
    fetchRealTracking,
    normalizeStatus
};
