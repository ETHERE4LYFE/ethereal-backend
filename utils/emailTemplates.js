// =========================================================
// EMAIL TEMPLATES - ETHERE4L (PURE HTML)
// =========================================================

// ✅ CAMBIO CRÍTICO: Usamos el CDN de Netlify para garantizar que Gmail cargue la imagen
// Asegúrate de que esta ruta exista en tu frontend (public/images/ui/header-logo.png)
const LOGO_URL = "https://ethereal-frontend.netlify.app/images/ui/header-logo.png";

const styles = {
    container: "margin:0;padding:0;width:100%;background-color:#f8f8f8;font-family:Helvetica,Arial,sans-serif;",
    wrapper: "max-width:600px;margin:20px auto;background:#ffffff;border-radius:8px;overflow:hidden;border:1px solid #eeeeee;",
    header: "background:#000000;padding:30px 20px;text-align:center;",
    logo: "display:block;width:150px;max-width:150px;height:auto;margin:0 auto;border:0;",
    content: "padding:40px 30px;color:#333333;line-height:1.6;",
    h1: "font-size:18px;font-weight:bold;margin:0 0 20px 0;color:#000000;text-align:center;text-transform:uppercase;",
    p: "font-size:15px;margin-bottom:15px;color:#555555;",
    box: "background:#f9f9f9;padding:15px;border-radius:4px;margin:20px 0;border-left:4px solid #000000;",
    button: "display:inline-block;background:#000000;color:#ffffff !important;text-decoration:none;padding:12px 25px;border-radius:4px;font-size:14px;font-weight:bold;margin-top:20px;",
    footer: "padding:20px;text-align:center;font-size:11px;color:#999999;background:#ffffff;border-top:1px solid #eee;"
};

function getEmailTemplate(cliente, pedido, jobId, isAdmin) {
    const totalFormatted = new Intl.NumberFormat('es-MX', {
        style: 'currency',
        currency: 'MXN'
    }).format(pedido.total);

    const titulo = isAdmin
        ? `NUEVA VENTA: ${jobId}`
        : `ORDEN RECIBIDA: ${jobId}`;

    const mensaje = isAdmin
        ? `Se ha generado una nueva orden. Revisa el PDF adjunto para procesar el envío.`
        : `Hola <b>${cliente.nombre}</b>, hemos recibido tu pedido correctamente.`;

    const detalleCaja = isAdmin
        ? `<strong>Cliente:</strong> ${cliente.nombre}<br><strong>Items:</strong> ${pedido.items.length}`
        : `<strong>ID:</strong> ${jobId}<br><strong>Total:</strong> ${totalFormatted}<br><strong>Estado:</strong> Pendiente de pago`;

    const callToAction = isAdmin
        ? ''
        : `
        <p style="${styles.p}">
            Adjunto encontrarás un PDF con los detalles de tu compra y las instrucciones de pago.
        </p>
        <div style="text-align:center;">
            <a href="https://ethereal-frontend.netlify.app" style="${styles.button}">
                VOLVER A LA TIENDA
            </a>
        </div>
        `;

    return `
<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ETHERE4L</title>
</head>
<body style="${styles.container}">
    <div style="${styles.wrapper}">
        <div style="${styles.header}">
            <img src="${LOGO_URL}" alt="ETHERE4L" style="${styles.logo}">
        </div>

        <div style="${styles.content}">
            <h1 style="${styles.h1}">${titulo}</h1>
            <p style="${styles.p}">${mensaje}</p>

            <div style="${styles.box}">
                <p style="margin:0;font-size:14px;line-height:1.5;">
                    ${detalleCaja}
                </p>
            </div>

            ${callToAction}
        </div>

        <div style="${styles.footer}">
            <p style="margin:0;">ETHERE4L STREETWEAR & HIGH FASHION</p>
            <p style="margin:5px 0;">Ciudad Juárez, Chihuahua, MX</p>
        </div>
    </div>
</body>
</html>
`;
}

function getPaymentConfirmedEmail(cliente, pedido, jobId, trackingUrl) {

    const totalFormatted = new Intl.NumberFormat('es-MX', {
        style: 'currency',
        currency: 'MXN'
    }).format(pedido.total);

    return `
<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<title>Pago Confirmado - ETHERE4L</title>
</head>
<body style="margin:0;padding:0;background:#f8f8f8;font-family:Helvetica,Arial,sans-serif;">
    <div style="max-width:600px;margin:30px auto;background:#ffffff;border-radius:8px;overflow:hidden;">
        <div style="background:#000;padding:30px;text-align:center;">
            <img src="${LOGO_URL}" alt="ETHERE4L" style="${styles.logo}">
        </div>

        <div style="padding:35px;color:#333;">
            <h2 style="text-align:center;margin-top:0;">Pago confirmado</h2>

            <p>Hola <b>${cliente.nombre}</b>,</p>

            <p>
                Hemos confirmado correctamente tu pago.
                Tu pedido ya está en proceso.
            </p>

            <div style="background:#f5f5f5;padding:20px;border-radius:6px;margin:25px 0;">
                <p><b>ID de pedido:</b> ${jobId}</p>
                <p><b>Total pagado:</b> ${totalFormatted}</p>
                <p><b>Estado:</b> PAGADO</p>
            </div>
            <div style="text-align:center;margin-top:30px;">
    <a href="${trackingUrl}" style="${styles.button}">
        VER ESTADO DEL PEDIDO
    </a>
    <p style="font-size:11px;color:#777;margin-top:10px;">
        Enlace seguro válido por 7 días
    </p>
</div>


            <p>En breve recibirás actualizaciones sobre el envío.</p>

            <p style="margin-top:30px;">— ETHERE4L</p>
        </div>

        <div style="text-align:center;font-size:12px;color:#999;padding:20px;">
            ETHERE4L • Ciudad Juárez, MX
        </div>
    </div>
</body>
</html>
`;
}

module.exports = {
    getEmailTemplate,
    getPaymentConfirmedEmail
};