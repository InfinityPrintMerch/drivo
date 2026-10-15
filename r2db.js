/* CONFIGURACIÓN R2 DIRECTA DESDE EL NAVEGADOR.
 * Estas credenciales serán visibles para quien pueda abrir la página.
 * Usa credenciales R2 de Object Read & Write limitadas a drivo-web.
 * No pegues aquí un API Token administrativo de Cloudflare.
 */
window.R2_CONFIG = {
    accountId: 'bd5ed32b0fb79bff9258f69dcf4e6476',
    endpoint: 'https://bd5ed32b0fb79bff9258f69dcf4e6476.r2.cloudflarestorage.com',
    bucket: 'drivo-web',
    publicUrl: 'https://pub-1a91b676516340c2a507f6d4524bb817.r2.dev',

    // Faltan estos dos valores; las URLs y el Account ID no los sustituyen.
    accessKeyId: 'eb69d8673c7e5c8973e7d92efb49a51d',
    secretAccessKey: 'eacea02e3c69c9b5a3feab0ba7514e2912e56bf5e58cd72b2a10eed9beb0d02e',
    sessionToken: '', // Solo para credenciales temporales; normalmente se deja vacío.

    prefix: 'drivoweb',
    requestTimeoutMs: 45000
};

// Cliente S3 SigV4 autocontenido: no requiere Worker, Node ni otra biblioteca.
(() => {
    'use strict';
    const validPath = /^(cars\/[a-zA-Z0-9_-]{1,80}\/(cover|extra[1-4])|(brands|manufacturers|collections)\/[a-zA-Z0-9_-]{1,80}\/(logo|banner)|profile\/current\/avatar)$/;
    const encode = value => encodeURIComponent(value).replace(/[!'()*]/g, char => '%' + char.charCodeAt(0).toString(16).toUpperCase());
    const hex = value => Array.from(new Uint8Array(value), byte => byte.toString(16).padStart(2, '0')).join('');
    const bytes = value => typeof value === 'string' ? new TextEncoder().encode(value) : value;
    const sha256 = value => crypto.subtle.digest('SHA-256', bytes(value));

    async function hmac(key, message) {
        const imported = await crypto.subtle.importKey('raw', bytes(key), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
        return crypto.subtle.sign('HMAC', imported, bytes(message));
    }

    function getConfig() {
        const source = window.R2_CONFIG;
        if (!source || typeof source !== 'object') throw new Error('No se cargó r2db.js. Debe estar junto a index.html.');
        if (!window.crypto?.subtle) throw new Error('Abre la página con HTTPS o desde http://localhost para conectar R2.');
        const accessKeyId = String(source.accessKeyId || '').trim();
        const secretAccessKey = String(source.secretAccessKey || '').trim();
        if (!accessKeyId || !secretAccessKey || /PEGA_AQUI/.test(accessKeyId + secretAccessKey)) {
            throw new Error('Completa accessKeyId y secretAccessKey en r2db.js con tus credenciales S3 de R2.');
        }
        let endpoint, publicUrl;
        try {
            endpoint = new URL(source.endpoint || `https://${source.accountId}.r2.cloudflarestorage.com`);
            publicUrl = new URL(source.publicUrl);
        } catch (_) { throw new Error('Revisa endpoint y publicUrl en r2db.js.'); }
        for (const url of [endpoint, publicUrl]) {
            if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash || !['', '/'].includes(url.pathname)) {
                throw new Error('endpoint y publicUrl deben ser URLs HTTPS sin rutas, parámetros ni credenciales.');
            }
        }
        if (!endpoint.hostname.endsWith('.r2.cloudflarestorage.com')) throw new Error('endpoint debe ser el endpoint S3 de Cloudflare R2.');
        const bucket = String(source.bucket || '').trim();
        const prefix = String(source.prefix || 'drivoweb').trim();
        if (!/^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$/.test(bucket)) throw new Error('El nombre de bucket no es válido.');
        if (!/^[a-zA-Z0-9_-]{1,64}$/.test(prefix)) throw new Error('prefix solo admite letras, números, guion y guion bajo.');
        const timeout = Number(source.requestTimeoutMs);
        return {
            endpoint: endpoint.origin, publicUrl: publicUrl.origin, bucket, prefix,
            accessKeyId, secretAccessKey, sessionToken: String(source.sessionToken || '').trim(),
            storageScope: endpoint.origin + '/' + bucket + '/' + prefix,
            requestTimeoutMs: Number.isFinite(timeout) ? Math.max(5000, Math.min(timeout, 120000)) : 45000
        };
    }

    function publicImageUrl(config, path, version = '') {
        if (!validPath.test(path)) throw new Error('Ruta de imagen inválida.');
        const url = new URL(config.publicUrl + '/' + [config.prefix, ...path.split('/')].map(encode).join('/'));
        if (version) url.searchParams.set('v', version);
        return url.href;
    }

    async function signedHeaders(config, method, url, bodyBytes, extraHeaders = {}, now = new Date()) {
        const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, '');
        const date = amzDate.slice(0, 8);
        const payloadHash = hex(await sha256(bodyBytes));
        const headers = {};
        for (const [name, value] of Object.entries(extraHeaders)) headers[name.toLowerCase()] = String(value).trim().replace(/\s+/g, ' ');
        headers.host = url.host;
        headers['x-amz-date'] = amzDate;
        headers['x-amz-content-sha256'] = payloadHash;
        if (config.sessionToken) headers['x-amz-security-token'] = config.sessionToken;
        const names = Object.keys(headers).sort();
        const canonicalHeaders = names.map(name => name + ':' + headers[name] + '\n').join('');
        const signedNames = names.join(';');
        const query = Array.from(url.searchParams, ([key, value]) => [encode(key), encode(value)])
            .sort((a, b) => a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : a[1] < b[1] ? -1 : a[1] > b[1] ? 1 : 0)
            .map(pair => pair.join('=')).join('&');
        const canonicalPath = url.pathname.split('/').map(part => encode(decodeURIComponent(part))).join('/');
        const canonicalRequest = [method, canonicalPath, query, canonicalHeaders, signedNames, payloadHash].join('\n');
        const scope = `${date}/auto/s3/aws4_request`;
        const stringToSign = ['AWS4-HMAC-SHA256', amzDate, scope, hex(await sha256(canonicalRequest))].join('\n');
        const dateKey = await hmac('AWS4' + config.secretAccessKey, date);
        const regionKey = await hmac(dateKey, 'auto');
        const serviceKey = await hmac(regionKey, 's3');
        const signingKey = await hmac(serviceKey, 'aws4_request');
        const signature = hex(await hmac(signingKey, stringToSign));
        // El navegador establece Host; se firma pero no se intenta escribir manualmente.
        delete headers.host;
        headers.Authorization = `AWS4-HMAC-SHA256 Credential=${config.accessKeyId}/${scope}, SignedHeaders=${signedNames}, Signature=${signature}`;
        return headers;
    }

    async function request(route, options = {}) {
        const config = getConfig();
        const checking = route === '/api/check';
        const path = checking ? '' : route.slice('/api/images/'.length);
        if (!checking && (!route.startsWith('/api/images/') || !validPath.test(path))) throw new Error('Ruta de imagen inválida.');
        const method = checking ? 'GET' : (options.method || 'GET').toUpperCase();
        if (!checking && !['PUT', 'DELETE'].includes(method)) throw new Error('Operación R2 no admitida.');
        const objectPath = checking ? [] : [config.prefix, ...path.split('/')];
        const url = new URL(config.endpoint + '/' + [config.bucket, ...objectPath].map(encode).join('/'));
        if (checking) {
            url.searchParams.set('list-type', '2');
            url.searchParams.set('max-keys', '1');
            url.searchParams.set('prefix', config.prefix + '/');
        }
        const body = options.body ? await options.body.arrayBuffer() : new ArrayBuffer(0);
        if (method === 'PUT' && (!body.byteLength || body.byteLength > 5242880)) throw new Error('La imagen debe ocupar entre 1 byte y 5 MB.');
        const extraHeaders = method === 'PUT' ? { 'content-type': options.body.type || 'image/webp', 'cache-control': 'no-store' } : {};
        const headers = await signedHeaders(config, method, url, body, extraHeaders);
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), config.requestTimeoutMs);
        try {
            const response = await fetch(url.href, {
                method, headers, ...(method === 'PUT' ? { body } : {}),
                signal: controller.signal, mode: 'cors', credentials: 'omit', cache: 'no-store', redirect: 'error'
            });
            if (!response.ok) {
                const text = await response.text();
                const xml = new DOMParser().parseFromString(text, 'application/xml');
                const code = xml.querySelector('Code')?.textContent || '';
                const explanations = {
                    SignatureDoesNotMatch: 'La firma no coincide. Revisa las dos claves y el reloj de tu equipo.',
                    InvalidAccessKeyId: 'El Access Key ID no es válido.',
                    AccessDenied: 'Las credenciales no tienen permiso Object Read & Write sobre drivo-web.',
                    NoSuchBucket: 'No se encontró la bucket configurada.',
                    RequestTimeTooSkewed: 'La fecha u hora de tu equipo no es correcta.',
                    ExpiredToken: 'Las credenciales temporales han caducado.'
                };
                throw new Error(explanations[code] || `R2 respondió HTTP ${response.status}${code ? ' (' + code + ')' : ''}. Revisa las credenciales y los permisos de la bucket.`);
            }
            if (method === 'PUT') {
                const version = response.headers.get('ETag')?.replace(/"/g, '') || crypto.randomUUID();
                return { ok: true, path, url: publicImageUrl(config, path, version) };
            }
            return { ok: true };
        } catch (error) {
            if (error.name === 'AbortError') throw new Error('R2 tardó demasiado. Vuelve a intentar; tus registros locales se conservan.');
            if (error instanceof TypeError) throw new Error('No se pudo conectar con R2. Revisa la conexión y configura CORS en la bucket para permitir GET, HEAD, PUT y DELETE.');
            throw error;
        } finally { clearTimeout(timer); }
    }

    function reference(source) {
        if (typeof source !== 'string' || !source.startsWith('https://')) return null;
        try {
            // Interpretar URLs no exige disponer de claves para conservar la cola de borrado.
            const raw = window.R2_CONFIG;
            const url = new URL(source);
            const publicBase = new URL(raw.publicUrl);
            const start = '/' + encode(raw.prefix || 'drivoweb') + '/';
            const path = url.pathname.slice(start.length);
            if (url.origin !== publicBase.origin || !url.pathname.startsWith(start) || !validPath.test(path)) return null;
            return { storageScope: new URL(raw.endpoint).origin + '/' + raw.bucket + '/' + (raw.prefix || 'drivoweb'), path };
        } catch (_) { return null; }
    }

    window.DrivoR2 = Object.freeze({ getConfig, request, reference, publicImageUrl });
})();
