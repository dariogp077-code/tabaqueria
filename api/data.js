// Función de servidor (Vercel). La clave de administrador vive acá, en el servidor:
// nadie puede verla desde el navegador. Los jefes entran sin clave (solo lectura).
const { neon } = require('@neondatabase/serverless');
const crypto = require('crypto');

const ADMIN_PASSWORD = 'dario1977';
const sha = s => crypto.createHash('sha256').update(String(s || '')).digest();
const same = (a, b) => !!b && crypto.timingSafeEqual(sha(a), sha(b));
const wait = ms => new Promise(r => setTimeout(r, ms));
let ready = false;

module.exports = async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  try {
    const { DATABASE_URL, VIEW_PASSWORD } = process.env; // VIEW_PASSWORD es opcional
    if (!DATABASE_URL) return res.status(500).json({ error: 'Falta la variable DATABASE_URL en Vercel.' });

    const role = req.headers['x-role'] === 'admin' ? 'admin' : 'jefes';
    const pass = req.headers['x-pass'];
    if (role === 'admin' && !same(pass, ADMIN_PASSWORD)) { await wait(800); return res.status(401).json({ error: 'Contraseña incorrecta.' }); }
    if (role === 'jefes' && VIEW_PASSWORD && !same(pass, VIEW_PASSWORD)) {
      await wait(800); return res.status(401).json({ error: 'Los jefes necesitan contraseña: escribila en el campo y tocá de nuevo el botón de Jefes.' });
    }

    const sql = neon(DATABASE_URL);
    if (!ready) {
      await sql`CREATE TABLE IF NOT EXISTS panel_data (id text PRIMARY KEY, payload jsonb NOT NULL, updated_at timestamptz NOT NULL DEFAULT now())`;
      ready = true;
    }

    if (req.method === 'GET') {
      const r = await sql`SELECT payload, updated_at FROM panel_data WHERE id = 'main'`;
      return res.status(200).json(r.length ? { payload: r[0].payload, updated_at: r[0].updated_at } : { payload: null });
    }

    if (req.method === 'POST') {
      if (role !== 'admin') return res.status(403).json({ error: 'Solo el administrador puede publicar.' });
      const body = req.body;
      if (!body || !Array.isArray(body.files)) return res.status(400).json({ error: 'Datos inválidos.' });
      await sql`INSERT INTO panel_data (id, payload, updated_at)
                SELECT 'backup', payload, updated_at FROM panel_data WHERE id = 'main'
                ON CONFLICT (id) DO UPDATE SET payload = EXCLUDED.payload, updated_at = EXCLUDED.updated_at`;
      await sql`INSERT INTO panel_data (id, payload, updated_at) VALUES ('main', ${JSON.stringify(body)}::jsonb, now())
                ON CONFLICT (id) DO UPDATE SET payload = EXCLUDED.payload, updated_at = now()`;
      return res.status(200).json({ ok: true });
    }

    res.setHeader('Allow', 'GET, POST');
    return res.status(405).json({ error: 'Método no permitido.' });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'Error en el servidor.' });
  }
};
