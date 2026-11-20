function crearModeloTokens(pool) {
  async function revocar(jti, _usuario = null, expUnix = null) {
    if (!jti) return;
    const expiraEn = expUnix
      ? new Date(expUnix * 1000)
      : new Date(Date.now() + 3600 * 1000);

    await pool.query(
      `INSERT IGNORE INTO tokens_revocados (jti, expira_en)
       VALUES (?, ?)`,
      [jti, expiraEn]
    );
  }

  async function estaRevocado(jti) {
    if (!jti) return false;

    const [filas] = await pool.query(
      `SELECT 1 FROM tokens_revocados
       WHERE jti = ? AND expira_en > NOW()
       LIMIT 1`,
      [jti]
    );

    return filas.length > 0;
  }

  async function listarRevocados() {
    const [filas] = await pool.query(
      `SELECT id, jti, expira_en, creado_en
       FROM tokens_revocados
       ORDER BY id DESC`
    );
    return filas;
  }

  return { revocar, estaRevocado, listarRevocados };
}

module.exports = { crearModeloTokens };