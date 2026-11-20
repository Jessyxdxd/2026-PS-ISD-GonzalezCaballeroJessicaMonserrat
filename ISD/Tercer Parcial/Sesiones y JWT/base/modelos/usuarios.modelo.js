// Consultas a la tabla usuarios. Siempre con ? (consulta parametrizada), nunca pegando texto en el SQL.
const bcrypt = require('bcryptjs');

function crearModeloUsuarios(pool) {
  // Regresa el usuario (sin el hash) si la contraseña es correcta, o null si no.
  async function verificar(usuario, contrasena) {
    if (!usuario || !contrasena) {
      return null;
    }

    const [filas] = await pool.query(
      'SELECT id, usuario, nombre, rol, contrasena_hash FROM usuarios WHERE usuario = ? LIMIT 1',
      [usuario]
    );

    if (!filas || filas.length === 0) {
      return null;
    }

    const registro = filas[0];
    const hash = registro.contrasena_hash ?? registro.password_hash ?? registro.contrasena;

    if (!hash) {
      return null;
    }

    const coincide = await bcrypt.compare(String(contrasena), String(hash));
    if (!coincide) {
      return null;
    }

    return {
      id: registro.id,
      usuario: registro.usuario,
      nombre: registro.nombre,
      rol: registro.rol,
    };
  }

  return { verificar };
}

module.exports = { crearModeloUsuarios };