// La aplicación de la demo. server.js la arranca; las pruebas la arrancan con otras configuraciones.
// Lo que dice "(en clase)" lo programamos juntos, paso por paso. Mientras no esté, esa ruta responde 501.
const path = require('path');
const crypto = require('crypto');
const express = require('express');
const session = require('express-session');
const MySQLStore = require('express-mysql-session')(session);
const jwt = require('jsonwebtoken');
require('dotenv').config();

const { crearModeloUsuarios } = require('./modelos/usuarios.modelo');
const { crearModeloTokens } = require('./modelos/tokens.modelo');

const NOMBRE_COOKIE = 'connect.sid';

function todasLasSesiones(almacen) {
  return new Promise((resolve, reject) => {
    const promesa = almacen.all((error, sesiones) => (error ? reject(error) : resolve(sesiones)));
    if (promesa && typeof promesa.then === 'function') promesa.then(resolve, reject);
  });
}

function crearApp(config = {}, pool) {
  const app = express();
  app.use(express.json());

  const usuarios = crearModeloUsuarios(pool);
  const tokens = crearModeloTokens(pool);

  const maxAgeMs = config.maxAgeMs ?? config.maxAge ?? 1000 * 60 * 60 * 24;

  const almacen = config.almacen === 'memoria'
    ? new session.MemoryStore()
    : new MySQLStore({ createDatabaseTable: false, clearExpired: false }, pool);
  app.locals.almacen = almacen;

  app.use(
    session({
      name: NOMBRE_COOKIE,
      secret: process.env.SESSION_SECRET || 'secreto-solo-para-la-demo',
      store: almacen,
      resave: false,
      saveUninitialized: false,
      rolling: Boolean(config.rolling),
      cookie: {
        maxAge: maxAgeMs,
        httpOnly: config.httpOnly !== undefined ? config.httpOnly : true,
        sameSite: config.sameSite || 'lax',
        secure: false,
      },
    })
  );

  const idCorto = (id) => (id ? `${id.slice(0, 8)}...` : null);

  function vencida(sesion) {
    const desde = config.rolling ? sesion.ultimoUso : sesion.creada;
    if (!desde) return false;
    return Date.now() - desde > maxAgeMs;
  }

  function requiereSesion(req, res, next) {
    if (!req.session) {
      return res.status(401).json({ error: 'No has iniciado sesión' });
    }
    if (req.session.usuario && vencida(req.session)) {
      return req.session.destroy(() => {
        res.clearCookie(NOMBRE_COOKIE);
        res.status(401).json({ error: '401 Tu sesión ha vencido. Por favor vuelve a ingresar tu usuario' });
      });
    }
    if (!req.session.usuario) {
      return res.status(401).json({ error: 'No has iniciado sesión' });
    }
    req.session.ultimoUso = Date.now();
    next();
  }

  function requiereRol(rol) {
    return (req, res, next) => {
      if (!req.session || !req.session.usuario) {
        return res.status(401).json({ error: 'No has iniciado sesión' });
      }
      if (req.session.usuario.rol !== rol) {
        return res.status(403).json({
          error: `403 Eres ${req.session.usuario.usuario}, pero esta ruta solo le pertenece a ${rol}`,
        });
      }
      next();
    };
  }

  app.get('/api/config', (req, res) => res.json(config));

  app.post('/api/visita', (req, res) => {
    req.session.visitas = (req.session.visitas || 0) + 1;
    res.json({ visitas: req.session.visitas, sesion: idCorto(req.sessionID) });
  });

  app.post('/api/login', async (req, res, next) => {
    try {
      const { usuario, contrasena } = req.body || {};
      const datos = await usuarios.verificar(usuario, contrasena);
      if (!datos) {
        return res.status(401).json({ error: 'Usuario o Contraseña incorrecto' });
      }

      const antes = req.session.usuario || req.session.visitas !== undefined ? idCorto(req.sessionID) : null;
      const visitas = req.session.visitas || 0;

      const guardar = () => {
        req.session.usuario = datos;
        req.session.datos = datos;
        req.session.visitas = visitas;
        req.session.creada = Date.now();
        req.session.ultimoUso = Date.now();
        req.session.save((error) => {
          if (error) return next(error);
          res.json({
            usuario: datos,
            sesionAntes: antes,
            sesionDespues: idCorto(req.sessionID),
          });
        });
      };

      if (config.regenerarAlEntrar) {
        req.session.regenerate((error) => (error ? next(error) : guardar()));
      } else {
        guardar();
      }
    } catch (error) {
      next(error);
    }
  });

  app.post('/api/logout', (req, res, next) => {
    req.session.destroy((error) => {
      if (error) return next(error);
      res.clearCookie(NOMBRE_COOKIE);
      res.json({ mensaje: 'Sesión cerrada' });
    });
  });

  app.get('/api/sesion', requiereSesion, (req, res) => {
    const desde = config.rolling ? req.session.ultimoUso : req.session.creada;
    res.json({
      usuario: req.session.usuario,
      sesion: idCorto(req.sessionID),
      expiraEnSegundos: Math.max(0, Math.round((desde + maxAgeMs - Date.now()) / 1000)),
    });
  });

  app.get('/api/perfil', requiereSesion, (req, res) => {
    req.session.visitas = (req.session.visitas || 0) + 1;
    res.json({
      mensaje: `Hola ${req.session.usuario.nombre}`,
      rol: req.session.usuario.rol,
      visitas: req.session.visitas,
    });
  });

  app.get('/api/admin/reporte', requiereSesion, requiereRol('admin'), (req, res) => {
    res.json({ reporte: 'Talleres para administrador' });
  });

  app.get('/api/diagnostico/sesiones', async (req, res, next) => {
    try {
      const sesiones = await todasLasSesiones(almacen);
      const lista = Object.entries(sesiones || {}).map(([id, s]) => ({
        sesion: idCorto(id),
        esLaTuta: id === req.sessionID,
        usuario: s && s.usuario ? s.usuario.usuario : '(sin iniciar sesion)',
        visitas: (s && s.visitas) || 0,
        expira: s && s.cookie && s.cookie.expires,
      }));
      res.json({ almacen: config.almacen, sesiones: lista });
    } catch (error) {
      next(error);
    }
  });

  // --- JWT ---
  const SECRETO_JWT = config.jwtSecreto || process.env.JWT_SECRET || 'secreto-jwt-solo-para-la-demo';

  function firmarToken(usuario) {
    return jwt.sign(
      {
        sub: String(usuario.id),
        usuario: usuario.usuario,
        nombre: usuario.nombre,
        rol: usuario.rol,
      },
      SECRETO_JWT,
      {
        algorithm: 'HS256',
        expiresIn: config.jwtExpiraSeg || 3600,
        jwtid: crypto.randomUUID(),
      }
    );
  }

  async function requiereJWT(req, res, next) {
    const encabezado = req.headers.authorization || '';
    if (!encabezado.startsWith('Bearer ')) {
      return res.status(401).json({ error: '401. Falta el token para estar Autorizado' });
    }
    const token = encabezado.slice('Bearer '.length).trim();

    let datos;
    try {
      datos = jwt.verify(token, SECRETO_JWT, { algorithms: ['HS256'] });
    } catch (error) {
      if (error.name === 'TokenExpiredError') {
        return res.status(401).json({ error: '401 Token expirado por favor renuevalo o vuelve iniciar' });
      }
      return res.status(401).json({ error: '401 Token invalido' });
    }

    try {
      if (config.jwtRevocar && (await tokens.estaRevocado(datos.jti))) {
        return res.status(401).json({ error: '401. Token revocado ya se cerro la sesión' });
      }
    } catch (error) {
      return next(error);
    }

    req.jwt = datos;
    next();
  }

  function requiereRolJWT(rol) {
    return (req, res, next) => {
      if (!req.jwt || req.jwt.rol !== rol) {
        return res.status(403).json({
          error: `403 Eres ${req.jwt ? req.jwt.usuario : 'desconocido'}, pero esta ruta no tienes el permiso para navegar de acuerdo a tu ${rol}`,
        });
      }
      next();
    };
  }

  app.post('/api/jwt/login', async (req, res, next) => {
    try {
      const { usuario, contrasena } = req.body || {};
      const datos = await usuarios.verificar(usuario, contrasena);
      if (!datos) {
        return res.status(401).json({ error: 'Usuario o contraseña incorrectos' });
      }
      res.json({ token: firmarToken(datos), usuario: datos });
    } catch (error) {
      next(error);
    }
  });

  app.get('/api/jwt/perfil', requiereJWT, (req, res) => {
    res.json({
      mensaje: `Hola ${req.jwt.nombre}`,
      rol: req.jwt.rol,
      expiraEnSegundos: Math.max(0, req.jwt.exp - Math.floor(Date.now() / 1000)),
    });
  });

  app.post('/api/jwt/refresh', requiereJWT, (req, res) => {
    const { sub, usuario, nombre, rol } = req.jwt;
    res.json({ token: firmarToken({ id: sub, usuario, nombre, rol }) });
  });

  app.get('/api/jwt/reporte', requiereJWT, requiereRolJWT('admin'), (req, res) => {
    res.json({ reporte: 'Talleres: 3' });
  });

  app.post('/api/jwt/logout', requiereJWT, async (req, res, next) => {
    try {
      if (config.jwtRevocar) {
        await tokens.revocar(req.jwt.jti, req.jwt.usuario, req.jwt.exp);
        return res.json({
          mensaje: 'Token revocado en el servidor, se anota en la lista negra',
          revocado: true,
        });
      }
      return res.json({
        mensaje: 'El servidor no guarda nada, solo se puede borrar el token desde el navegador',
        revocado: false,
      });
    } catch (error) {
      next(error);
    }
  });

  // Tarjeta 6: solicitar token usando la sesión activa
  app.post('/api/jwt/solicitar', requiereSesion, (req, res) => {
    const usuario = req.session.usuario;
    const token = firmarToken(usuario);
    res.json({
      token,
      usuario,
    });
  });

  // Tarjeta 7: lista negra de tokens solo para administrador
  app.get('/api/jwt/lista-negra', requiereSesion, requiereRol('admin'), async (req, res, next) => {
    try {
      const lista = await tokens.listarRevocados();
      res.json({ tokensRevocados: lista });
    } catch (error) {
      next(error);
    }
  });

  app.use('/api', (req, res) => res.status(404).json({ error: 'Ruta no encontrada' }));

  app.use(express.static(path.join(__dirname, 'public')));

  app.use((error, req, res, next) => {
    console.log('Ejercicio de sesiones');
    console.error(error);
    res.status(500).json({ error: 'Error de servidor' });
  });

  return app;
}

module.exports = { crearApp, NOMBRE_COOKIE };