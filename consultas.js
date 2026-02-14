import pkg from "pg";
import bcrypt from "bcryptjs";

const { Pool } = pkg;

const pool = new Pool({
  user: "diegoalfonzogozalezgonzalez",
  host: "localhost",
  database: "softjobs",
  password: "Muller8*",
  allowExitOnIdle: true,
});

// ----------------------
// REGISTRAR USUARIO
// ----------------------
export const registrarUsuario = async (email, password, rol, lenguage) => {

  //  CÓDIGO AGREGADO AQUÍ — VALIDAR EMAIL DUPLICADO

  const existe = await pool.query(
    "SELECT * FROM usuarios WHERE email = $1",
    [email]
  );

  if (existe.rows.length > 0) {
    throw new Error("El email ya está registrado.");
  }

  // Hashear contraseña
  const passwordHash = await bcrypt.hash(password, 10);

  const query = `
    INSERT INTO usuarios (email, password, rol, lenguage)
    VALUES ($1, $2, $3, $4)
    RETURNING id, email, rol, lenguage;
  `;

  const { rows } = await pool.query(query, [
    email,
    passwordHash,
    rol,
    lenguage,
  ]);

  return rows[0];
};

// ----------------------
// LOGIN DE USUARIO
// ----------------------

export const loginUsuario = async (email, password) => {
  const query = `SELECT * FROM usuarios WHERE email = $1;`;
  const { rows } = await pool.query(query, [email]);

  if (!rows.length) return null;

  const usuario = rows[0];

  const passwordValida = await bcrypt.compare(password, usuario.password);

  if (!passwordValida) return null;

  return usuario;
};

// ----------------------
// OBTENER USUARIO POR EMAIL
// ----------------------

export const obtenerUsuarioPorEmail = async (email) => {
  const query = `
    SELECT id, email, rol, lenguage
    FROM usuarios
    WHERE email = $1;
  `;

  const { rows } = await pool.query(query, [email]);

  return rows[0];
};