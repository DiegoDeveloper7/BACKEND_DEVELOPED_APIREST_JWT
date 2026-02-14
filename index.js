import express from "express";
import cors from "cors";
import morgan from "morgan";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import { registrarUsuario, loginUsuario, obtenerUsuarioPorEmail } from "./consultas.js";

dotenv.config();

const app = express();

// =============================
//   MIDDLEWARE 1: REPORTES
// =============================
app.use((req, res, next) => {
  const fecha = new Date().toLocaleString();
  console.log(`📌 Consulta recibida → ${req.method} ${req.url} — ${fecha}`);
  next();
});

// =============================
//   MIDDLEWARES GLOBALES
// =============================
app.use(cors());
app.use(express.json());
app.use(morgan("dev"));

const JWT_SECRET = process.env.JWT_SECRET || "CLAVE_SUPER_SECRETA";


// ======================================================
//  CÓDIGO AGREGADO AQUÍ — MIDDLEWARE VALIDAR PASSWORD
// ======================================================
const validarPassword = (req, res, next) => {
  const { password } = req.body;

  const regex =
    /^(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{6,10}$/;

  if (!regex.test(password)) {
    return res.status(400).json({
      message:
        "La contraseña debe tener entre 6 y 10 caracteres, incluir una letra mayúscula, un número y un carácter especial."
    });
  }

  next();
};


// ======================================================
// MIDDLEWARE 2: VERIFICAR CREDENCIALES / LOGIN
// ======================================================
const verificarCredenciales = (req, res, next) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({
      message: "Faltan credenciales: email y password son obligatorios.",
    });
  }

  next();
};

// ======================================================
// MIDDLEWARE 3: VALIDAR TOKEN / RUTAS PROTEGIDAS
// ======================================================
const validarToken = (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader) {
      return res.status(401).json({ message: "Token no proporcionado." });
    }

    const token = authHeader.split(" ")[1]; // "Bearer token"

    const decoded = jwt.verify(token, JWT_SECRET);

    req.email = decoded.email;

    next();
  } catch (error) {
    return res.status(401).json({
      message: "Token inválido o expirado.",
    });
  }
};

// --------------------------------------------------------
// 1. POST /usuarios — REGISTRO
// --------------------------------------------------------
// CÓDIGO AGREGADO AQUÍ — SE AGREGA validarPassword SOLO EN REGISTRO

app.post("/usuarios", validarPassword, async (req, res) => {
  try {
    const { email, password, rol, lenguage } = req.body;

    if (!email || !password || !rol || !lenguage) {
      return res.status(400).json({ message: "Todos los campos son obligatorios." });
    }

    const nuevo = await registrarUsuario(email, password, rol, lenguage);

    res.status(201).json({
      message: "Usuario registrado con éxito",
      usuario: nuevo,
    });
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
});

// --------------------------------------------------------
// 2. POST /login — TOKEN JWT
// --------------------------------------------------------
app.post("/login", verificarCredenciales, async (req, res) => {
  try {
    const { email, password } = req.body;

    const usuario = await loginUsuario(email, password);

    if (!usuario) {
      return res.status(401).json({ message: "Credenciales incorrectas." });
    }

    const token = jwt.sign({ email: usuario.email }, JWT_SECRET, {
      expiresIn: "1h",
    });

    res.json({
      message: "Usuario autenticado",
      token,
    });
  } catch (error) {
    console.error("Error en POST /login:", error.message);
    res.status(500).json({ message: error.message });
  }
});

// --------------------------------------------------------
// 3. GET /usuarios — RUTA PROTEGIDA
// --------------------------------------------------------
app.get("/usuarios", validarToken, async (req, res) => {
  try {
    const usuario = await obtenerUsuarioPorEmail(req.email);

    if (!usuario) {
      return res.status(404).json({ message: "Usuario no encontrado." });
    }

    res.json([usuario]);
  } catch (error) {
    console.error("Error en GET /usuarios:", error.message);

    res.status(401).json({
      message: "Token inválido o expirado.",
    });
  }
});


const PORT = 3000;
app.listen(PORT, () => console.log(`🔥 Servidor backend corriendo en puerto ${PORT}`));



