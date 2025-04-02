const express = require('express');
const admin = require('firebase-admin');
const cors = require('cors');
const bodyParser = require('body-parser');
const winston =require('winston');
const bcrypt =require('bcryptjs');
const jwt =require('jsonwebtoken');
const rateLimit=require('express-rate-limit');
const speakeasy = require('speakeasy');

require('dotenv').config();
const PORT = 3001;


const limiter = rateLimit({
    windowMs : 10 * 60* 1000,
    max : 100,
    massage : 'TDemasiadas peticiones desde esta IP. Inténtalo de nuevo más tarde'
});

const SECRET_KEY = process.env.JWT_SECRET || 'uteq';


const serviceAccount = require("./config/firestore.json");
//inicializa firestore admin SDK
if (!admin.apps.length) {
    admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
    });
} else {
    admin.app(); //si realimente inicializa usa la instancia
}
//si import first router.js conect to db, so crash.
const router = require("./routes");

//inicilize express
const server = express();

//Middlewares
server.use(
    limiter,
    cors({
        origin:"http://localhost:3000",
        credentials: true,
    })
);

//setup winston logging for files locally
const logger = winston.createLogger({
    level: 'info',
    format: winston.format.json(),
    transports: [
        new winston.transports.File({ filename:'logs/error.log', level: 'error'}),
        new winston.transports.File({ filename:'logs/all.log', level: 'info'}),
        new winston.transports.File({ filename:'logs/combined.log'}),
    ]
});

server.use(bodyParser.json());
const db =admin.firestore();

//Middleware
server.use((req, res, next) => {
    console.log(`🌪 [${req.method}] ${req.url} - Body:`, req.body);
    const startTime = Date.now();
    //snapshot riginal response
    const originalSend = res.send;
    let statusCode;

    res.send = function (body) {
        statusCode = res.statusCode;
        originalSend.call(this, body);
    };

    res.on('finish', async () => {
        //determinar nivel de log basado en status
        const logLevel = res.statusCode >= 400 ? 'error' : 'info';
        const responseTime = Date.now() - startTime;
        const logData = {
            logLevel: logLevel,
            Timestamp: new Date(),
            method: req.method,
            url:req.url,
            path: req.path,
            query: req.query,
            params: req.params,
            status:statusCode || res.statusCode,
            responseTime: responseTime,
            ip: req.ip || req.connection.remoteAddress, 
            userAgent: req.get('User-Agent'),
            protocol: req.protocol,
            hostname: req.hostname,
            system: {
                nodeVersion: process.version,
                environment: process.env.NODE_ENV || 'development',
                pid: process.pid
            },
        };

         //guardar en archivo local 
      logger.log({
        level: logLevel,
        message: 'Request completed',
        ...logData
    });



    //guardar en file local
    logger.info(logData);

    //guardar en firestore
    try {
        await db.collection('log').add(logData);
    } catch (error) {
        logger.error('Error al guardar log en Firestore:', error);
    }
    });
    next();
});

server.use("/api", router);

//Endpoint de login
server.post("/login", async (req, res) => {
    try {
        const { email, password } = req.body;
        const userDoc = await db.collection("user").doc(email).get();

        if (!userDoc.exists) {
            return res.status(401).json({ message: "Usuario no encontrado" });
        }

        const user = userDoc.data();
        const isPasswordValid = await bcrypt.compare(password, user.password);

        if (!isPasswordValid) {
            return res.status(401).json({ message: "Contraseña incorrecta" });
        }

        // Generar token JWT temporal (sin MFA aún)
        const tempToken = jwt.sign({ email }, SECRET_KEY, { expiresIn: "5m" });

        // Indicar que se requiere MFA
        res.json({ 
            tempToken, 
            requireMFA: true 
        });
    } catch (error) {
        console.error("Error en login:", error);
        res.status(500).json({ message: "Error interno del servidor" });
    }
});

server.post("/verify-mfa", async (req, res) => {
    const { email, token, tempToken } = req.body;

    try {
        // Verificar token temporal primero
        jwt.verify(tempToken, SECRET_KEY, async (err, decoded) => {
            if (err) return res.status(401).json({ message: "Token inválido o expirado" });

            // Obtener secreto MFA del usuario
            const userDoc = await db.collection("user").doc(email).get();
            const user = userDoc.data();

            const verified = speakeasy.totp.verify({
                secret: user.mfaSecret,
                encoding: "base32",
                token,
                window: 1
            });

            if (verified) {
                // Generar token JWT final (válido por 2 horas)
                const finalToken = jwt.sign({ email }, SECRET_KEY, { expiresIn: "2h" });
                res.json({ 
                    success: true, 
                    token: finalToken 
                });
            } else {
                res.status(401).json({ success: false, message: "Código MFA incorrecto" });
            }
        });
    } catch (error) {
        console.error("Error al verificar MFA:", error);
        res.status(500).json({ message: "Error interno del servidor" });
    }
});
//middeware para veridicar el token
const verifyToken = (req, res, next) => {
    const token = req.headers["authorization"];
    if (!token) return res.status(403).json({message: "Token requerido"});

    jwt.verify(token.split(" ") [1], SECRET_KEY, (err, decoded) => {
        if (err)
            return res.status(401).json({messeage: "Token invalido o expirado"});
        req.user = decoded;
        next();
    });
};

/*ruta protegida
server.get("/protected", verifyToken, (req, res) => {
    res.json({ message: "Acceso permitido", user: req.user });
});
*/
server.post("/register", async (req, res) => {
    try {
        const { email, username, password } = req.body;
        console.log("Datos recibidos:", { email, username, password });

        // Validaciones
        if (!email || !username || !password) {
            return res.status(400).json({ 
                message: "Campos requeridos: email, username, password",
                received: req.body
            });
        }
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
            return res.status(400).json({ message: "Email inválido" });
        }
        if (password.length < 8) {
            return res.status(400).json({ message: "La contraseña debe tener al menos 8 caracteres" });
        }

        // Verificar si el usuario ya existe
        const userDoc = await db.collection("user").doc(email).get();
        if (userDoc.exists) {
            return res.status(400).json({ message: "El email ya está registrado" });
        }

        // Hash de contraseña y generar secreto MFA
        const hashedPassword = await bcrypt.hash(password, 10);
        const secret = speakeasy.generateSecret({ length: 20 });

        // Guardar usuario en Firestore
        await db.collection("user").doc(email).set({
            email,
            username,
            password: hashedPassword,
            mfaSecret: secret.base32,  // Almacena el secreto en base32
        });

        // Respuesta exitosa con datos para MFA
        res.json({ 
            success: true,
            mfaUrl: secret.otpauth_url,  // URL para el QR
            mfaSecret: secret.base32     // Secreto para verificación manual (opcional)
        });

    } catch (error) {
        console.error("Error completo en /register:", error);
        res.status(500).json({ 
            message: "Error interno del servidor",
            error: error.message 
        });
    }
});

server.post("/verify-otp", async (req, res) => {
    const { email, token } = req.body;
  
    try {
      // Accede a Firestore y busca el usuario por su email
      const snapshot = await db.collection("user").where("email", "==", email).get();
  
      if (snapshot.empty) {
        return res.status(404).json({ error: "Usuario no encontrado" });
      }
  
      // Extrae el usuario encontrado
      const userDoc = snapshot.docs[0];
      const user = userDoc.data();
  
      // Verifica el código OTP
      const verified = speakeasy.totp.verify({
        secret: user.mfaSecret,  // Asegúrate de que 'mfaSecret' existe en Firestore
        encoding: "base32",
        token,
        window: 1
      });
  
      if (verified) {
        res.json({ success: true });
      } else {
        res.status(401).json({ success: false, error: "Código incorrecto" });
      }
    } catch (error) {
      console.error("Error al verificar OTP:", error);
      res.status(500).json({ error: "Error interno del servidor" });
    }
  });

  // API Routes
server.get('/api/getInfo', (req, res) => {
    res.json({
        nodeVersion: process.version,
        studentInfo: {
            fullName: "Dulce Valeria Miguel Juan", // Replace with your actual name
            group: "IDGS11" // Replace with your actual group
        },
        timestamp: new Date().toISOString()
    });
});
  
server.get("/api/logs", verifyToken, async (req, res) => {
    const logsSnapshot = await db.collection("log").orderBy("Timestamp", "desc").limit(50).get();
    const logs = logsSnapshot.docs.map(doc => doc.data());
    res.json(logs);
});

server.listen(PORT, () => {
    console.log(`Servidor corriendo en http://localhost:${PORT}`);
});
