const express = require('express');
const admin = require('firebase-admin');
const cors = require('cors');
const bodyParser = require('body-parser');
const winston =require('winston');
const bcrypt =require('bcrypt');
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
        methods: ["GET", "POST", "OPTIONS"]
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

//middeware para veridicar el token

const verifyToken = (req, res, next) => {
    try {
        // 1. Obtener token de múltiples fuentes
        const token = req.headers["authorization"]?.split(" ")[1] || 
                     req.query.token || 
                     req.cookies.token;
        
        if (!token) {
            console.log("Token no proporcionado");
            return res.status(403).json({message: "Token requerido"});
        }

        // 2. Verificar token
        jwt.verify(token, SECRET_KEY, (err, decoded) => {
            if (err) {
                console.error("Error verificando token:", {
                    name: err.name,
                    message: err.message,
                    expiredAt: err.expiredAt,
                    date: new Date()
                });
                
                if (err.name === "TokenExpiredError") {
                    return res.status(401).json({message: "Token expirado"});
                }
                return res.status(401).json({message: "Token inválido"});
            }

            // 3. Verificar datos básicos del token
            if (!decoded.email) {
                console.error("Token no contiene email");
                return res.status(401).json({message: "Token mal formado"});
            }

            req.user = decoded;
            next();
        });
    } catch (error) {
        console.error("Error en middleware verifyToken:", error);
        return res.status(500).json({message: "Error interno al verificar token"});
    }
};
// Variable global para almacenar clientes conectados
const clients = new Set();


// Endpoint SSE específico con headers manuales
server.get("/api/logs/stream", verifyToken, (req, res) => {
    // Configurar headers específicos para SSE
    res.writeHead(200, {
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache',
        'Connection': 'keep-alive',
        'Access-Control-Allow-Origin': 'http://localhost:3000',
        'Access-Control-Allow-Credentials': 'true'
    });
    res.flushHeaders();

    const clientId = Date.now();
    const newClient = {
        id: clientId,
        res
    };
    clients.add(newClient);

    // Enviar evento de conexión establecida
    res.write(`event: connect\ndata: ${JSON.stringify({msg: "Conexión SSE establecida", clientId})}\n\n`);

    // Heartbeat cada 30 segundos
    const heartbeat = setInterval(() => {
        res.write(`event: heartbeat\ndata: ${JSON.stringify({time: new Date().toISOString()})}\n\n`);
    }, 30000);

    req.on('close', () => {
        clearInterval(heartbeat);
        clients.delete(newClient);
        console.log(`Cliente ${clientId} desconectado`);
    });
});
// Función para notificar a todos los clientes sobre nuevos logs
const notifyClients = (logData) => {
    console.log("Preparando para enviar a clientes:", logData); // 👈 Debug
    const sseFormattedData = `event: newLog\ndata: ${JSON.stringify(logData)}\n\n`;
    clients.forEach(client => {
        try {
            console.log("Enviando a cliente:", client.id); // 👈 Debug
            client.res.write(sseFormattedData);
        } catch (error) {
            console.error("Error enviando SSE:", error);
            clients.delete(client);
        }
    });
};;



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
        console.log("Nuevo log guardado, notificando clientes:", logData);
        notifyClients(logData);// Notificar a todos los clientes SSE
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
  server.get('/api/getInfo', verifyToken, (req, res) => {
    console.log("Usuario autenticado:", req.user); // Debug
    
    try {
        const responseData = {
            nodeVersion: process.version,
            studentInfo: {
                fullName: "Dulce Valeria Miguel Juan",
                group: "IDGS11"
            },
            timestamp: new Date().toISOString()
        };
        
        console.log("Enviando respuesta:", responseData); // Debug
        res.json(responseData);
    } catch (error) {
        console.error("Error en /api/getInfo:", error);
        res.status(500).json({error: "Error interno del servidor"});
    }
});
  
server.get("/api/logs", verifyToken, async (req, res) => {
    const snapshot = await db.collection("log")
        .orderBy("Timestamp", "desc")
        .limit(50)
        .get();
    const logs = snapshot.docs.map(doc => doc.data());
    res.json(logs);
});




server.listen(PORT, () => {
    console.log(`Servidor corriendo en http://localhost:${PORT}`);
});
