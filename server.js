const express = require('express');
const admin = require('firebase-admin');
const cors = require('cors');
const bodyParser = require('body-parser');
const winston =require('winston');
const bcrypt =require('bcryptjs');
const jwt =require('jsonwebtoken');
const rateLimit=require('express-rate-limit');
const speakeasy = require('speakeasy');
const { Timestamp } = require('firebase-admin/firestore');

require('dotenv').config();
const PORT = 3001;


const limiter = rateLimit({
    windowMs : 10 * 60* 1000,
    max : 100,
    massage : 'Demasiadas peticiones desde esta IP. Inténtalo de nuevo más tarde'
});

const SECRET_KEY = process.env.JWT_SECRET || 'uteq';

//const serviceAccount = require("../config/firestore.json");
const serviceAccount = JSON.parse(process.env.SERVICE_ACCOUNT_KEY)

if (!admin.apps.length) {
    admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
    });
} else {
    admin.app(); 
}
const router = require("./routes");

const server = express();

server.use(
    limiter,
    cors({
        origin:"https://front-logger-seg.vercel.app/",
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
  
/*server.get("/api/logs", verifyToken, async (req, res) => {
    const snapshot = await db.collection("log")
        .orderBy("Timestamp", "desc")
        .limit(50)
        .get();
    const logs = snapshot.docs.map(doc => doc.data());
    res.json(logs);
});
*/
// Controlador para obtener logs con filtros dinámicos
server.get("/api/logs", verifyToken, async (req, res) => {
    try {
        // Parámetros de consulta
        const { 
            startDate, 
            endDate, 
            logLevel, 
            method, 
            statusCode,
            limit = 1000  // Límite por defecto para evitar sobrecarga
        } = req.query;
        
        let query = db.collection("log");
        
        // Filtro por rango de fechas
        if (startDate && endDate) {
            query = query.where("Timestamp", ">=", new Date(startDate))
                        .where("Timestamp", "<=", new Date(endDate));
        } else if (startDate) {
            query = query.where("Timestamp", ">=", new Date(startDate));
        } else if (endDate) {
            query = query.where("Timestamp", "<=", new Date(endDate));
        }
        
        // Filtros adicionales
        if (logLevel) {
            query = query.where("logLevel", "==", logLevel.toLowerCase());
        }
        if (method) {
            query = query.where("method", "==", method.toUpperCase());
        }
        if (statusCode) {
            query = query.where("status", "==", parseInt(statusCode));
        }
        
        // Orden y límite
        query = query.orderBy("Timestamp", "desc");
        
        if (limit && !isNaN(limit)) {
            query = query.limit(parseInt(limit));
        }
        
        const snapshot = await query.get();
        const logs = snapshot.docs.map(doc => {
            const data = doc.data();
            // Aseguramos que el timestamp sea un objeto Date válido
            data.Timestamp = data.Timestamp.toDate ? data.Timestamp.toDate() : new Date(data.Timestamp);
            return data;
        });
        
        res.json(logs);
    } catch (error) {
        console.error("Error fetching logs:", error);
        res.status(500).json({ error: "Error al obtener los logs" });
    }
});

// Endpoint para estadísticas (usado por las gráficas)
server.get("/api/logs/stats", verifyToken, async (req, res) => {
    try {
        const { period = 'hour', groupBy = 'logLevel' } = req.query;
        const now = new Date();
        let startDate;
        
        // Definir el rango de tiempo según el período solicitado
        switch (period) {
            case 'hour':
                startDate = new Date(now.getTime() - (60 * 60 * 1000));
                break;
            case 'day':
                startDate = new Date(now.getTime() - (24 * 60 * 60 * 1000));
                break;
            case 'week':
                startDate = new Date(now.getTime() - (7 * 24 * 60 * 60 * 1000));
                break;
            case 'month':
                startDate = new Date(now.getTime() - (30 * 24 * 60 * 60 * 1000));
                break;
            default:
                return res.status(400).json({ error: "Período no válido" });
        }
        
        const snapshot = await db.collection("log")
            .where("Timestamp", ">=", startDate)
            .get();
        
        const logs = snapshot.docs.map(doc => doc.data());
        
        // Procesamiento para gráficas
        const stats = {
            logLevels: {},
            methods: {},
            statusCodes: {},
            responseTimes: {
                '<100ms': 0,
                '100-500ms': 0,
                '500-1000ms': 0,
                '>1000ms': 0
            },
            timeline: []
        };
        
        // Agrupar datos
        logs.forEach(log => {
            // Por nivel de log
            stats.logLevels[log.logLevel] = (stats.logLevels[log.logLevel] || 0) + 1;
            
            // Por método HTTP
            stats.methods[log.method] = (stats.methods[log.method] || 0) + 1;
            
            // Por código de estado
            const statusGroup = `${Math.floor(log.status / 100)}xx`;
            stats.statusCodes[statusGroup] = (stats.statusCodes[statusGroup] || 0) + 1;
            
            // Por tiempo de respuesta
            if (log.responseTime < 100) stats.responseTimes['<100ms']++;
            else if (log.responseTime < 500) stats.responseTimes['100-500ms']++;
            else if (log.responseTime < 1000) stats.responseTimes['500-1000ms']++;
            else stats.responseTimes['>1000ms']++;
            
            // Para la línea de tiempo (agrupar por intervalos)
            const logTime = log.Timestamp.toDate ? log.Timestamp.toDate() : new Date(log.Timestamp);
            const timeKey = groupBy === 'minute' ? 
                logTime.toISOString().substring(0, 16) : // Por minuto
                logTime.toISOString().substring(0, 13); // Por hora
            
            if (!stats.timeline[timeKey]) {
                stats.timeline[timeKey] = {
                    timestamp: timeKey,
                    count: 0,
                    byLevel: {}
                };
            }
            stats.timeline[timeKey].count++;
            stats.timeline[timeKey].byLevel[log.logLevel] = 
                (stats.timeline[timeKey].byLevel[log.logLevel] || 0) + 1;
        });
        
        // Convertir timeline de objeto a array
        stats.timeline = Object.values(stats.timeline)
            .sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
        
        res.json(stats);
    } catch (error) {
        console.error("Error generating stats:", error);
        res.status(500).json({ error: "Error al generar estadísticas" });
    }
});



server.listen(PORT, () => {
    console.log(`Servidor corriendo en http://localhost:${PORT}`);
});
