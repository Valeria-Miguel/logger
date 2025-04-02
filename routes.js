const express = require('express');
const bcrypt =require('bcryptjs');
const jwt = require('jsonwebtoken');
const admin = require('firebase-admin');
const router = express.Router();
const speakeasy = require('speakeasy');
const db = admin.firestore();
const JWT_SECRET = process.env.JWT_SECRET || 'uteq';
console.debug('Usign JWT secret: ' + JWT_SECRET);
//user registration
let requestCounter = 0;
/*
const validateEmail = (email) => {
    const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return re.test(email);
};

const validateFields = (fields) => {
    for (const [key, value] of Object.entries(fields)) {
        if (!value || value.trim() === '') {
            return { valid: false, field: key };
        }
    }
    return { valid: true };
};

router.post('/login', async (req, res, next) => {
    try {
        const { email, password } = req.body;
        
        // Validar campos
        const fieldValidation = validateFields({ email, password });
        if (!fieldValidation.valid) {
            return res.status(400).json({ 
                message: `El campo ${fieldValidation.field} no puede estar vacío` 
            });
        }
        
        // Obtener usuario
        const userRef = db.collection('user').doc(email);
        const doc = await userRef.get();
        
        if (!doc.exists) {
            return res.status(401).json({ message: 'Credenciales inválidas' });
        }
        
        const user = doc.data();
        
        // Verificar contraseña
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(401).json({ message: 'Credenciales inválidas' });
        }
        
        // Generar token JWT
        const token = jwt.sign(
            { email: user.email, username: user.username },
            JWT_SECRET,
            { expiresIn: '1h' }
        );
        
        res.json({ 
            token,
            requireMFA: true,
            mfaSecret: user.mfaSecret // En producción, no devolver esto
        });
        
    } catch (error) {
        next(error);
    }
});

router.post('/register', async (req, res, next) => {
    try {
        const { email, username, password } = req.body;
        
        // Validar campos no vacíos
        const fieldValidation = validateFields({ email, username, password });
        if (!fieldValidation.valid) {
            return res.status(400).json({ 
                message: `El campo ${fieldValidation.field} no puede estar vacío` 
            });
        }
        
        // Validar formato de email
        if (!validateEmail(email)) {
            return res.status(400).json({ message: 'Formato de email inválido' });
        }
        
        // Verificar si el usuario ya existe
        const userRef = db.collection('user').doc(email);
        const doc = await userRef.get();
        
        if (doc.exists) {
            return res.status(400).json({ message: 'El usuario ya existe' });
        }
        
        // Hashear contraseña y crear usuario
        const hashedPassword = await bcrypt.hash(password, 10);
        const secret = speakeasy.generateSecret({ length: 20 });
        
        await userRef.set({
            username,
            email,
            password: hashedPassword,
            mfaSecret: secret.base32,
            createdAt: admin.firestore.FieldValue.serverTimestamp()
        });
        
        res.status(201).json({ 
            message: 'Usuario registrado exitosamente',
            mfaSecret: secret.base32 // En producción, no deberías devolver esto
        });
        
    } catch (error) {
        next(error);
    }
});*/
// Ruta para obtener usuarios
router.get('/users', async (req, res, next) => {
    try {
        // Incrementar el contador de peticiones
        requestCounter++;

        // Si el contador es divisible por 2, generar un error
        if (requestCounter % 3 === 0) {
            // Crear un error simulado
            const error = new Error('Error simulado cada 2 peticiones');
            error.statusCode = 500; // Asignar un código de estado al error
            throw error; // Lanzar el error para que el middleware en server.js lo maneje
        }

        // Obtener todos los documentos de la colección 'user'
        const usersSnapshot = await db.collection('user').get();
        const users = [];
        usersSnapshot.forEach((doc) => {
            const userData = doc.data();
            // No devolver la contraseña por seguridad
            delete userData.password;
            users.push({ id: doc.id, ...userData });
        });
        res.status(200).json(users);
    } catch (error) {
        // Pasar el error al middleware en server.js
        next(error); // Ahora `next` está definido
    }
});
module.exports = router;

