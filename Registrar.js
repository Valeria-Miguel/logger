Registrar 

http://localhost:3001/api/register

{ 
"email": "dulce@gmail.com",
"username": "dulce",
"password": "123dulva"
  
}
POST http://localhost:3001/login
{
    "username": "admin",
    "password": "1234"
  }


  GET http://localhost:3001/protected
  {
    "Authorization": "Bearer <token>"
  }


  router.post('/register', async (req, res) => {
    try {
        const { email, username, password } = req.body;

        if (!email || !password || !username) {
            return res.status(400).json({ message: 'Missing fields' });
        }

        // Hashear la contraseña
        const hashedPassword = await bcrypt.hash(password, 10);

        // Generar secreto para MFA
        const secret = speakeasy.generateSecret({ length: 20 });

        // Guardar usuario en la base de datos
        await db.collection('user').add({
            username,
            email,
            password: hashedPassword,
            mfaSecret: secret.base32
        });

        res.status(201).json({
            message: 'User registered',
            secret: secret.otpauth_url
        });
    } catch (error) {
        console.error('Error registering user:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});