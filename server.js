const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const swaggerUi = require('swagger-ui-express');
const swaggerJsdoc = require('swagger-jsdoc');
const bcrypt = require('bcryptjs');

const app = express();
const PORT = 5000;
const SECRET_KEY = 'your_secret_key'; // You should use an environment variable for this in production

app.use(bodyParser.json());

const users = [
    {
        email: "test1@gmail.com",
        password: bcrypt.hashSync('password', 8),
        role: "ADMIN",
        permissions: [
            "WRITE",
            "READ"
        ]
    },
    {
        email: "test2@gmail.com",
        password: bcrypt.hashSync('password', 8),
        role: "READER",
        permissions: [
            "READ"
        ]
    }
]
app.post('/login', (req, res) => {
    const { email, password, role, permissions } = req.body;
    if (email && password) {
        const currentUser = users.find(obj => obj.email === email);
        if(currentUser){
            // Simple email/password validation
            if (bcrypt.compareSync(password, currentUser.password)) {
                const token = jwt.sign({ email: email, role: currentUser.role, permissions: currentUser.permissions }, SECRET_KEY, { expiresIn: '1m' });
                return res.status(200).json({ token });
            } else {
                alert("Password is wrong");
                return res.status(401).json({ message: 'Password is wrong' });
            }
        } else {
            alert("We do not have user with such an email");
            return res.status(401).json({ message: 'We do not have user with such an email' });
        }
    }


});

// Middleware to check JWT and permissions
const authenticateJWT = (permissionsRequired) => {
    return (req, res, next) => {
        const authHeader = req.headers.authorization;
        if (authHeader) {
            const token = authHeader.split(' ')[1];
            jwt.verify(token, SECRET_KEY, (err, user) => {
                if (err) {
                    return res.sendStatus(403);
                }
                req.user = user;
                if (permissionsRequired.every(permission => user.permissions.includes(permission))) {
                    next();
                } else {
                    return res.sendStatus(403);
                }
            });
        } else {
            res.sendStatus(401);
        }
    };
};


app.get('/entities', authenticateJWT(['READ']), (req, res) => {
    const { skip = 0, limit = 10 } = req.query;
    // Simulated data retrieval
    const entities = Array.from({ length: 100 }, (_, i) => ({ id: i, name: `Entity ${i}` }));
    const result = entities.slice(Number(skip), Number(skip) + Number(limit));
    res.status(200).json(result);
});


app.post('/entities', authenticateJWT(['WRITE']), (req, res) => {
    const { name } = req.body;
    if (name) {
        // Simulated entity creation
        res.status(201).json({ id: Date.now(), name });
    } else {
        res.status(400).json({ message: 'Invalid input' });
    }
});

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
