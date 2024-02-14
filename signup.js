const express = require('express');
const app = express();
const mysql = require('mysql2');
const jwt = require('jsonwebtoken');
let session = require('express-session');
const bcrypt = require('bcrypt');
let passport = require('passport');
//let FacebookStrategy = require('passport-facebook').Strategy;
let GoogleStrategy = require('passport-google-oauth20').Strategy;
const port = 3010;




const cred = {host: 'localhost', port: 3306, user: 'root', password: 'root12', database: 'loginportal'};
const con = mysql.createConnection({...cred, database: 'loginportal', dateStrings: true});

const pool = mysql.createPool(cred);

app.use(express.json());
// Connect to MySQL
con.connect((err) => {
    if (err) {
        throw err;
    }
    console.log('Connected to MySQL');
});

app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));


// Signup with visible password

app.post('/signup', (req, res) => {
    res.setHeader('Content-Type', 'application/json');
    const { firstname, lastname, username, password, conpass, phonenumber } = req.body;
    console.log(firstname, lastname, username, password, conpass,   phonenumber);
    
    //Check if passwords match
    if (password !== conpass) {
        return res.status(400).send('Passwords do not match');
    }

    //Insert user data into MySQL
    const sql = 'INSERT INTO user ( firstname, lastname, username, password, conpass, phonenumber) VALUES (?, ?, ?, ?, ?, ?)';
    con.query(sql, [firstname, lastname, username, password, conpass, phonenumber], (err, result) => {
        if (err) {
            return res.status(500).send('Error inserting user data into database');
        }
        console.log('User registered:', result);
        res.send('Signup successful!');
    });
});


// Signup with hash password
app.post('/signupsecure', async (req, res) => {
    res.setHeader('Content-Type', 'application/json');
    const { firstname, lastname, username, password, conpass, phonenumber } = req.body;

    console.log(firstname, lastname, username, password, conpass, phonenumber);

    // Check if passwords match
    if (password !== conpass) {
        return res.status(400).json({ error: 'Passwords do not match' });
    }

    try {
        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Insert user data into MySQL with hashed password
        const sql = `INSERT INTO user (firstname, lastname, username, password, conpass, phonenumber) VALUES (?, ?, ?, ?, ?, ?)`;
        con.query(sql, [firstname, lastname, username, hashedPassword, hashedPassword, phonenumber], (err, result) => {
            if (err) {
                console.error('Error inserting user data into database:', err);
                return res.status(500).json({ error: 'Error inserting user data into database' });
            }
            console.log('User registered:', result);
            res.json({ message: 'Signup successful', userId: result.insertId });
        });
    } catch (error) {
        console.error('Error hashing password:', error);
        res.status(500).json({ error: 'Error hashing password' });
    }
});

// Login route
app.post('/login', async (req, res) => {
    // Extract username and password from request body
    const { username, password } = req.body;

    try {
        console.log('Database connected');
        // Check if user exists in the database
        const [rows] = await pool.promise().query('SELECT * FROM user WHERE username = ?', [username]);

        // If user not found, return error
        if (rows.length === 0) {
            return res.status(401).json({ error: 'Invalid username / password' });
        }
        console.log('Data fetched successfully');
        // Compare password with hashed password stored in the database
        const match = await bcrypt.compare(password, rows[0].password);
        console.log('Data password decrypted successfully');
        // If passwords match, generate JWT token
        if (match) {
            const token = jwt.sign({ username: username }, '605003', { expiresIn: '1h' });
            return res.json({ token: token });
            
        } 
        
        else {
            // If passwords don't match, return error
            return res.status(401).json({ error: 'Invalid data' });
            
        }
    } 
    catch (error) {
        console.error('Error during login:', error);
        return res.status(500).json({ error: 'Internal server error' });
        
    }
});


const verifyToken = (req, res, next) => {
    const token = req.headers.authorization;

    if (!token) {
        return res.status(401).json({
            
            message: 'Access Denied! Unauthorized User'
        });
    }

    const tokenString = token.slice(7); // Remove 'Bearer ' from the beginning of the token

    jwt.verify(tokenString, '605003', (err, decoded) => {
        if (err) {
            return res.status(401).json({
                
                message: 'Invalid Token'
            });
        }

        req.decoded = decoded;
        next();
    });
};


// Route to get user information using token
app.get('/user', verifyToken, async (req, res) => {
    try {
        // Extract username from decoded token
        const { uid } = req.body;

        // Query the database to get user information
        const [rows] = await pool.promise().query(`SELECT * FROM user WHERE uid = ?`, [uid]);

        // If user not found, return error
        if (rows.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Return user information
        return res.json(rows[0]); // Assuming the user information is stored in the first row of the result
    } catch (error) {
        console.error('Error retrieving user information:', error);
        return res.status(500).json({ error: 'Internal server error' });
    }
});


// Update the user information

app.put('/update/uid', verifyToken, (req, res) => {
    res.setHeader('Content-Type', 'application/json');
    const { firstname, lastname, username, password, conpass, phonenumber } = req.body;
    const { uid } = req.params; // Extract uid from URL parameters
    
    // Check if passwords match
    if (password !== conpass) {
        return res.status(400).json({ error: 'Passwords do not match' });
    }

    // Update user data in MySQL
    const sql = 'UPDATE user SET firstname = ?, lastname = ?, username = ?, password = ?, conpass = ?, phonenumber = ? WHERE uid = ?';
    con.query(sql, [firstname, lastname, username, password, conpass, phonenumber, uid], (err, result) => {
        if (err) {
            console.error('Error updating user data in database:', err);
            return res.status(500).json({ error: 'Error updating user data in database' });
        }
        console.log('User updated:', result);
        res.json({ message: 'Update successful' });
    });
});


// Delete the user information
app.delete('/delete', verifyToken, (req, res) => {
    const uid = req.body.uid;

  
    // Connect to the database
    con.connect(err => {
      try {
        if (err) throw err;
        console.log('Database connected');
  
        const deleteQuery = 'DELETE FROM user WHERE uid=?';
        con.query(deleteQuery, [uid], (err, result) => {
          try {
            if (err) throw err;
  
            res.json({ message: 'User deleted successfully' });
          } catch (ex) {
            console.error('Error deleting user:', ex);
            res.status(500).json({ error: 'Internal server error' });
          }
        });
      } catch (ex) {
        console.error('Error connecting to database:', ex);
        res.status(500).json({ error: ' server error' });
      } 
    });
  });


// Google Authentication
app.use(session({
    secret: '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',
    resave: false,
    saveUninitialized: true
  }));


app.use(passport.initialize());
app.use(passport.session());

// Google OAuth2 configuration
passport.use(new GoogleStrategy({
    clientID: '563580321359-rfius56jnbkh4k7o4r7987c0opmhat04.apps.googleusercontent.com',
    clientSecret: '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',
    callbackURL: 'http://localhost:3010/auth/google/callback'
  },
  function(accessToken, refreshToken, profile, done) {
    // You can perform actions after successful authentication here
    return done(null, profile);
  }
));

// Serialize user
passport.serializeUser(function(user, done) {
  done(null, user);
});

// Deserialize user
passport.deserializeUser(function(obj, done) {
  done(null, obj);
});

// Google authentication route
app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] }));

// Google authentication callback route
app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect or respond as needed
    res.redirect('/');
  });
  app.get('/', (req, res) => {
    res.send('<a href="/auth/google">Authenticate with Google</a><br/><br/><a href="/auth/facebook">Login with Facebook</a>');
  });
  

app.listen(port, () => {
    console.log(`Server is listening at http://localhost:${port}`);
});
