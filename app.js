const express = require('express')
const mysql = require('mysql')
const { createPool } = require('mysql')
const cors = require('cors')
const dotenv = require('dotenv');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');

dotenv.config({path: './.env'});

const app = express();
app.use(cors());
app.use(bodyParser.json());

const db = mysql.createPool({
    host: process.env.DATABASE_HOST,
    user: process.env.DATABASE_USER, 
    password: process.env.DATABASE_PASSWORD, 
    database: process.env.DATABASE,
    connectionLimit: 10,
});

db.on('connection', (connection) => {
    console.log('New database connection established');
});

db.on('error', (error) => {
    console.error('Error in database connection:', error);
});

app.post('/signup', (req, res) => {

    const { fname, lname, email, password } = req.body;

    db.query('SELECT * FROM users WHERE email = ?', [email], async (error, results) => {
        if(error){
            console.error('Error checking preexistence of email : ', error);
            res.status(500).json({ success : false, message : 'failed to check for preexistence of email'});
        } else {
            if(results.length > 0){
                // this email already exists
                console.error('Error: User already registered');
                res.status(409).json({ success : false, message : 'User already registered'});
            } else {
                await bcrypt.hash(password, 10, (error, hash)=>{

                    if(error){

                        console.error('Error generating hash: ', error);
                        res.status(500).json({ success: false, message : 'Error Generating Hash'});

                    } else {

                        const query = 'INSERT INTO users (fname, lname, email, password) VALUES (?, ?, ?, ?)';
                        db.query(query, [fname, lname, email, hash], (error, results)=>{
                            if(error){
                                console.error('Error Inserting User: ', error);
                                res.status(500).json({ success : false, message : 'Error Inserting User' });
                            } else {
                                console.log('User Inserted successfully');
                                res.status(201).json({ success: true, message: 'User Inserted Successfully' })
                            }
                        })
                    }
                });

                
            }   
        }
    })
})

app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    const query = 'SELECT * FROM users WHERE email = ?';
    
    await db.query(query, [email], async (error, results) => {
        if (error) {
            console.error('Error executing login query: ', error);
            res.status(500).json({ success: false, message: 'Internal Server Error' });
        } else {
            if (results.length > 0) {
                // User with the provided email id exists, now check if the password is valid 
                // console.log(results[0]);
                await bcrypt.compare(password, results[0].password, (errormatch, passwordmatch)=>{
                    if(errormatch){
                        res.status(401).json({ success: false, message: 'invalid credentials'});
                    } else {
                        // no error, that means password has been matched
                        res.status(200).json({ success: true, message: 'Login successful', welcomeMsg : 'Welcome ' + results[0].fname.toUpperCase() + '!'});
                    }
                })
            } else {
                // Invalid credentials
                res.status(401).json({ success: false, message: 'Invalid credentials' });
            }
        }
    });
});



app.listen(process.env.PORT || 5000, (req, res)=>{
    console.log(`Server started on Port ${process.env.PORT || 5000}`)
})