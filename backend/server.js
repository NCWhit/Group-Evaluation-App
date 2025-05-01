const express = require('express')
const cors = require('cors')
const {v4:uuidv4} = require('uuid')
const sqlite3 = require('sqlite3').verbose()
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')

const strSecret = 'thisIsOurSecret'

const dbSource = "" /// Will need to be added once db is built
const HTTP_PORT = 8000
const db = new sqlite3.Database(dbSource)

var app = express()
app.use(cors())
app.use(express.json())

/*
    MAKE SURE TO INCLUDE the "verifyToken" function when building any routes to ensure user has a valid session.
*/


app.post('/register', (req, res, next) => {
    let strEmail = req.body.email.trim().toLowerCase()
    let strPassword = req.body.password
    let strFirstName = req.body.firstname
    let strLastName = req.body.lastname
    let strName = strFirstName + " " + strLastName

    // Email validation 
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(strEmail)) {
        return res.status(400).json({ error: "You must provide a valid email address" })
    }

    // Password validation 
    if (strPassword.length < 8) {
        return res.status(400).json({ error: "Password must be at least 8 characters long" })
    }
    if (!/[A-Z]/.test(strPassword)) {
        return res.status(400).json({ error: "Password must contain at least one uppercase letter" })
    }
    if (!/[a-z]/.test(strPassword)) {
        return res.status(400).json({ error: "Password must contain at least one lowercase letter" })
    }
    if (!/[0-9]/.test(strPassword)) {
        return res.status(400).json({ error: "Password must contain at least one number" })
    }
    if (!/[!@#$%^&*(),.?":{}|<>]/.test(strPassword)) {
        return res.status(400).json({ error: "Password must contain at least one special character" })
    }

    strPassword = bcrypt.hashSync(strPassword, intSalt)

    // Add the new user to the DB 
    let strCommand = `INSERT INTO tblUsers VALUES (?, ?, ?)`
    db.run(strCommand, [strEmail, strPassword, strName, "Active"], function (err) {
        if(err){
            console.log(err)
            res.status(400).json({
                status:"error",
                message:err.message
            })
        } else {
            res.status(201).json({
                status:"success"
            })
        }
    })
})

app.post('/login', (req, res, next) => {
    const strEmail = req.body.email.trim().toLowerCase()
    const strPassword = req.body.password

    if(strEmail,strPassword == null){
        return res.status(400).json({error:"Must provide an email and password"})
    }
    let strCommand = 'SELECT Password FROM tblUsers WHERE Email = ?'
    db.all(strCommand,[strEmail],(err,result) => {
        if(err){
            console.log(err)
            res.status(400).json({
                status:"error",
                message:err.message
            })
        } else {
            if(result.length == 0){
                return res.status(401).json({error:"Invalid email or password"})
            } else {
                let strHash = result[0].Password
                if(bcrypt.compareSync(strPassword,strHash)){  /// If password match create session and JWT
                    let strSessionID = uuidv4()
                    let strCommand = 'INSERT INTO tblSessions VALUES (?,?,?)'
                    let datNow = new Date()
                    let strNow = datNow.toISOString()
                    db.run(strCommand,[strSessionID,strEmail,strNow],function(err,result){
                        if(err){
                            console.log(err)
                            res.status(400).json({
                                status:"error",
                                message:err.message
                            })
                        } else {

                            const strToken = jwt.sign({username:strEmail,sessionid:strSessionID,permissions:"admin"},strSecret, {expiresIn:'12h'})
                            res.status(201).json({strToken})
                        }
                    })
                } else {
                    res.status(401).json({error:"Invalid email or password"})
                }
            }
        }
    })
})

function verifyToken(req,res,next){ /// Make sure to include verify token for any routes
    const strToken = req.headers.authorization.split(' ')[1]
    if(strToken == null){
        return res.status(401).json({error:"You must have an active session to perform this function"})
    }
    jwt.verify(strToken,strSecret,(err,decoded) => {
        if(err){
            return res.status(401).json({error:"Invalid session identifier"})
        } else {
            req.user = decoded
            next()
        }
    })
}