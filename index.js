const express = require('express')
const cors = require('cors')
const cookieparser = require('cookie-parser')
const mysql = require('mysql2/promise')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const emailValidator = require('node-email-verifier')

// --- config ---
const PORT = 3000
const HOST = 'localhost'
const JWT_SECRET = 'jelszo'
const JWT_EXPIRES_IN = '7d'
const COOKIE_NAME = 'auth_token'


// --- cookie bealitas ---
const COOKIE_OPTS = {
    httpOnly: true,
    secure: false,
    sameSite: 'lax',
    path: '/',
    maxAge: 7 * 24 * 60 * 60 * 1000,

}

// --- adabazis bealitas ---
const db = mysql.createPool({
    host: 'localhost',
    user: 'root',
    password: '',
    database: 'szavazas'
})

// --- APP ---
const app = express()

app.use(express.json())
app.use(cookieparser())
app.use(cors({
    origin: '*',
    credentials: true
}))

// --- vegpontok ---

app.post('/regisztracio', async (req, res) => {
    const { email, felhasznalonev, jelszo, admin } = req.body
    if (!email || !felhasznalonev || !jelszo || !admin) {
        return res.status(400).json("hianyzo bemeneti adatok")
    }

    try {
        const isValid = await emailValidator(email)
        if (!isValid) {
            return res.status(401).json({ message: "nem valid email" })
        }

        const [exists] = await db.query('SELECT * FROM felhasznalok WHERE email = ? OR felhasznalonev = ?', [email, felhasznalonev])
        if (exists.length) {
            return res.status(402).json({ message: "az email vagy felhasznalo nev mar foglalt" })
        }

        const hash = await bcrypt.hash(jelszo, 10)
        const [result] = await db.query('INSERT INTO felhasznalok (email, felhasznalonev, jelszo, admin) VALUES(?,?,?,?', [email, felhasznalonev, hash, admin])

        return res.status(200).json({
            message: "sikeres regisztracio",
            id: result.insertId
        })
    } catch (error) {
        console.log(error)
        return res.status(500).json({ message: "szerverhiba" })
    }
})

app.post('/belepes', async (req, res) => {
    const { felhasznalonevVagyEmail, jelszo } = req.body
    if (!felhasznalonevVagyEmail || !jelszo) {
        return res.status(400).json({ message: "hianyos belepesi adatok" })
    }

    try {
        const isValid = await emailValidator(felhasznalonevVagyEmail)
        let hashJelszo = ""
        let user = {}
        if (isValid) {
            const [rows] = await db.query('SELECT * FROM felhasznalok WHERE email = ?', [felhasznalonevVagyEmail])
            if (rows.length) {
                user = rows[0]
                hashJelszo = user.jelszo
            } else {
                return res.status(401).json({ message: "ilyen fiok nem letezik" })
            }
        } else {
            const [rows] = await db.query('SELECT * FROM felhasznalok WHERE felhasznalonev = ?', [felhasznalonevVagyEmail])
            if (rows.length) {
                user = rows[0]
                hashJelszo = user.jelszo
            } else {
                return res.status(401).json({ message: "ilyen fiok nem letezik" })
            }
        }

        const ok = bcrypt.compare(jelszo, hashJelszo)
        if (!ok) {
            return res.status(403).json({ message: "rossz jelszot adtal meg" })
        }
        if (ok) {
            const token = jwt.sign(
                { id: user.id, email: user.email, felhasznalonev: user.felhasznalonev, admin: user.admin },
                JWT_SECRET,
                { expiresIn: JWT_EXPIRES_IN }
            )
            req.cookie(COOKIE_NAME, token, COOKIE_OPTS)
            res.status(200).json({ message: "sikeres belepes" })
        }
    } catch (error) {
        return res.status(500).json({ message: "Szerverhiba" })
    }
})

// vedett
app.get('/adataim', auth, async (req, res) => {

})





// --- szerver elinditasa ---
app.listen(PORT, HOST, () => {
    console.log(`api fut a: http://${HOST}:${PORT}/`)
})