import express from 'express';
import db from '../db/index.js';
import { usersTable} from '../db/schema.js';
import { eq } from 'drizzle-orm';
import { createHmac, randomBytes } from 'node:crypto';
import jwt from 'jsonwebtoken';
import { ensureAuthenticated } from '../middlewares/auth.middleware.js';


const router = express.Router()

router.patch('/', ensureAuthenticated, async (req,res) => {
    const user = req.user;

    // if(!user) {
    //     return res.status(400).json({error: `You are not logged In`});
    // }

    const {name} = req.body;

    await db.update(usersTable).set({name}).where(eq(usersTable.id, user.id))

    return res.json({status: 'success'})

})

router.get('/', ensureAuthenticated, async (req, res) => {
    const user = req.user;
    // if(!user) {
    //     return res.status(400).json({error: `You are not logged In`});
    // }
    const [updatedDetails] = await db.select({
        id: usersTable.id,
        name: usersTable.name,
        role: usersTable.role,
        email: usersTable.email
    }).from(usersTable).where(eq(usersTable.id, user.id))
    return res.json(updatedDetails)
    
})

router.post('/signup', async (req, res) => {
    const {name, email, password} = req.body ?? {};
    if (![name, email, password].every((value) => typeof value === 'string' && value.trim())) {
        return res.status(400).json({error: 'name, email, and password are required'})
    }

    try {
        const [existingUser] = await db
            .select({id: usersTable.id})
            .from(usersTable)
            .where(eq(usersTable.email, email))

        if (existingUser) {
            return res.status(400).json({error: `user with email ${email} already exists`})
        }

        const salt = randomBytes(256).toString('hex')
        const hashedPassword = createHmac('sha256', salt).update(password).digest('hex')
        const [user] = await db.insert(usersTable).values({
            name,
            email,
            password: hashedPassword,
            salt
        }).returning({id: usersTable.id})

        return res.status(201).json({status: "success", data: {userId: user.id}})
    } catch (error) {
        console.error('Signup failed:', error)
        return res.status(500).json({error: 'Unable to create user'})
    }
    
})

router.post('/login', async (req, res) => {
    const {email, password} = req.body;

    const [existingUser] = await db
            .select({
                id: usersTable.id,
                email: usersTable.email,
                name: usersTable.name,
                role: usersTable.role,
                salt: usersTable.salt,
                password: usersTable.password
            })
            .from(usersTable)
            .where(eq(usersTable.email, email))

    if (! existingUser) {
        return res.status(400).json({error: `user with email ${email} not exists`})
    }
    const salt = existingUser.salt
    const existingHashedPassword = existingUser.password;
    const newHashed = createHmac('sha256', salt).update(password).digest('hex')

    if(existingHashedPassword !== newHashed) {
        return res.status(400).json({error: `Incorrect password`})
    }

    // generate session for user
    // const [session] = await db.insert(userSession).values({
    //     userId:existingUser.id
    // }).returning({id: userSession.id})
    
    // return res.json({status: `Success`, sessionId: session.id})
    

    // JWT Based login
    const payload = {
        id: existingUser.id,
        email: existingUser.email,
        name: existingUser.name,
        role: existingUser.role,
    }

    const token = jwt.sign(payload, process.env.JWT_SECRET, {expiresIn: '1h'})
    return res.json({status: `Success`, token})
    
})

export default router;