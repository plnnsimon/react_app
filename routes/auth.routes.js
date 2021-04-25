const {Router} = require('express')
const {check, validationResult} = require('express-validator')
const config = require('config')
const jwt = require('jsonwebtoken')
const User = require('../models/User')
const bcrypt = require('bcryptjs')
const router = Router()

router.post(
    '/register', 
    [
        check('email', 'Invalid email').isEmail,
        check('password', 'Et least 8 characters').isLength({ min: 8 })
    ],
    async (req, res) => {
    try {
        const errors = validationResult(req)

        if (!errors.isEmpty()) {
            return res.status(400).json({
                errors: errors.array(),
                message: 'Invalid data at the registration'
            })
        }

        const {email, password} = req.body
        const candidate = await User.findOne({ email })
        if (candidate) {
            return res.status(400).json({ message: 'This user is already exist!' })
        }

        const hashedPassword = await bcrypt.hash(password, 12);
        const user = new User ({ email, password: hashedPassword })

        await user.save()

        res.status(201).json({ message: 'User has been created!' })

    } catch (e) {
        res.status(500).json({ message: 'Something wrong, try again!'})
    }
})

router.post(
    '/login', 
    [
        check('email', 'Enter the correct email').normalizeEmail().isEmail(),
        check('password', 'Enter password').exists()
    ],
    async (req, res) => {
    try {
        const errors = validationResult(req)

        if (!errors.isEmpty()) {
            return res.status(400).json({
                errors: errors.array(),
                message: 'Invalid data by entering in system'
            })
        }

        const {email, password} = req.body

        const user = await User.findOne({ email })
        if (!user) {
            return res.status(400).json({ message: 'User not found' })
        }

        const isMatch = await bcrypt.compare(password, user.password)
        if (!isMatch) {
            return res.status(400).json({ message: 'Incorrect password, try again' })
        }

        const token = jwt.sign(
            { userId: user.id },
            config.get('jwtSecret'),
            { expiresIn: '1h' }
        )

        res.json({ token, userId: user.id })


    } catch (e) {
        res.status(500).json({ message: 'Something wrong, try again!'})
    }
})

module.exports = router 