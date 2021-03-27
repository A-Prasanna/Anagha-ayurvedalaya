const express = require ('express');

const auth = require('../../middleware/auth');

const config = require('config');

const {check, validationResult} = require('express-validator');

const router = express.Router();

const authh =  require('../../middleware/auth');

const User = require('../../models/User')

const jwt = require('jsonwebtoken');

const bcrypt = require('bcryptjs');

//@route  GET api/auth
//@desc   test route
//@acess  public
router.get('/',auth, async (req, res) => {
    try{
        const user = await User.findById(req.user.id).select('-password');
        res.json(user);
    }
    catch(err){
        console.error(err.message);
        res.status(500).send('server error');
    }
});

//@route  POST api/auth
//@desc   Authenticate user & get token
//@acess  public
router.post('/', [
    check('email','please enter a valid email').isEmail(),
    check('password','password is required').exists()
],
    async function (req, res) {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const {  email, password } = req.body;

        try {
            //see if user exists
            let user = await User.findOne({ email });

            if (!user) {
                return res.status(400).json({ errors: [{ msg: 'User doesnt exist '}] });
            }   

            const isMatch = await bcrypt.compare(password, user.password);

            if(!isMatch) {
                return res.status(400).json({ errors: [{ msg: 'Invalid credentials' }] });
            }

            //return son webtoken
            const payload = {
                user : {
                    id: user.id
                }
            };
            jwt.sign(
                payload, 
                config.get('jwtSecret'), 
                {expiresIn : 36000},
                (err,token) => {
                    if (err) throw err;
                    res.json({ token });
                }
            );
        }

        catch (err) {
            console.error(err.message);
            res.status(500).send('server error');
        }
    }
);
module.exports= router;