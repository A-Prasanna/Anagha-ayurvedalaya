const express = require ('express');

const router = express.Router();

const gravatar = require('gravatar');

const {check, validationResult} = require('express-validator');

const User = require('../../models/User');

const bcrypt = require('bcryptjs');

const jwt = require('jsonwebtoken');

const config = require('config');

//@route  POST api/users
//@desc   register user
//@acess  public
router.post('/', [
    check('name','name is required').not().isEmpty(),
    check('email','please enter a valid email').isEmail(),
    check('password','please enter a password with 5 or more characters').isLength({min:6})
],
    async function (req, res) {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const { name, email, password } = req.body;

        try {
            //see if user exists
            let user = await User.findOne({ email });

            if (user) {
                return res.status(400).json({ errors: [{ msg: 'User already exist' }] });
            }
            //get user gravatar
            const avatar = gravatar.url(email, {
                s: '200',
                r: 'pg',
                d: 'mm'
            });

            user = new User({ name, email, avatar, password });

            //encrypt password
            const salt = await bcrypt.genSalt(10);
            user.password = await bcrypt.hash(password, salt);
            await user.save();

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