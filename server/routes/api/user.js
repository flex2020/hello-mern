const express = require('express');
const router = express.Router();
const { check, validationResult } = require('express-validator');
const User = require('../../model/User');
const gravatar = require('gravatar');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const config = require('config');

router.post('/', 
[ //--- 유효성 검사하는 부분
  check('name', 'Name is required.').not().isEmpty(),
  check('email', 'Please enter your email.').not().isEmpty(),
  check('password', 'Please enter a password with 8 or more').isLength({
    min: 8,
  }),

],

async (req, res) => {
  const errors = validationResult(req);
  if(!errors.isEmpty()) {
    return res.status(400).json({
      errors: errors.array()
    })
  }
    const { name, email, password } = req.body;
    
    try {
      // 유저가 존재하는 지 확인
      let user = await User.findOne({ email });
      if(user) {
        return res.status(400).json({
          errors: [{
            msg: 'User already exists.'
          }]
        });
      }
      // 유저의 아바타(프로필 사진)
      const avatar = gravatar.url(email, {
        s: '200',
        r: 'pg',
        d: 'mm'
      });
      user = new User({
        name,
        email,
        avatar,
        password
      });
      // 비밀번호를 encrypt
      const salt = await bcrypt.genSalt(10);
      user.password = await bcrypt.hash(password, salt);
      await user.save();

      //jsonwebtoken return
      const payload = {
        user: {
          id: user.id
        }
      }
      jwt.sign(payload,
        config.get('jwtSecret'),
        { expiresIn: 3600 },
        (err, token) => {
          if(err) throw err;
          res.json({
            token
          })
        }
        )

    } catch (err) {
      console.error(err.message);
      res.status(500).send('Server error');
    }
});

module.exports = router;