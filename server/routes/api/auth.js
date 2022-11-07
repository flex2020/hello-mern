const express = require('express');
const router = express.Router();
const auth = require('../../middleware/auth');
const { check, validationResult } = require('express-validator');
const User = require('../../model/User');
const gravatar = require('gravatar');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const config = require('config');

router.get('/', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password');
    res.json(user);
  } catch(err) {
    console.error(err.message);
    res.status(500).send('Server Error');
  }
});

router.post('/', 
[ //--- 유효성 검사하는 부분
  check('email', 'Please enter your email.').isEmail(),
  check('password', 'Please enter a password with 8 or more').exists()
],
async (req, res) => {
  const errors = validationResult(req);
  if(!errors.isEmpty()) {
    return res.status(400).json({
      errors: errors.array()
    })
  }
    const { email, password } = req.body;
    
    try {
      // 유저가 존재하는 지 확인
      let user = await User.findOne({ email });
      if(!user) {
        return res.status(400).json({
          errors: [{
            msg: 'User is not exist.'
          }]
        });
      }
      
      const isMatch = await bcrypt.compare(password, user.password);
      if(!isMatch) {
        return res.status(400).json({
          errors: [{
            msg: 'User is not exist.'
          }]
        });
      }
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