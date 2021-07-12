const express = require('express');
const router = express.Router();
const userCtrl = require('../controllers/user');
const verifyPassword = require('../middleware/password');
const rateLimit = require('express-rate-limit');

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15M
  max: 100, // limit each IP to 100 requests per windowMs
  delayMs: 0 // disable delaying - full speed until the max limit is reached
});

router.post('/signup', verifyPassword, userCtrl.signup);
router.post('/login', limiter, userCtrl.login);

module.exports = router;
