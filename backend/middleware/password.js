const passValidator = require('../models/password');

module.exports = (req, res, next) => {
  if (!passValidator.validate(req.body.password)) {
    return res.status(400).json({
      error:
        'Votre mot de passe doit contenir une minuscule, une majuscule, 8 caractères min. 1 chiffre min.' +
        passValidator.validate('Indiquez un nouveau mot de passe', {
          list: true
        })
    });
  } else {
    next();
  }
};
