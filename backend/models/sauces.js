const mongoose = require('mongoose');

// Shema de DB des sauces
const sauceSchema = mongoose.Schema({
  userId: { type: String },
  name: { type: String, required: true },
  manufacturer: {
    type: String,
    maxlength: [50],
    required: true,
    match: /^[^@&*";?#/\$=*<>]+$/g
  },
  description: {
    type: String,
    maxlength: [350],
    required: true,
    match: /^[^@&*";?#/\$=*<>]+$/g
  },
  mainPepper: {
    type: String,
    maxlength: [50],
    required: true,
    match: /^[^@&*";?#/\$=*<>]+$/g
  },
  imageUrl: { type: String, required: true },
  heat: { type: Number, required: true },
  likes: { type: Number },
  dislikes: { type: Number },
  usersLiked: { type: Array },
  usersDisliked: { type: Array }
});

module.exports = mongoose.model('Sauce', sauceSchema);
