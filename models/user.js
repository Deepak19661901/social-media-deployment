const mongoose = require('mongoose')

const userSchema = new mongoose.Schema({

  username: String,
  name: String,
  email: String,
  password: String,
  posts: [
    {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Post'
    }
  ],
  profilepic: {
    url: {
      type: String,
      default: "https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcT5x4ugT-l8K56rUtVOPDhJam2Hp5sRLQtyVQ&s"
    },
    public_id: String
  },
  following: [
    {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    }
  ],
  followers: [
    {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    }
  ],
  bio: {
    type: String,
    default: ''
  },

})

module.exports = mongoose.model('User', userSchema)

