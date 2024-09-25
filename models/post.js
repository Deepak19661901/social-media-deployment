const mongoose = require('mongoose')

const postSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'user' },
  content: String,
  postimg: String,
  likes: [{ type: mongoose.Schema.Types.ObjectId, ref: 'user' }],
  comments: [{ 
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'user' }, 
    text: String 
  }],
  createdAt: { type: Date, default: Date.now },
});

module.exports= mongoose.model('post',postSchema)