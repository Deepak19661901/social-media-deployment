const mongoose = require('mongoose')

const userSchema = mongoose.Schema({

    username:String,
    name:String,
    email:String,
    password:String,
    posts:[
      {
        type:mongoose.Schema.Types.ObjectId,
        ref:'post'
      }
    ],
    profilepic:{
      type:String,
      default:'defaultimg.jpg'
    }
    ,
    following:[  // Jisko hm follow krte h
      {
        type:mongoose.Schema.Types.ObjectId,
        ref:'user'
      }
    ]
    ,
    followers:[   // jo hmko follow krta hai
      {
        type:mongoose.Schema.Types.ObjectId,
        ref:'user'
      }
    ],
    bio: {
    type: String,
    default: ''
  },

})

module.exports = mongoose.model('user',userSchema)

