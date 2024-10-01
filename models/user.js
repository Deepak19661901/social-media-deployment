const mongoose = require('mongoose')


mongoose.connect('mongodb://127.0.0.1:27017/instagram').then(()=>{
  console.log("DB is Connected..")
}).catch((err)=>{
  console.log("Some thing is Wrong while connecting DB ",err.message)
})

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

