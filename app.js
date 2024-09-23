const express = require('express')
const userModel = require('./models/user')
const postModel = require('./models/post')
const jwt = require('jsonwebtoken')
const bcrypt = require('bcrypt')
const cookieParser = require('cookie-parser')
const path = require('path')
const app = express()
const upload = require('./config/multerconfig')
const uploadpostimg = require('./config/createpostmulterconfig')

// Set view engine
app.set('view engine', 'ejs')

// Middleware
app.use(express.json())
app.use(express.urlencoded({ extended: true }))
app.use(cookieParser())
app.use(express.static(path.join(__dirname,'public')))

// API

// Home route
app.get('/', (req, res) => {
  res.render('index')
})

// Create user
app.post('/create', async (req, res) => {
  let { username, name, email, password } = req.body
  let user = await userModel.findOne({ email })

  // User is already created
  if (user) return res.send('User already created')

  bcrypt.genSalt(10, (err, salt) => {
    if (err) return res.send('Error while generating salt', err.message)
    
    bcrypt.hash(password, salt, async (err, hash) => {
      if (err) return res.send('Something went wrong')
      
      let createdUser = await userModel.create({
        email: email,
        password: hash,
        username: username,
        name: name
      })

      const token = jwt.sign({ email: email, username: username }, 'secret-key', {
        expiresIn: '1d' // Token expires in 1 day
      })

      res.cookie('token', token, {
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000, // 1 day
        sameSite: 'strict'
      })

      // Redirect to profile after creating the user
      res.redirect('/profile')
    })
  })
})

// Render login form
app.get('/loginuser', (req, res) => {
  res.render('login')
})

// Login user
app.post('/profile', async (req, res) => {
  let { email, password } = req.body
  let user = await userModel.findOne({ email })

  if (!user) return res.redirect('/')

  bcrypt.compare(password, user.password, (err, result) => {
    if (err) return res.send('Something went wrong')
    if (!result) return res.send('Invalid credentials')

    const token = jwt.sign({ email: email }, 'secret-key', {
      expiresIn: '1d'
    })

    res.cookie('token', token, {
      httpOnly: true,
      maxAge: 24 * 60 * 60 * 1000,
      sameSite: 'strict'
    })

    // Redirect to profile after login
    res.redirect('/profile')
  })
})

// Logout user
app.get('/logout', (req, res) => {
  res.clearCookie('token')
  res.redirect('/')
})

// Middleware to check if the user is logged in
const isLoggedIn = (req, res, next) => {
  const token = req.cookies.token

  if (!token) {
    return res.redirect('/loginuser')
  }

  jwt.verify(token, 'secret-key', async (err, decode) => {
    if (err) {
      return res.redirect('/loginuser')
    }
    req.user = decode // Add user data to request object
    next()
  })
}

// Profile route
app.get('/profile', isLoggedIn, async (req, res) => {
  const userData = await userModel.findOne({ email: req.user.email }).populate("posts")
  
  res.render('profile', { user: userData })
})

app.post('/createpost',uploadpostimg.single('uploadpostimg'),isLoggedIn,async(req,res)=>{
  let user = await userModel.findOne({email:req.user.email})
 
  
  let {content} = req.body
  let post = await postModel.create({  // post create by the user
    user:user._id,
    content:content,
    postimg:req.file.filename
  })
  // now add post id of that particular user
  user.posts.push(post._id);
  await user.save();

  res.redirect('/profile')

})

// Logic for the like functionality



app.get('/like/:id', isLoggedIn, async (req, res) => {
  // Find the logged-in user
  const loginUser = await userModel.findOne({ email: req.user.email });

  // Find the post by ID
  const post = await postModel.findOne({ _id: req.params.id }).populate('user');
  
  // Check if the logged-in user has already liked the post
  const likeIndex = post.likes.indexOf(loginUser._id);

  if (likeIndex === -1) {
    // If not liked, add the logged-in user's ID to the likes array
    post.likes.push(loginUser._id);
  } else {
    // If already liked, remove the user's ID from the likes array
    post.likes.splice(likeIndex, 1);
  }

  // Save the updated post
  await post.save();

  // Redirect back to the referrer (page where the request came from)
  const referer = req.get('referer');
  if (referer.includes('/allpost')) {
    res.redirect('/allpost');
  } else if (referer.includes('/profile')) {
    res.redirect('/profile');
  } else {
    res.redirect('/'); // Fallback redirect
  }
});


// Edit logic for the like functionality

app.get('/edit/:id',isLoggedIn,async(req,res)=>{
    const editPost = await postModel.findOne({_id:req.params.id})
    res.render('edit',{'editdata':editPost})
})

app.post('/update/:id',isLoggedIn,async(req,res)=>{
  let {content} = req.body
  console.log(req.params.id)
  console.log(content)
  await postModel.findByIdAndUpdate({_id:req.params.id},{content:content},{new:true})
  res.redirect('/profile')
})


// profile  page add

app.get('/editprofile',isLoggedIn,(req,res)=>{
  res.render('editprofile')
})

//profile  image pic
app.post('/updateprofilepic', upload.single('image'),isLoggedIn, async (req, res) => {
  try {
  
    // console.log(req.file.filename)
    const user = await userModel.findOne({ email: req.user.email });

    user.profilepic = req.file.filename; 
    
    await user.save(); 
    res.redirect('/profile');
  } catch (err) {
    console.error(err);
    res.status(500).send('An error occurred while uploading the profile picture');
  }
});

// allpost

app.get('/allpost',isLoggedIn,async(req,res)=>{
   const loginUser = await userModel.findOne({email:req.user.email})
  //  console.log(user)
   const allpost = await postModel.find().populate('user');
   console.log(allpost)
   res.render('allpost',{allpost,loginUser})
})

app.listen(3000, () => {
  console.log('Server is connected...')
})
