const express = require('express');
const userModel = require('./models/user');
const postModel = require('./models/post');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const cookieParser = require('cookie-parser');
const path = require('path');
const app = express();
const upload = require('./config/multerconfig');
const uploadpostimg = require('./config/createpostmulterconfig');

// Set view engine
app.set('view engine', 'ejs');

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// Home route
app.get('/', (req, res) => {
  res.render('index');
});

// Create user
app.post('/create', async (req, res) => {
  let { username, name, email, password } = req.body;
  let user = await userModel.findOne({ email });

  if (user) return res.send('User already created');

  bcrypt.genSalt(10, (err, salt) => {
    if (err) return res.send('Error while generating salt', err.message);
    
    bcrypt.hash(password, salt, async (err, hash) => {
      if (err) return res.send('Something went wrong');

      let createdUser = await userModel.create({
        email,
        password: hash,
        username,
        name
      });

      const token = jwt.sign({ email, username }, 'secret-key', {
        expiresIn: '1d'
      });

      res.cookie('token', token, {
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000, // 1 day
        sameSite: 'strict'
      });

      res.redirect('/profile');
    });
  });
});

// Render login form
app.get('/loginuser', (req, res) => {
  res.render('login');
});

// Login user
app.post('/profile', async (req, res) => {
  let { email, password } = req.body;
  let user = await userModel.findOne({ email });

  if (!user) return res.redirect('/');

  bcrypt.compare(password, user.password, (err, result) => {
    if (err) return res.send('Something went wrong');
    if (!result) return res.send('Invalid credentials');

    const token = jwt.sign({ email }, 'secret-key', {
      expiresIn: '1d'
    });

    res.cookie('token', token, {
      httpOnly: true,
      maxAge: 24 * 60 * 60 * 1000,
      sameSite: 'strict'
    });

    res.redirect('/profile');
  });
});

// Logout user
app.get('/logout', (req, res) => {
  res.clearCookie('token');
  res.redirect('/');
});

// Middleware to check if the user is logged in
const isLoggedIn = (req, res, next) => {
  const token = req.cookies.token;

  if (!token) {
    return res.redirect('/loginuser');
  }

  jwt.verify(token, 'secret-key', (err, decode) => {
    if (err) {
      return res.redirect('/loginuser');
    }
    req.user = decode;
    next();
  });
};

// Profile route
app.get('/profile', isLoggedIn, async (req, res) => {
  const userData = await userModel.findOne({ email: req.user.email }).populate('posts');
  res.render('profile', { user: userData });
});

// Create post
app.post('/createpost', uploadpostimg.single('uploadpostimg'), isLoggedIn, async (req, res) => {
  let user = await userModel.findOne({ email: req.user.email });
  let { content } = req.body;
  let post = await postModel.create({
    user: user._id,
    content,
    postimg: req.file.filename
  });
  user.posts.push(post._id);
  await user.save();
  res.redirect('/profile');
});

// Like functionality
app.get('/like/:id', isLoggedIn, async (req, res) => {
  const loginUser = await userModel.findOne({ email: req.user.email });
  const post = await postModel.findOne({ _id: req.params.id }).populate('user');
  const likeIndex = post.likes.indexOf(loginUser._id);

  if (likeIndex === -1) {
    post.likes.push(loginUser._id);
  } else {
    post.likes.splice(likeIndex, 1);
  }
  await post.save();
  res.redirect(req.get('referer'));
});

// Edit post
app.get('/edit/:id', isLoggedIn, async (req, res) => {
  const editPost = await postModel.findOne({ _id: req.params.id });
  res.render('edit', { editdata: editPost });
});

app.post('/update/:id', isLoggedIn, async (req, res) => {
  let { content } = req.body;
  await postModel.findByIdAndUpdate({ _id: req.params.id }, { content }, { new: true });
  res.redirect('/profile');
});

// Edit profile page
app.get('/editprofile', isLoggedIn, (req, res) => {
  res.render('editprofile');
});

// Profile picture upload
app.post('/updateprofilepic', upload.single('image'), isLoggedIn, async (req, res) => {
  const user = await userModel.findOne({ email: req.user.email });
  user.profilepic = req.file.filename;
  await user.save();
  res.redirect('/profile');
});

// View all posts
app.get('/allpost', isLoggedIn, async (req, res) => {
  const loginUser = await userModel.findOne({ email: req.user.email });
  const allpost = await postModel.find().populate('user');
  res.render('allpost', { allpost, loginUser });
});

// Add comment
app.post('/addcomment', isLoggedIn, async (req, res) => {
  const { comment, postId } = req.body;
  const loginUser = await userModel.findOne({ email: req.user.email });
  const newComment = {
    user: loginUser._id,
    text: comment,
  };
  const post = await postModel.findById(postId);
  post.comments.push(newComment);
  await post.save();
  res.redirect(req.get('referer'));
});

// Explore page (Follow functionality)
// Explore page (Follow functionality)
app.get('/explore', isLoggedIn, async (req, res) => {
  const email = req.user.email;
  const loggedInUser = await userModel.findOne({ email });
  const users = await userModel.find();
  const filteredUser = users.filter(user => user.email !== email);

  res.render('explore', { users: filteredUser, loggedInUser }); // Pass loggedInUser to the view
});


// Follow user
app.get('/follow/:id', isLoggedIn, async (req, res) => {
  try {
    const following_ID = req.params.id;
    const loggedInUser = await userModel.findOne({ email: req.user.email });
    console.log(loggedInUser)
    if (loggedInUser.following.includes(following_ID)) {
      return res.send('You are already following this user');
    }
    loggedInUser.following.push(following_ID);
    await loggedInUser.save();

    const followedUser = await userModel.findById(following_ID);
    followedUser.followers.push(loggedInUser._id);
    await followedUser.save();
    res.render('explore');
  } catch (err) {
    res.status(500).send('An error occurred while trying to follow the user');
  }
});

app.listen(3000, () => {
  console.log('Server is running on port 3000');
});
