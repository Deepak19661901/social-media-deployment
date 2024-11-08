require('dotenv').config()
const mongoose = require('mongoose')
const express = require('express');
const userModel = require('./models/user');
const postModel = require('./models/post');
const messageModel = require('./models/message');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const cookieParser = require('cookie-parser');
const path = require('path');
const http = require('http');
const socketIo = require('socket.io');
const upload = require('./config/multerconfig');
const uploadpostimg = require('./config/createpostmulterconfig');
const crypto = require('crypto');
const fs = require('fs');
const { prototype } = require('stream');

const app = express();
const server = http.createServer(app);
const io = socketIo(server);


// DB Connection


mongoose.connect(process.env.MONGO_URL).then(() => {
  console.log("DB is Connected..")
}).catch((err) => {
  console.log("Some thing is Wrong while connecting DB ", err.message)
})

// Set view engine
app.set('view engine', 'ejs');

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// Encryption key management
const ENCRYPTION_KEY_FILE = path.join(__dirname, 'encryption_key.txt');
let ENCRYPTION_KEY;

if (fs.existsSync(ENCRYPTION_KEY_FILE)) {
  ENCRYPTION_KEY = Buffer.from(fs.readFileSync(ENCRYPTION_KEY_FILE, 'utf8'), 'hex');
} else {
  ENCRYPTION_KEY = crypto.randomBytes(32);
  fs.writeFileSync(ENCRYPTION_KEY_FILE, ENCRYPTION_KEY.toString('hex'));
}

const IV_LENGTH = 16;

function encrypt(text) {
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
  let encrypted = cipher.update(text);
  encrypted = Buffer.concat([encrypted, cipher.final()]);
  return iv.toString('hex') + ':' + encrypted.toString('hex');
}

function decrypt(text) {
  try {
    const textParts = text.split(':');
    const iv = Buffer.from(textParts.shift(), 'hex');
    const encryptedText = Buffer.from(textParts.join(':'), 'hex');
    const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
    let decrypted = decipher.update(encryptedText);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted.toString();
  } catch (error) {
    console.error('Decryption error:', error);
    return 'Error: Unable to decrypt message';
  }
}

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
  const userData = await userModel.findOne({ email: req.user.email }).populate('posts').populate('followers')
    .populate('following');

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
app.get('/editprofile', isLoggedIn, async (req, res) => {
  const user = await userModel.findOne({ email: req.user.email });
  res.render('editprofile', { user });
});

// Update profile
app.post('/editprofile', isLoggedIn, upload.single('profilepic'), async (req, res) => {
  try {
    const { name, bio } = req.body;
    const user = await userModel.findOne({ email: req.user.email });

    user.name = name;
    user.bio = bio;

    if (req.file) {
      user.profilepic = req.file.filename;
    }

    await user.save();
    res.redirect('/profile');
  } catch (err) {
    console.error(err);
    res.status(500).send('An error occurred while updating the profile');
  }
});

// View all posts
app.get('/allpost', isLoggedIn, async (req, res) => {
  try {
    const loginUser = await userModel.findOne({ email: req.user.email });
    const allpost = await postModel.find()
      .populate('user', 'username profilepic')
      .populate({
        path: 'comments',
        populate: {
          path: 'user',
          select: 'username'
        }
      })
      .sort('-createdAt');

    res.render('allpost', { allpost, loginUser });
  } catch (err) {
    console.error(err);
    res.status(500).send('An error occurred while loading posts');
  }
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

// Follow user
app.get('/follow/:id', isLoggedIn, async (req, res) => {
  try {
    const targetUserId = req.params.id;
    const loggedInUser = await userModel.findOne({ email: req.user.email });
    const targetUser = await userModel.findById(targetUserId);

    if (!targetUser) {
      return res.status(404).send('User not found');
    }

    const isFollowing = loggedInUser.following.includes(targetUserId);

    if (isFollowing) {
      // Unfollow
      loggedInUser.following = loggedInUser.following.filter(id => id.toString() !== targetUserId);
      targetUser.followers = targetUser.followers.filter(id => id.toString() !== loggedInUser._id.toString());
    } else {
      // Follow
      loggedInUser.following.push(targetUserId);
      targetUser.followers.push(loggedInUser._id);
    }

    await loggedInUser.save();
    await targetUser.save();

    res.redirect(req.get('referer') || '/followers');
  } catch (err) {
    console.error(err);
    res.status(500).send('An error occurred while trying to follow/unfollow the user');
  }
});

// Explore route
app.get('/explore', isLoggedIn, async (req, res) => {
  try {
    const email = req.user.email;
    const loggedInUser = await userModel.findOne({ email });
    const users = await userModel.find({ _id: { $ne: loggedInUser._id } });

    res.render('explore', { users, loggedInUser });
  } catch (err) {
    console.error(err);
    res.status(500).send('An error occurred while loading the explore page');
  }
});

// Followers route
app.get('/followers', isLoggedIn, async (req, res) => {
  try {
    const loggedInUser = await userModel.findOne({ email: req.user.email }).populate('followers');

    res.render('followers', {
      followusers: loggedInUser.followers,
      loggedInUser: loggedInUser
    });
  } catch (err) {
    console.error(err);
    res.status(500).send('An error occurred while fetching followers');
  }
});

// Following route
app.get('/following', isLoggedIn, async (req, res) => {
  try {
    const loggedInUser = await userModel.findOne({ email: req.user.email }).populate('following');

    res.render('following', {
      followingusers: loggedInUser.following,
      loggedInUser: loggedInUser
    });
  } catch (err) {
    console.error(err);
    res.status(500).send('An error occurred while fetching following users');
  }
});

// Chat list route
app.get('/chat-list', isLoggedIn, async (req, res) => {
  try {
    const loggedInUser = await userModel.findOne({ email: req.user.email })
      .populate('followers')
      .populate('following');

    const chatUsers = [...loggedInUser.followers, ...loggedInUser.following]
      .filter((user, index, self) =>
        index === self.findIndex((t) => t._id.toString() === user._id.toString())
      );

    res.render('chat-list', { chatUsers, loggedInUser });
  } catch (err) {
    console.error(err);
    res.status(500).send('An error occurred while fetching chat list');
  }
});

// Individual chat route
app.get('/chat/:userId', isLoggedIn, async (req, res) => {
  try {
    const loggedInUser = await userModel.findOne({ email: req.user.email });
    const chatPartner = await userModel.findById(req.params.userId);

    if (!chatPartner) {
      return res.status(404).send('User not found');
    }

    const chatHistory = await messageModel.find({
      $or: [
        { sender: loggedInUser._id, receiver: chatPartner._id },
        { sender: chatPartner._id, receiver: loggedInUser._id }
      ]
    }).sort('timestamp');

    const decryptedChatHistory = chatHistory.map(message => {
      try {
        return {
          ...message.toObject(),
          text: decrypt(message.encryptedText)
        };
      } catch (error) {
        console.error('Error decrypting message:', error);
        return {
          ...message.toObject(),
          text: 'Error: Unable to decrypt message'
        };
      }
    });

    res.render('chat', { loggedInUser, chatPartner, chatHistory: decryptedChatHistory });
  } catch (err) {
    console.error(err);
    res.status(500).send('An error occurred while loading the chat');
  }
});

// Delete post
app.get('/deletepost/:id', isLoggedIn, async (req, res) => {
  try {
    const post = await postModel.findById(req.params.id);
    if (!post) {
      return res.status(404).send('Post not found');
    }

    const user = await userModel.findOne({ email: req.user.email });

    // Check if the logged-in user is the owner of the post
    if (post.user.toString() !== user._id.toString()) {
      return res.status(403).send('You are not authorized to delete this post');
    }

    await postModel.findByIdAndDelete(req.params.id);

    // Remove the post from the user's posts array
    user.posts = user.posts.filter(postId => postId.toString() !== req.params.id);
    await user.save();

    res.redirect('/profile');
  } catch (err) {
    console.error(err);
    res.status(500).send('An error occurred while deleting the post');
  }
});

// Delete account
app.get('/deleteaccount', isLoggedIn, async (req, res) => {
  try {
    const user = await userModel.findOne({ email: req.user.email });

    // Delete all posts by the user
    await postModel.deleteMany({ user: user._id });

    // Remove user from followers and following lists of other users
    await userModel.updateMany(
      { $or: [{ followers: user._id }, { following: user._id }] },
      { $pull: { followers: user._id, following: user._id } }
    );

    // Delete the user
    await userModel.findByIdAndDelete(user._id);

    res.clearCookie('token');
    res.redirect('/');
  } catch (err) {
    console.error(err);
    res.status(500).send('An error occurred while deleting the account');
  }
});

// Socket.IO connection handling
io.on('connection', (socket) => {
  socket.on('join', ({ userId, chatPartnerId }) => {
    const roomId = [userId, chatPartnerId].sort().join('_');
    socket.join(roomId);
  });

  socket.on('chat message', async (message) => {
    try {
      if (!message.text) {
        throw new Error('Message text is empty');
      }
      const encryptedText = encrypt(message.text);
      const newMessage = new messageModel({
        sender: message.sender,
        receiver: message.receiver,
        encryptedText: encryptedText
      });
      await newMessage.save();

      const roomId = [message.sender, message.receiver].sort().join('_');
      io.to(roomId).emit('chat message', {
        ...newMessage.toObject(),
        text: message.text // Send the original text for immediate display
      });
    } catch (error) {
      console.error('Error saving message:', error);
    }
  });
});

// Start the server
const PORT = process.env.PORT || 3000
server.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});