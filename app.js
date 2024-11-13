
require('dotenv').config()
const mongoose = require('mongoose')
const express = require('express');
const User = require('./models/user');
const Post = require('./models/post');
const Message = require('./models/message');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const cookieParser = require('cookie-parser');
const path = require('path');
const http = require('http');
const socketIo = require('socket.io');
const crypto = require('crypto');
const fs = require('fs');
const { handleUpload, cloudinary } = require('./config/cloudinaryConfig');
const { prototype } = require('stream');
const multer = require('multer');

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
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));
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
  let user = await User.findOne({ email });

  if (user) return res.send('User already created');

  bcrypt.genSalt(10, (err, salt) => {
    if (err) return res.send('Error while generating salt', err.message);

    bcrypt.hash(password, salt, async (err, hash) => {
      if (err) return res.send('Something went wrong');

      let createdUser = await User.create({
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
  let user = await User.findOne({ email });

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
  try {
    const user = await User.findOne({ email: req.user.email })
      .populate({
        path: 'posts',
        options: { sort: { 'createdAt': -1 } }
      });

    res.render('profile', { user });
  } catch (error) {
    console.error('Profile error:', error);
    res.status(500).send('Error loading profile');
  }
});

// Create post
app.post('/createpost', isLoggedIn, async (req, res, next) => {
  req.uploadField = 'uploadpostimg';
  handleUpload(req, res, async (err) => {
    if (err) return next(err);

    try {
      if (!req.file) {
        return res.status(400).send('Please upload an image');
      }

      const user = await User.findOne({ email: req.user.email });

      const post = await Post.create({
        user: user._id,
        content: req.body.content,
        postimg: {
          url: req.file.path,
          public_id: req.file.filename
        }
      });

      user.posts.push(post._id);
      await user.save();
      res.redirect('/profile');
    } catch (error) {
      console.error('Post creation error:', error);
      if (req.file && req.file.filename) {
        await cloudinary.uploader.destroy(req.file.filename);
      }
      res.status(500).send('Error creating post: ' + error.message);
    }
  });
});

// Like functionality
app.post('/like/:id', isLoggedIn, async (req, res) => {
  try {
    const loginUser = await User.findOne({ email: req.user.email });
    const post = await Post.findOne({ _id: req.params.id }).populate('user');
    const likeIndex = post.likes.indexOf(loginUser._id);

    if (likeIndex === -1) {
      post.likes.push(loginUser._id);
    } else {
      post.likes.splice(likeIndex, 1);
    }

    await post.save();

    res.json({
      isLiked: likeIndex === -1,
      likesCount: post.likes.length
    });
  } catch (error) {
    console.error('Like error:', error);
    res.status(500).json({ error: 'Error processing like' });
  }
});

// Edit post
app.get('/edit/:postid', isLoggedIn, async (req, res) => {
  try {
    const post = await Post.findById(req.params.postid);
    res.render('edit', { editdata: post });
  } catch (error) {
    res.status(500).send(error.message);
  }
});

app.post('/update/:id', isLoggedIn, async (req, res, next) => {
  req.uploadField = 'postimg';
  handleUpload(req, res, async (err) => {
    if (err) return next(err);

    try {
      const post = await Post.findById(req.params.id);

      // Update content
      post.content = req.body.content;

      // If new image uploaded
      if (req.file) {
        // Delete old image if exists
        if (post.postimg && post.postimg.public_id) {
          await cloudinary.uploader.destroy(post.postimg.public_id);
        }

        // Update with new image
        post.postimg = {
          url: req.file.path,
          public_id: req.file.filename
        };
      }

      await post.save();
      res.redirect('/profile');
    } catch (error) {
      console.error('Post update error:', error);
      if (req.file && req.file.filename) {
        await cloudinary.uploader.destroy(req.file.filename);
      }
      res.status(500).send('Error updating post: ' + error.message);
    }
  });
});

// Edit profile page
app.get('/editprofile', isLoggedIn, async (req, res) => {
  try {
    const user = await User.findOne({ email: req.user.email });
    if (!user) {
      return res.redirect('/login');
    }
    res.render('editprofile', {
      user,
      defaultProfilePic: 'https://res.cloudinary.com/your-cloud-name/image/upload/v1/instagram-clone/default-avatar.png'
    });
  } catch (err) {
    console.error('Error loading edit profile page:', err);
    res.status(500).send('An error occurred');
  }
});

// Update profile
app.post('/editprofile', isLoggedIn, async (req, res, next) => {
  req.uploadField = 'profilepic';
  handleUpload(req, res, async (err) => {
    if (err) return next(err);

    try {
      const user = await User.findOne({ email: req.user.email });

      // Update basic info
      user.name = req.body.name || user.name;
      user.bio = req.body.bio || user.bio;

      // If new profile picture uploaded
      if (req.file) {
        // Delete old profile picture if exists
        if (user.profilepic && user.profilepic.public_id) {
          await cloudinary.uploader.destroy(user.profilepic.public_id);
        }

        // Update with new profile picture
        user.profilepic = {
          url: req.file.path,
          public_id: req.file.filename
        };
      }

      await user.save();
      res.redirect('/profile');
    } catch (error) {
      console.error('Profile update error:', error);
      if (req.file && req.file.filename) {
        await cloudinary.uploader.destroy(req.file.filename);
      }
      res.status(500).send('Error updating profile: ' + error.message);
    }
  });
});

// View all posts
app.get('/allpost', isLoggedIn, async (req, res) => {
  try {
    const loginUser = await User.findOne({ email: req.user.email });
    const allpost = await Post.find()
      .populate('user')
      .populate({
        path: 'comments',
        populate: {
          path: 'user',
          select: 'username'
        }
      })
      .sort('-createdAt');

    console.log('First post comments:', allpost[0]?.comments);

    res.render('allpost', { allpost, loginUser });
  } catch (err) {
    console.error(err);
    res.status(500).send('An error occurred while loading posts');
  }
});

// Add comment
app.post('/addcomment', isLoggedIn, async (req, res) => {
  try {
    const { comment, postId } = req.body;

    if (!comment || !postId) {
      return res.status(400).json({ error: 'Comment and postId are required' });
    }

    const loginUser = await User.findOne({ email: req.user.email });
    const post = await Post.findById(postId);

    if (!post) {
      return res.status(404).json({ error: 'Post not found' });
    }

    const newComment = {
      user: loginUser._id,
      content: comment
    };

    post.comments.push(newComment);
    await post.save();

    // Return the new comment data
    res.json({
      username: loginUser.username,
      content: comment
    });
  } catch (error) {
    console.error('Error adding comment:', error);
    res.status(500).json({ error: 'Error adding comment' });
  }
});

// Follow user
app.get('/follow/:id', isLoggedIn, async (req, res) => {
  try {
    const targetUserId = req.params.id;
    const loggedInUser = await User.findOne({ email: req.user.email });
    const targetUser = await User.findById(targetUserId);

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
    const loggedInUser = await User.findOne({ email });
    const users = await User.find({ _id: { $ne: loggedInUser._id } });

    res.render('explore', { users, loggedInUser });
  } catch (err) {
    console.error(err);
    res.status(500).send('An error occurred while loading the explore page');
  }
});

// Followers route
app.get('/followers', isLoggedIn, async (req, res) => {
  try {
    const loggedInUser = await User.findOne({ email: req.user.email }).populate('followers');

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
    const loggedInUser = await User.findOne({ email: req.user.email }).populate('following');

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
    const loggedInUser = await User.findOne({ email: req.user.email })
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
    const loggedInUser = await User.findOne({ email: req.user.email });
    const chatPartner = await User.findById(req.params.userId);

    if (!chatPartner) {
      return res.status(404).send('User not found');
    }

    const chatHistory = await Message.find({
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
    const post = await Post.findById(req.params.id);
    if (!post) {
      return res.status(404).send('Post not found');
    }

    const user = await User.findOne({ email: req.user.email });

    if (post.user.toString() !== user._id.toString()) {
      return res.status(403).send('You are not authorized to delete this post');
    }

    // Delete image from Cloudinary
    if (post.postimg && post.postimg.public_id) {
      await cloudinary.uploader.destroy(post.postimg.public_id);
    }

    await Post.findByIdAndDelete(req.params.id);
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
    const user = await User.findOne({ email: req.user.email });

    // Delete all posts by the user
    await Post.deleteMany({ user: user._id });

    // Remove user from followers and following lists of other users
    await User.updateMany(
      { $or: [{ followers: user._id }, { following: user._id }] },
      { $pull: { followers: user._id, following: user._id } }
    );

    // Delete the user
    await User.findByIdAndDelete(user._id);

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
      const newMessage = new Message({
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

// All Posts route (if you don't have this already)
app.get('/allpost', isLoggedIn, async (req, res) => {
  try {
    const posts = await Post.find()
      .populate('user')
      .populate({
        path: 'comments',
        populate: { path: 'user' }
      })
      .sort({ createdAt: -1 });

    const loginUser = await User.findOne({ email: req.user.email });
    res.render('allpost', {
      allpost: posts,
      loginUser,
      defaultProfilePic: "https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcT5x4ugT-l8K56rUtVOPDhJam2Hp5sRLQtyVQ&s"
    });
  } catch (err) {
    console.error(err);
    res.status(500).send('Error loading posts');
  }
});

// User Profile View route
app.get('/profile/:id', isLoggedIn, async (req, res) => {
  try {
    console.log('Accessing profile with ID:', req.params.id);

    // Validate MongoDB ObjectId
    if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
      console.log('Invalid ObjectId');
      return res.render('user-profile-view', {
        requestedUrl: req.originalUrl
      });
    }

    const profileUser = await User.findById(req.params.id)
      .populate({
        path: 'posts',
        options: { sort: { 'createdAt': -1 } }
      })
      .populate('followers')
      .populate('following');

    if (!profileUser) {
      console.log('Profile user not found');
      return res.render('under-construction', {
        requestedUrl: req.originalUrl
      });
    }

    const loggedInUser = await User.findOne({ email: req.user.email });
    const isFollowing = loggedInUser.following.includes(profileUser._id);
    const isOwnProfile = loggedInUser._id.toString() === profileUser._id.toString();

    if (isOwnProfile) {
      console.log('Redirecting to own profile');
      return res.redirect('/profile');
    }

    console.log('Rendering user profile view');
    res.render('user-profile-view', {
      profileUser,
      loggedInUser,
      isFollowing,
      defaultProfilePic: "https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcT5x4ugT-l8K56rUtVOPDhJam2Hp5sRLQtyVQ&s"
    });
  } catch (err) {
    console.error('Error loading profile:', err);
    res.render('under-construction', {
      requestedUrl: req.originalUrl
    });
  }
});

// Server listen should be at the very end
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).send('Something broke! ' + err.message);
});