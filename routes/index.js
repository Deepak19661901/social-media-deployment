const upload = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: 50 * 1024 * 1024 } // 50MB limit
});

router.post('/editprofile', isLoggedIn, upload.single('profilepic'), async (req, res) => {
    try {
        const user = await userModel.findOne({ email: req.user.email });

        if (req.file) {
            // If there's an existing profile picture, delete it from Cloudinary
            if (user.profilepic && user.profilepic.public_id) {
                await cloudinary.uploader.destroy(user.profilepic.public_id);
            }

            // Upload new image to Cloudinary
            const result = await cloudinary.uploader.upload(req.file.path, {
                folder: 'profile_pictures',
                width: 500,
                height: 500,
                crop: 'fill',
                gravity: 'face'
            });

            // Update user profile picture
            user.profilepic = {
                url: result.secure_url,
                public_id: result.public_id
            };
        }

        // Update other fields
        if (req.body.name) user.name = req.body.name;
        if (req.body.bio) user.bio = req.body.bio;

        await user.save();
        res.redirect('/profile');
    } catch (error) {
        console.error('Profile update error:', error);
        res.status(500).send('Error updating profile');
    }
});

router.get('/profile', isLoggedIn, async (req, res) => {
  try {
    const user = await userModel.findOne({ email: req.user.email })
      .populate({
        path: 'posts',
        options: { sort: { 'createdAt': -1 } }
      })
      .populate('followers')
      .populate('following');

    if (!user) {
      return res.status(404).send('User not found');
    }

    // Log to check what data we're getting
    console.log('User profile data:', {
      username: user.username,
      profilePic: user.profilepic,
      postsCount: user.posts.length
    });

    res.render('profile', { user });
  } catch (error) {
    console.error('Profile route error:', error);
    res.status(500).send('Server Error');
  }
});

app.get('/explore', isLoggedIn, async (req, res) => {
  try {
    const loggedInUser = await userModel.findOne({ email: req.user.email });
    const users = await userModel.find({ 
      _id: { $ne: loggedInUser._id } 
    }).select('username name profilepic following');

    res.render('explore', { 
      users, 
      loggedInUser,
      defaultProfilePic: 'https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcT5x4ugT-l8K56rUtVOPDhJam2Hp5sRLQtyVQ&s'
    });
  } catch (err) {
    console.error(err);
    res.status(500).send('An error occurred while loading explore page');
  }
}); 