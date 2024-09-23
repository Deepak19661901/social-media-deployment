const multer = require('multer');
const path = require('path');
const fs = require('fs');

// Define the directory where files will be stored
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const dir = path.join(__dirname, '..', 'public', 'images', 'uploadpostimg');
    
    // Check if directory exists, if not, create it
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }

    cb(null, dir);  // Set the directory for multer to store files
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, 'image-' + uniqueSuffix + path.extname(file.originalname));
  }
});

// Initialize multer with storage settings
const uploadpostimg = multer({ storage });

module.exports = uploadpostimg;
