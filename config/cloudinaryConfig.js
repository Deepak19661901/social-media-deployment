const cloudinary = require('cloudinary').v2;
const multer = require('multer');
const { CloudinaryStorage } = require('multer-storage-cloudinary');
const sharp = require('sharp');
const { Readable } = require('stream');

cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
});

// Function to compress image and maintain orientation
const compressImage = async (buffer) => {
    return sharp(buffer)
        .rotate() // This will auto-rotate based on EXIF data
        .resize(1080, 1080, {
            fit: 'inside',
            withoutEnlargement: true,
            position: 'center'
        })
        .jpeg({
            quality: 80,
            force: false // Preserve original format if possible
        })
        .withMetadata() // Preserve image metadata including orientation
        .toBuffer();
};

// Middleware to handle upload with compression
const handleUpload = async (req, res, next) => {
    const upload = multer({
        storage: multer.memoryStorage(),
        limits: { fileSize: 50 * 1024 * 1024 }
    }).single(req.uploadField || 'uploadpostimg');

    upload(req, res, async (err) => {
        if (err) {
            return res.status(400).send('Error uploading file: ' + err.message);
        }

        try {
            if (!req.file) {
                return next();
            }

            // Compress image
            const compressedBuffer = await compressImage(req.file.buffer);

            // Upload to Cloudinary
            const uploadResult = await new Promise((resolve, reject) => {
                const uploadStream = cloudinary.uploader.upload_stream(
                    {
                        folder: 'instagram-clone',
                        resource_type: 'auto'
                    },
                    (error, result) => {
                        if (error) reject(error);
                        else resolve(result);
                    }
                );

                const readableStream = new Readable({
                    read() {
                        this.push(compressedBuffer);
                        this.push(null);
                    }
                });

                readableStream.pipe(uploadStream);
            });

            // Add upload result to request
            req.file.path = uploadResult.secure_url;
            req.file.filename = uploadResult.public_id;
            next();
        } catch (error) {
            next(error);
        }
    });
};

module.exports = { handleUpload, cloudinary };