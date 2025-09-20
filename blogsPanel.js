const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const multer = require("multer");
const { CloudinaryStorage } = require("multer-storage-cloudinary");
const cloudinary = require("cloudinary").v2;
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const path = require("path");
require("dotenv").config({ path: path.join(__dirname, ".env") });
const app = express();

// Allowed Origins for CORS
const allowedOrigins = [
  "https://connectingdotserp.com",
  "https://www.connectingdotserp.com",
  "https://blog.connectingdotserp.com",
  "https://www.blog.connectingdotserp.com",
  "https://subdomain-x26r.vercel.app",
  "https://domain-topaz.vercel.app",
  "http://localhost:3000",
  "http://localhost:3001",
  "http://localhost:5002",
];

const corsOptions = {
  origin: function (origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      console.error("❌ CORS Blocked Origin:", origin);
      callback(new Error("Not allowed by CORS"));
    }
  },
  methods: ["GET", "POST", "PUT", "DELETE"],
  allowedHeaders: ["Content-Type", "Authorization"],
  credentials: true,
};

app.use(cors(corsOptions));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ✅ Debugging Middleware
app.use((req, res, next) => {
  console.log("Incoming Request:", req.method, req.url);
  console.log("Origin:", req.headers.origin);
  next();
});

// ✅ MongoDB Connection
if (!process.env.MONGO_URI) {
  console.error("❌ Missing MONGO_URI in environment. Ensure it is set in backend/.env");
  process.exit(1);
}


// Enhanced User Schema & Model
const userSchema = new mongoose.Schema(
  {
    username: {
      type: String,
      required: [true, 'Username is required'],
      unique: true,
      trim: true,
      minlength: [3, 'Username must be at least 3 characters long'],
      maxlength: [30, 'Username cannot be longer than 30 characters'],
      match: [/^[a-zA-Z0-9_]+$/, 'Username can only contain letters, numbers, and underscores']
    },
    password: {
      type: String,
      required: [true, 'Password is required'],
      minlength: [6, 'Password must be at least 6 characters long'],
      select: false
    },
    role: {
      type: String,
      enum: {
        values: ['superadmin', 'admin', 'user'],
        message: 'Role must be one of: superadmin, admin, or user'
      },
      default: 'user'
    },
    email: {
      type: String,
      trim: true,
      lowercase: true,
      match: [/^\S+@\S+\.\S+$/, 'Please enter a valid email address']
    },
    isActive: {
      type: Boolean,
      default: true
    },
    lastLogin: Date
  },
  {
    timestamps: {
      createdAt: 'createdAt',
      updatedAt: 'updatedAt'
    },
    toJSON: { virtuals: true },
    toObject: { virtuals: true }
  }
);

// Indexes for better performance
userSchema.index({ username: 1 }, { unique: true });
userSchema.index({ email: 1 }, { unique: true, sparse: true });

// Pre-save hook to hash password
userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  try {
    this.password = await bcrypt.hash(this.password, 12);
    next();
  } catch (error) {
    console.error('Password hashing error:', error);
    next(error);
  }
});

// Method to compare passwords
userSchema.methods.comparePassword = async function(candidatePassword) {
  try {
    return await bcrypt.compare(candidatePassword, this.password);
  } catch (error) {
    console.error('Password comparison error:', error);
    throw error;
  }
};

// Virtual for user's full profile (excluding sensitive data)
userSchema.virtual('profile').get(function() {
  return {
    id: this._id,
    username: this.username,
    email: this.email,
    role: this.role,
    isActive: this.isActive,
    lastLogin: this.lastLogin,
    createdAt: this.createdAt,
    updatedAt: this.updatedAt
  };
});

const User = mongoose.model("User", userSchema);

// ✅ CORRECTED BLOG SCHEMA WITH COURSES SUPPORT
const blogSchema = new mongoose.Schema(
  {
    title: { type: String, required: true },
    slug: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
      index: true,
    },
    content: { type: String, required: true },
    category: { type: String, required: true },
    subcategory: {
      type: String,
      required: true,
      enum: ["Article", "Tutorial", "Interview Questions"],
    },
    author: { type: String, required: true },
    image: { type: String },
    imagePublicId: { type: String },
    // ✅ Banner Image Fields
    bannerImage: { type: String },
    bannerImagePublicId: { type: String },
    status: {
      type: String,
      enum: ["Trending", "Featured", "Editor's Pick", "Recommended", "None"],
      default: "None",
    },
    // ✅ Tags Field
    tags: { 
      type: [String], 
      default: [],
      validate: {
        validator: function(tags) {
          return tags.length <= 10;
        },
        message: 'Cannot have more than 10 tags'
      }
    },
    
    // ✅ CORRECTED: Courses field with proper validation and field names
    courses: [{
      name: {
        type: String,
        required: true,
        maxlength: 100,
        trim: true
      },
      description: {
        type: String,
        required: true,
        maxlength: 300,
        trim: true
      },
      courseUrl: {
        type: String,
        required: true,
        validate: {
          validator: function(v) {
            return /^https?:\/\/.+/.test(v);
          },
          message: 'Course URL must be a valid URL'
        }
      },
      courseImage: { type: String },
      courseImagePublicId: { type: String }
    }],
    
    // ✅ CORRECTED: Course images metadata for cleanup
    courseImagesData: [{
      fieldIndex: { type: Number, required: true },
      publicId: { type: String, required: true },
      url: { type: String, required: true }
    }]
  },
  { timestamps: true }
);

// ✅ Add indexes for better performance
blogSchema.index({ tags: 1 });
blogSchema.index({ author: 1, createdAt: -1 });
blogSchema.index({ category: 1, createdAt: -1 });
blogSchema.index({ status: 1, createdAt: -1 });

const Blog = mongoose.model("Blog", blogSchema);

// ✅ Configure Cloudinary
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

// ✅ Helper function to extract public_id from Cloudinary URL
const getPublicIdFromUrl = (url) => {
  if (!url) return null;
  try {
    const urlParts = url.split("/");
    const versionIndex = urlParts.findIndex(
      (part) => part.startsWith("v") && !isNaN(part.substring(1))
    );
    if (versionIndex !== -1 && urlParts.length > versionIndex + 2) {
      const relevantParts = urlParts.slice(versionIndex + 1);
      const publicIdWithExtension = relevantParts.slice(1).join("/");
      return publicIdWithExtension.substring(
        0,
        publicIdWithExtension.lastIndexOf(".")
      );
    } else if (urlParts.length > 1) {
      const fileNameWithExtension = urlParts[urlParts.length - 1];
      const publicIdWithFolder = urlParts
        .slice(urlParts.lastIndexOf("upload") + 2)
        .join("/");
      return publicIdWithFolder.substring(
        0,
        publicIdWithFolder.lastIndexOf(".")
      );
    }
    return null;
  } catch (error) {
    console.error("Error extracting public ID:", error);
    return null;
  }
};

// ✅ ENHANCED: Helper function to delete image from Cloudinary with better error handling
const deleteCloudinaryImage = async (publicId) => {
  if (!publicId || typeof publicId !== 'string' || publicId.trim() === '') {
    console.warn('⚠️ Invalid publicId for deletion:', publicId);
    return;
  }
  
  try {
    console.log(`🗑️ Attempting to delete Cloudinary image with public ID: ${publicId.trim()}`);
    const result = await cloudinary.uploader.destroy(publicId.trim());
    console.log(`✅ Cloudinary deletion result:`, result);
    return result;
  } catch (error) {
    console.error(`❌ Error deleting Cloudinary image ${publicId}:`, error);
    // Don't throw error - log it and continue
  }
};


// ✅ Enhanced Helper function to delete all blog images from Cloudinary
const deleteAllBlogImages = async (blog) => {
  const deletePromises = [];
  
  // Delete featured image
  if (blog.imagePublicId) {
    deletePromises.push(deleteCloudinaryImage(blog.imagePublicId));
  }
  
  // Delete banner image
  if (blog.bannerImagePublicId) {
    deletePromises.push(deleteCloudinaryImage(blog.bannerImagePublicId));
  }
  
  // Delete course images
  if (blog.courseImagesData && Array.isArray(blog.courseImagesData) && blog.courseImagesData.length > 0) {
    blog.courseImagesData.forEach(imageData => {
      if (imageData && imageData.publicId) {
        deletePromises.push(deleteCloudinaryImage(imageData.publicId));
      }
    });
  }
  
  if (deletePromises.length > 0) {
    try {
      await Promise.all(deletePromises);
      console.log("✅ All blog images deleted successfully");
    } catch (error) {
      console.error("❌ Error deleting some blog images:", error);
    }
  }
};

// ✅ Multer Storage for Cloudinary
const storage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: {
    folder: "blog-images",
    format: async (req, file) => "png",
    public_id: (req, file) =>
      Date.now() + "-" + file.originalname.split(".")[0],
  },
});

const upload = multer({ 
  storage,
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB limit per file
  }
});

// ✅ Enhanced multer configuration for course images
const uploadFields = upload.fields([
  { name: 'image', maxCount: 1 },
  { name: 'bannerImage', maxCount: 1 },
  { name: 'courseImages', maxCount: 50 }
]);

// ✅ Helper function to process tags from request
const processTags = (tagsInput) => {
  if (!tagsInput) return [];
  let tags = [];
  try {
    if (typeof tagsInput === 'string') {
      tags = JSON.parse(tagsInput);
    } else if (Array.isArray(tagsInput)) {
      tags = tagsInput;
    }
  } catch (e) {
    if (typeof tagsInput === 'string') {
      tags = tagsInput.split(',').map(tag => tag.trim()).filter(Boolean);
    } else {
      tags = [];
    }
  }
  return tags
    .map(tag => tag.toString().trim().toLowerCase())
    .filter(tag => tag.length > 0 && tag.length <= 50)
    .slice(0, 10);
};

// Helper function to process course image
async function processCourseImage(course, uploadedFile, courseImagesData, index) {
  let path = course.courseImage || null;
  let publicId = course.courseImagePublicId || null;

  if (uploadedFile) {
    path = uploadedFile.path;
    publicId = uploadedFile.filename || getPublicIdFromUrl(uploadedFile.path);
    if (publicId) {
      courseImagesData.push({
        fieldIndex: index,
        publicId,
        url: path
      });
    }
  }

  return { path, publicId };
}

// Helper function to clean up course images
async function cleanupCourseImages(imagesData) {
  const cleanup = imagesData.map(img => 
    img?.publicId ? deleteCloudinaryImage(img.publicId) : Promise.resolve()
  );
  return Promise.allSettled(cleanup);
}

// Helper function to handle slug updates
async function handleSlugUpdate(body, existingBlog) {
  try {
    let baseSlug = body.slug ? generateSlug(body.slug) : generateSlug(body.title);
    
    if (baseSlug !== existingBlog.slug) {
      const uniqueSlug = await findUniqueSlug(baseSlug, Blog, existingBlog.id);
      return { slug: uniqueSlug, error: null };
    }
    return { slug: existingBlog.slug, error: null };
  } catch (error) {
    return { slug: null, error: 'Error generating slug' };
  }
}

// Helper function to handle image uploads
async function handleImageUpload(file, existingPublicId) {
  if (existingPublicId) {
    try {
      await deleteCloudinaryImage(existingPublicId);
    } catch (error) {
      console.error('Error deleting old image:', error);
    }
  }
  
  return {
    path: file.path,
    publicId: file.filename || getPublicIdFromUrl(file.path)
  };
}

// Helper function to process courses
async function processCourses(coursesInput, files) {
  if (typeof coursesInput !== 'string' || !coursesInput.trim()) {
    return { error: 'Courses data is required' };
  }

  let parsed;
  try {
    parsed = JSON.parse(coursesInput);
  } catch (e) {
    return { error: 'Invalid courses JSON format' };
  }

  if (!Array.isArray(parsed)) {
    return { error: 'Courses must be an array' };
  }

  const validCourses = [];
  const courseImages = (files && files.courseImages) ? files.courseImages : [];
  const courseImagesData = [];

  for (let i = 0; i < parsed.length; i++) {
    const course = parsed[i];
    
    if (!course || typeof course !== 'object' ||
        !course.name?.trim() || 
        !course.description?.trim() || 
        !course.courseUrl?.trim()) {
      return { error: `Invalid course at index ${i}: Missing required fields` };
    }

    // Validate URL format
    try {
      new URL(course.courseUrl.trim());
    } catch {
      return { error: `Invalid URL in course at index ${i}` };
    }

    // Process course image
    const courseImage = await processCourseImage(
      course,
      courseImages[i],
      courseImagesData,
      i
    );

    validCourses.push({
      name: course.name.trim(),
      description: course.description.trim(),
      courseUrl: course.courseUrl.trim(),
      courseImage: courseImage.path || null,
      courseImagePublicId: courseImage.publicId || null
    });
  }

  return { 
    validCourses,
    courseImagesData,
    error: null 
  };
}

// Helper functions for slug generation
const generateSlug = (text) => {
  return text
    .toString()
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .toLowerCase()
    .trim()
    .replace(/\s+/g, "-")
    .replace(/[^\w-]+/g, "")
    .replace(/--+/g, "-");
};

const findUniqueSlug = async (baseSlug, BlogModel, excludeId = null) => {
  let slug = baseSlug;
  let counter = 0;
  while (true) {
    let query = { slug };
    if (excludeId) {
      query._id = { $ne: excludeId };
    }
    const existingBlog = await BlogModel.findOne(query);
    if (!existingBlog) {
      return slug;
    }
    counter++;
    slug = `${baseSlug}-${counter}`;
  }
};

// JWT Authentication Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token)
    return res
      .status(401)
      .json({ message: "Access Denied: No token provided" });
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      console.error("JWT Verification Error:", err);
      return res.status(403).json({ message: "Access Denied: Invalid token" });
    }
    req.user = user;
    next();
  });
};

// ✅ Migration function to fix existing data
const migrateBlogSchema = async () => {
  try {
    console.log('🔄 Starting blog schema migration...');
    
    // Find blogs that have old field names or missing new fields
    const blogsToMigrate = await Blog.find({
      $or: [
        { coursesData: { $exists: true } },
        { courseImagesData: { $exists: false } }
      ]
    });
    
    console.log(`📊 Found ${blogsToMigrate.length} blogs to migrate`);
    
    for (const blog of blogsToMigrate) {
      const updateData = {};
      
      // Remove old coursesData field if it exists
      if (blog.coursesData !== undefined) {
        updateData.$unset = { coursesData: "" };
      }
      
      // Initialize new fields if they don't exist
      if (!blog.courseImagesData) {
        updateData.courseImagesData = [];
      }
      
      // Ensure courses array exists and has correct structure
      if (!blog.courses || !Array.isArray(blog.courses)) {
        updateData.courses = [];
      }
      
      if (Object.keys(updateData).length > 0) {
        await Blog.findByIdAndUpdate(blog._id, updateData);
        console.log(`✅ Migrated blog: ${blog.title}`);
      }
    }
    
    console.log('🎉 Blog schema migration completed successfully');
  } catch (error) {
    console.error('❌ Migration error:', error);
  }
};

// ✅ MongoDB Connection with Migration
mongoose
  .connect(process.env.MONGO_URI)
  .then(async () => {
    console.log("✅ Blogs MongoDB Connected");
    // Run migration on startup
    await migrateBlogSchema();
  })
  .catch((err) => console.error("❌ MongoDB Connection Error:", err));

// ✅ Validate JWT Token Endpoint
app.get("/api/auth/validate-token", authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }
    if (!user.isActive) {
      return res.status(403).json({ message: "Account is inactive" });
    }
    
    res.json({
      id: user._id,
      username: user.username,
      email: user.email,
      role: user.role,
      isActive: user.isActive,
      lastLogin: user.lastLogin,
      createdAt: user.createdAt,
      updatedAt: user.updatedAt
    });
  } catch (err) {
    console.error("Token validation error:", err);
    res.status(500).json({ 
      message: "Error validating token", 
      error: err.message 
    });
  }
});

// ✅ Logout Endpoint
app.post("/api/auth/logout", authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (user) {
      // Optional: add lastLogout field if needed
    }
    res.json({ message: "Logged out successfully" });
  } catch (err) {
    console.error("Logout error:", err);
    res.status(500).json({ 
      message: "Error during logout", 
      error: err.message 
    });
  }
});

// Enhanced role-based middleware
const requireRole = (roles) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ message: "Access Denied: Authentication required" });
    }
    
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ 
        message: "Access Denied: Insufficient permissions",
        required: roles,
        current: req.user.role
      });
    }
    
    next();
  };
};

// --- Enhanced Authentication Routes ---
// Register User
app.post("/api/auth/register", async (req, res) => {
  try {
    const { username, email, password, role = 'user' } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({ 
        message: "Username and password are required" 
      });
    }
    
    const existingUser = await User.findOne({ 
      $or: [
        { username }, 
        ...(email ? [{ email }] : [])
      ] 
    });
    
    if (existingUser) {
      return res.status(409).json({ 
        message: "User with that username or email already exists" 
      });
    }
    
    const user = new User({ username, email, password, role });
    await user.save();
    
    res.status(201).json({ 
      message: "User registered successfully!", 
      user: user.profile 
    });
  } catch (err) {
    console.error("Registration Error:", err);
    
    if (err.name === 'ValidationError') {
      const errors = Object.values(err.errors).map(e => e.message);
      return res.status(400).json({ 
        message: "Validation failed", 
        errors 
      });
    }
    
    res.status(500).json({ 
      message: "Error registering user", 
      error: err.message 
    });
  }
});

// Login User
app.post("/api/auth/login", async (req, res) => {
  try {
    const { loginIdentifier, password } = req.body;
    
    if (!loginIdentifier || !password) {
      return res.status(400).json({ 
        message: "Login identifier and password are required" 
      });
    }
    
    const user = await User.findOne({
      $or: [{ username: loginIdentifier }, { email: loginIdentifier }],
      isActive: true
    }).select('+password');
    
    if (!user) {
      return res.status(401).json({ message: "Invalid credentials" });
    }
    
    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      return res.status(401).json({ message: "Invalid credentials" });
    }
    
    user.lastLogin = new Date();
    await user.save();
    
    const token = jwt.sign(
      { 
        id: user._id, 
        username: user.username, 
        email: user.email,
        role: user.role 
      },
      process.env.JWT_SECRET,
      { expiresIn: "24h" }
    );
    
    res.json({
      message: "Logged in successfully",
      token,
      user: user.profile
    });
  } catch (err) {
    console.error("Login Error:", err);
    res.status(500).json({ 
      message: "Error during login", 
      error: err.message 
    });
  }
});

// Get current user profile
app.get("/api/auth/profile", authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }
    
    res.json({ user: user.profile });
  } catch (err) {
    console.error("Profile Error:", err);
    res.status(500).json({ 
      message: "Error fetching profile", 
      error: err.message 
    });
  }
});

// Update user profile
app.put("/api/auth/profile", authenticateToken, async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findById(req.user.id);
    
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }
    
    if (email) user.email = email;
    await user.save();
    
    res.json({ 
      message: "Profile updated successfully", 
      user: user.profile 
    });
  } catch (err) {
    console.error("Profile Update Error:", err);
    res.status(500).json({ 
      message: "Error updating profile", 
      error: err.message 
    });
  }
});

// ================ USER MANAGEMENT ENDPOINTS ================
// Get all users (Admin/SuperAdmin only)
app.get("/api/auth/users", authenticateToken, async (req, res) => {
  try {
    if (!['admin', 'superadmin'].includes(req.user.role.toLowerCase())) {
      return res.status(403).json({ 
        message: "Access denied. Admin privileges required.",
        requiredRole: ["admin", "superadmin"],
        currentRole: req.user.role
      });
    }
    
    console.log(`Admin ${req.user.username} fetching all users`);
    
    const users = await User.find({}, { password: 0 }).sort({ createdAt: -1 });
    
    console.log(`Found ${users.length} users`);
    res.json(users);
    
  } catch (err) {
    console.error("Error fetching users:", err);
    res.status(500).json({ 
      message: "Error fetching users", 
      error: process.env.NODE_ENV === 'development' ? err.message : 'Internal server error'
    });
  }
});

// Get specific user by ID (Admin/SuperAdmin only)
app.get("/api/auth/users/:id", authenticateToken, async (req, res) => {
  try {
    if (!['admin', 'superadmin'].includes(req.user.role.toLowerCase())) {
      return res.status(403).json({ 
        message: "Access denied. Admin privileges required." 
      });
    }
    
    const { id } = req.params;
    
    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({ message: "Invalid user ID format" });
    }
    
    const user = await User.findById(id, { password: 0 });
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }
    
    res.json(user);
  } catch (err) {
    console.error("Error fetching user:", err);
    res.status(500).json({ 
      message: "Error fetching user", 
      error: process.env.NODE_ENV === 'development' ? err.message : 'Internal server error'
    });
  }
});

// Update user (Admin/SuperAdmin only)
app.put("/api/auth/users/:id", authenticateToken, async (req, res) => {
  try {
    if (!['admin', 'superadmin'].includes(req.user.role.toLowerCase())) {
      return res.status(403).json({ 
        message: "Access denied. Admin privileges required." 
      });
    }
    
    const { id } = req.params;
    const { username, email, role, isActive } = req.body;
    
    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({ message: "Invalid user ID format" });
    }
    
    const userToUpdate = await User.findById(id);
    if (!userToUpdate) {
      return res.status(404).json({ message: "User not found" });
    }
    
    if (userToUpdate.username === 'admin' && username && username !== 'admin') {
      return res.status(403).json({ 
        message: "Cannot change main admin username" 
      });
    }
    
    if (role === 'superadmin' && req.user.role.toLowerCase() !== 'superadmin') {
      return res.status(403).json({ 
        message: "Only superadmin can promote users to superadmin role" 
      });
    }
    
    const updateData = {};
    if (username) updateData.username = username;
    if (email) updateData.email = email;
    if (role) updateData.role = role;
    if (typeof isActive === 'boolean') updateData.isActive = isActive;
    
    const updatedUser = await User.findByIdAndUpdate(
      id, 
      updateData, 
      { new: true, runValidators: true }
    ).select({ password: 0 });
    
    console.log(`User ${updatedUser.username} updated by ${req.user.username}`);
    res.json({ 
      message: "User updated successfully",
      user: updatedUser
    });
  } catch (err) {
    console.error("Error updating user:", err);
    
    if (err.code === 11000) {
      return res.status(409).json({ 
        message: "Username or email already exists" 
      });
    }
    
    res.status(500).json({ 
      message: "Error updating user", 
      error: process.env.NODE_ENV === 'development' ? err.message : 'Internal server error'
    });
  }
});

// Delete user (Admin/SuperAdmin only)
app.delete("/api/auth/users/:id", authenticateToken, async (req, res) => {
  try {
    if (!['admin', 'superadmin'].includes(req.user.role.toLowerCase())) {
      return res.status(403).json({ 
        message: "Access denied. Admin privileges required." 
      });
    }
    
    const { id } = req.params;
    console.log(`Admin ${req.user.username} attempting to delete user: ${id}`);
    
    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({ message: "Invalid user ID format" });
    }
    
    const userToDelete = await User.findById(id);
    if (!userToDelete) {
      return res.status(404).json({ message: "User not found" });
    }
    
    console.log(`Found user to delete: ${userToDelete.username}`);
    
    if (userToDelete.username === 'admin') {
      return res.status(403).json({ 
        message: "Cannot delete the main admin user" 
      });
    }
    
    if (userToDelete._id.toString() === req.user.id) {
      return res.status(403).json({ 
        message: "Cannot delete yourself" 
      });
    }
    
    if (userToDelete.role === 'superadmin' && req.user.role.toLowerCase() !== 'superadmin') {
      return res.status(403).json({ 
        message: "Only superadmin can delete other superadmins" 
      });
    }
    
    await User.findByIdAndDelete(id);
    console.log(`User ${userToDelete.username} deleted successfully`);
    
    res.json({ 
      message: `User "${userToDelete.username}" deleted successfully`,
      deletedUser: {
        id: userToDelete._id,
        username: userToDelete.username,
        role: userToDelete.role
      }
    });
  } catch (err) {
    console.error("Error deleting user:", err);
    res.status(500).json({ 
      message: "Error deleting user", 
      error: process.env.NODE_ENV === 'development' ? err.message : 'Internal server error'
    });
  }
});

// ✅ General ping endpoint
app.get("/api/ping", (req, res) => {
  res.json({ 
    message: "Server is running!", 
    timestamp: new Date().toISOString(),
    status: "healthy",
    server: "Express Blog Backend"
  });
});

// ✅ Wake/Ping Endpoint
app.get("/api/blogs/ping", (req, res) => {
  res.status(200).json({ message: "Server is awake!" });
});

// ✅ Fetch all blogs WITH TAGS AND COURSES SUPPORT
app.get("/api/blogs", async (req, res) => {
  try {
    const { category, subcategory, status, tags, limit, skip } = req.query;
    let query = {};
    
    if (category) query.category = category;
    if (subcategory) query.subcategory = subcategory;
    if (status) query.status = status;
    
    // Add tag filtering support
    if (tags) {
      const tagArray = Array.isArray(tags) ? tags : tags.split(',').map(t => t.trim());
      query.tags = { $in: tagArray };
    }
    
    const parsedLimit = parseInt(limit) || 8;
    const parsedSkip = parseInt(skip) || 0;
    
    const blogs = await Blog.find(query)
      .sort({ createdAt: -1 })
      .skip(parsedSkip)
      .limit(parsedLimit + 1);
    
    const hasMore = blogs.length > parsedLimit;
    const blogsToSend = hasMore ? blogs.slice(0, parsedLimit) : blogs;
    
    res.json({ blogs: blogsToSend, hasMore });
  } catch (err) {
    console.error("Error fetching blogs:", err);
    res.status(500).json({ message: "Error fetching blogs", error: err.message });
  }
});

// ✅ ENHANCED: Backend tags endpoint with null filtering
app.get("/api/blogs/tags", async (req, res) => {
  try {
    console.log('🏷️ Fetching all tags from database...');
    const tags = await Blog.distinct("tags");
    
    // ✅ ENHANCED: Filter out null, undefined, empty, and non-string values
    const sortedTags = tags
      .filter(tag => {
        return tag && 
               typeof tag === 'string' && 
               tag.trim() !== '';
      })
      .map(tag => tag.trim()) // Clean up whitespace
      .sort();
    
    console.log(`Found ${sortedTags.length} valid unique tags`);
    res.json({ 
      tags: sortedTags,
      count: sortedTags.length
    });
  } catch (err) {
    console.error("❌ Error fetching tags:", err);
    res.status(500).json({ message: "Error fetching tags", error: err.message });
  }
});


// ✅ Search blogs by tags
app.get("/api/blogs/search/tags", async (req, res) => {
  try {
    const { tags, limit, skip } = req.query;
    
    if (!tags) {
      return res.status(400).json({ message: "Tags parameter is required" });
    }
    
    const tagArray = Array.isArray(tags) ? tags : [tags];
    
    const [blogs, total] = await Promise.all([
      Blog.find({ tags: { $in: tagArray } })
        .sort({ createdAt: -1 })
        .limit(parseInt(limit) || 10)
        .skip(parseInt(skip) || 0)
        .lean(),
      Blog.countDocuments({ tags: { $in: tagArray } })
    ]);
    
    res.json({
      blogs,
      total,
      limit: parseInt(limit) || 10,
      skip: parseInt(skip) || 0
    });
  } catch (err) {
    console.error("Error searching blogs by tags:", err);
    res.status(500).json({ message: "Error searching blogs", error: err.message });
  }
});

// ✅ Get current user's blog posts only
app.get("/api/blogs/my-posts", authenticateToken, async (req, res) => {
  try {
    const { category, subcategory, status, tags, limit, skip } = req.query;
    
    console.log(`Fetching posts for user: ${req.user.username} (ID: ${req.user.id})`);
    
    // Build query for current user's posts only
    let query = { 
      $or: [
        { author: req.user.username },
        { authorId: req.user.id },
        { createdBy: req.user.id },
        { userId: req.user.id }
      ]
    };
    
    if (category) query.category = category;
    if (subcategory) query.subcategory = subcategory;
    if (status) query.status = status;
    
    if (tags) {
      const tagArray = Array.isArray(tags) ? tags : tags.split(',').map(t => t.trim());
      query.tags = { $in: tagArray };
    }
    
    const parsedLimit = parseInt(limit) || 50;
    const parsedSkip = parseInt(skip) || 0;
    
    const blogs = await Blog.find(query)
      .sort({ createdAt: -1 })
      .skip(parsedSkip)
      .limit(parsedLimit);
    
    console.log(`✅ Found ${blogs.length} posts for user ${req.user.username}`);
    
    res.json({ 
      blogs, 
      total: blogs.length,
      author: req.user.username 
    });
    
  } catch (err) {
    console.error("Error fetching user blogs:", err);
    res.status(500).json({ message: "Error fetching user blogs", error: err.message });
  }
});

// ====================================
// PARAMETERIZED ROUTES (most specific to least specific)
// ====================================

// ✅ Fetch blog by SLUG (more specific than ID)
app.get("/api/blogs/slug/:slug", async (req, res) => {
  try {
    const blog = await Blog.findOne({ slug: req.params.slug });
    if (!blog) return res.status(404).json({ message: "Blog not found" });
    res.json(blog);
  } catch (err) {
    res.status(500).json({ message: "Error fetching blog", error: err.message });
  }
});

// ✅ Parameterized routes (ID-based)
app.get("/api/blogs/:id", async (req, res) => {
  try {
    if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
      return res.status(400).json({ message: "Invalid Blog ID format" });
    }
    const blog = await Blog.findById(req.params.id);
    if (!blog) return res.status(404).json({ message: "Blog not found" });
    res.json(blog);
  } catch (err) {
    res.status(500).json({ message: "Error fetching blog", error: err.message });
  }
});

// ✅ Create a new blog WITH COURSES SUPPORT
app.post(
  "/api/blogs",
  authenticateToken,
  uploadFields,
  async (req, res) => {
    try {
      const {
        title,
        content,
        category,
        subcategory,
        author,
        status,
        slug: providedSlug,
        tags: tagsInput,
        courses: coursesInput
      } = req.body;
      
      console.log("📝 Creating blog with courses:", {
        title,
        coursesInput,
        files: req.files
      });
      
      let blogSlug;
      if (providedSlug) {
        blogSlug = generateSlug(providedSlug);
      } else {
        blogSlug = generateSlug(title);
      }
      blogSlug = await findUniqueSlug(blogSlug, Blog);
      
      // Handle Featured Image
      let imagePath = null;
      let imagePublicId = null;
      if (req.files && req.files.image && req.files.image[0]) {
        const imageFile = req.files.image[0];
        imagePath = imageFile.path;
        imagePublicId = imageFile.filename || getPublicIdFromUrl(imagePath);
        console.log("📸 Featured image uploaded:", imagePath);
      }
      
      // Handle Banner Image
      let bannerImagePath = null;
      let bannerImagePublicId = null;
      if (req.files && req.files.bannerImage && req.files.bannerImage[0]) {
        const bannerFile = req.files.bannerImage[0];
        bannerImagePath = bannerFile.path;
        bannerImagePublicId = bannerFile.filename || getPublicIdFromUrl(bannerImagePath);
        console.log("🖼️ Banner image uploaded:", bannerImagePath);
      }
      
      // ✅ Process courses data
      let processedCourses = [];
      let courseImagesData = [];
      
      if (coursesInput) {
        try {
          const coursesArray = typeof coursesInput === 'string' ? JSON.parse(coursesInput) : coursesInput;
          
          // Handle course images
          const courseImages = req.files && req.files.courseImages ? req.files.courseImages : [];
          
          processedCourses = coursesArray.map((course, index) => {
            const courseImage = courseImages[index];
            let courseImagePath = null;
            let courseImagePublicId = null;
            
            if (courseImage) {
              courseImagePath = courseImage.path;
              courseImagePublicId = courseImage.filename || getPublicIdFromUrl(courseImagePath);
              
              // Store metadata for cleanup
              courseImagesData.push({
                fieldIndex: index,
                publicId: courseImagePublicId,
                url: courseImagePath
              });
              
              console.log(`🎓 Course ${index + 1} image uploaded:`, courseImagePath);
            }
            
            return {
              name: course.name,
              description: course.description,
              courseUrl: course.courseUrl,
              courseImage: courseImagePath,
              courseImagePublicId: courseImagePublicId
            };
          });
          
          console.log("🎓 Processed courses:", processedCourses.length);
        } catch (err) {
          console.error("Error processing courses:", err);
          throw new Error("Invalid courses data format");
        }
      }
      
      // Process tags
      const processedTags = processTags(tagsInput);
      
      const newBlog = new Blog({
        title,
        slug: blogSlug,
        content,
        category,
        subcategory,
        author,
        image: imagePath,
        imagePublicId,
        bannerImage: bannerImagePath,
        bannerImagePublicId,
        status: status || "None",
        tags: processedTags,
        courses: processedCourses,
        courseImagesData: courseImagesData
      });
      
      await newBlog.save();
      console.log("✅ Blog created successfully with courses and images");
      
      res.status(201).json({ 
        message: "Blog created successfully with courses", 
        blog: newBlog 
      });
    } catch (err) {
      // Cleanup uploaded files if blog creation fails
      if (req.files) {
        const filesToClean = [];
        
        if (req.files.image && req.files.image[0]) {
          filesToClean.push(req.files.image[0].filename || getPublicIdFromUrl(req.files.image[0].path));
        }
        if (req.files.bannerImage && req.files.bannerImage[0]) {
          filesToClean.push(req.files.bannerImage[0].filename || getPublicIdFromUrl(req.files.bannerImage[0].path));
        }
        if (req.files.courseImages) {
          req.files.courseImages.forEach(file => {
            filesToClean.push(file.filename || getPublicIdFromUrl(file.path));
          });
        }
        
        // Delete all uploaded files
        filesToClean.forEach(async (publicId) => {
          await deleteCloudinaryImage(publicId);
        });
      }
      
      if (err.code === 11000 && err.keyPattern && err.keyPattern.slug) {
        return res.status(409).json({
          message: "A blog with a similar title/slug already exists. Please choose a unique title or provide a custom slug.",
          error: err.message,
        });
      }
      console.error("Error creating blog:", err);
      res.status(500).json({ message: "Error creating blog", error: err.message });
    }
  }
);

// Update a blog WITH COURSES SUPPORT - Improved Implementation
app.put('/api/blogs/:id', authenticateToken, uploadFields, async (req, res) => {
  try {
    const { id } = req.params;
    console.log('Updating blog:', id);
    
    // Validate blog ID
    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({ message: 'Invalid Blog ID format' });
    }

    // Find existing blog
    const existingBlog = await Blog.findById(id);
    if (!existingBlog) {
      return res.status(404).json({ message: 'Blog not found' });
    }

    const updatedData = {};

    // Process tags if provided
    if (req.body.tags !== undefined) {
      try {
        updatedData.tags = processTags(req.body.tags);
      } catch (e) {
        return res.status(400).json({ message: 'Invalid tags format' });
      }
    }

    // Process courses if provided
    if (Object.prototype.hasOwnProperty.call(req.body, 'courses')) {
      const { validCourses, courseImagesData, error } = await processCourses(req.body.courses, req.files);
      if (error) {
        return res.status(400).json({ message: error });
      }
      updatedData.courses = validCourses;
      updatedData.courseImagesData = courseImagesData;

      // Cleanup previous course images if any
      if (Array.isArray(existingBlog.courseImagesData) && existingBlog.courseImagesData.length) {
        await cleanupCourseImages(existingBlog.courseImagesData);
      }
    }

    // Handle slug update if title or slug changed
    if (req.body.title || req.body.slug) {
      const slugResult = await handleSlugUpdate(req.body, existingBlog);
      if (slugResult.error) {
        return res.status(400).json({ message: slugResult.error });
      }
      updatedData.slug = slugResult.slug;
    }

    // Handle featured image upload
    if (req.files?.image?.[0]) {
      const { path, publicId } = await handleImageUpload(
        req.files.image[0],
        existingBlog.imagePublicId
      );
      updatedData.image = path;
      updatedData.imagePublicId = publicId;
    }

    // Handle banner image upload
    if (req.files?.bannerImage?.[0]) {
      const { path, publicId } = await handleImageUpload(
        req.files.bannerImage[0],
        existingBlog.bannerImagePublicId
      );
      updatedData.bannerImage = path;
      updatedData.bannerImagePublicId = publicId;
    }

    // Update simple fields
    const scalarFields = ['title', 'content', 'category', 'subcategory', 'author', 'status'];
    scalarFields.forEach(field => {
      if (req.body[field] !== undefined) {
        updatedData[field] = req.body[field];
      }
    });

    // Apply updates
    const updatedBlog = await Blog.findByIdAndUpdate(
      id,
      updatedData,
      { new: true, runValidators: true }
    );

    if (!updatedBlog) {
      return res.status(404).json({ message: 'Blog not found after update' });
    }

    return res.json({ message: 'Blog updated successfully', blog: updatedBlog });
    
  } catch (err) {
    console.error('Error updating blog:', err);
    
    if (err?.code === 11000 && err?.keyPattern?.slug) {
      return res.status(409).json({ 
        message: 'A blog with a similar title/slug already exists',
        error: err.message
      });
    }
    
    if (err?.name === 'ValidationError') {
      const errors = Object.values(err.errors).map(e => e.message);
      return res.status(400).json({ 
        message: 'Validation failed', 
        errors,
        error: err.message
      });
    }
    
    return res.status(500).json({ 
      message: 'Error updating blog', 
      error: err.message 
    });
  }
});

// ✅ Delete a blog WITH ALL IMAGE CLEANUP INCLUDING COURSES
app.delete("/api/blogs/:id", authenticateToken, async (req, res) => {
  try {
    if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
      return res.status(400).json({ message: "Invalid Blog ID format" });
    }
    
    const blogToDelete = await Blog.findById(req.params.id);
    if (!blogToDelete)
      return res.status(404).json({ message: "Blog not found" });
    
    // Delete all images associated with the blog
    await deleteAllBlogImages(blogToDelete);
    
    await Blog.findByIdAndDelete(req.params.id);
    console.log("✅ Blog and all associated images deleted successfully");
    
    res.json({ message: "Blog and associated images deleted successfully" });
  } catch (err) {
    console.error("Error deleting blog:", err);
    res.status(500).json({ message: "Error deleting blog", error: err.message });
  }
});

// ✅ Start the blog server
const PORT = process.env.BLOG_PORT || 5002;
app.listen(PORT, () => console.log(`🚀 Blog server running on port ${PORT}`));

