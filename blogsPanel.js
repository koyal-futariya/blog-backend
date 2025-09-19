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

mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("✅ Blogs MongoDB Connected"))
  .catch((err) => console.error("❌ MongoDB Connection Error:", err));

// --- Enhanced User Schema & Model ---
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
      select: false // Never return password in queries
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

// ✅ Course Schema & Model
const courseSchema = new mongoose.Schema(
  {
    name: { 
      type: String, 
      required: [true, 'Course name is required'],
      trim: true,
      maxlength: [200, 'Course name cannot exceed 200 characters']
    },
    slug: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
      index: true,
    },
    description: { 
      type: String, 
      required: [true, 'Course description is required'],
      trim: true,
      maxlength: [2000, 'Description cannot exceed 2000 characters']
    },
    courseImage: { 
      type: String 
    },
    courseImagePublicId: { 
      type: String 
    },
    courseUrl: { 
      type: String,
      trim: true,
      validate: {
        validator: function(url) {
          if (!url) return true; // Allow empty URLs
          return /^https?:\/\/.+/.test(url);
        },
        message: 'Please provide a valid URL starting with http:// or https://'
      }
    },
    category: { 
      type: String,
      required: true,
      trim: true
    },
    subcategory: {
      type: String,
      trim: true
    },
    price: {
      type: Number,
      min: [0, 'Price cannot be negative']
    },
    currency: {
      type: String,
      default: 'INR',
      enum: ['INR', 'USD', 'EUR', 'GBP']
    },
    duration: {
      type: String,
      trim: true
    },
    level: {
      type: String,
      enum: ['Beginner', 'Intermediate', 'Advanced', 'Expert'],
      default: 'Beginner'
    },
    status: {
      type: String,
      enum: ['Active', 'Inactive', 'Coming Soon', 'Archived'],
      default: 'Active'
    },
    featured: {
      type: Boolean,
      default: false
    },
    tags: { 
      type: [String], 
      default: [],
      validate: {
        validator: function(tags) {
          return tags.length <= 15;
        },
        message: 'Cannot have more than 15 tags'
      }
    },
    createdBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true
    },
    author: {
      type: String,
      required: true
    }
  },
  { 
    timestamps: true,
    toJSON: { virtuals: true },
    toObject: { virtuals: true }
  }
);

// Indexes for better performance
courseSchema.index({ slug: 1 }, { unique: true });
courseSchema.index({ category: 1 });
courseSchema.index({ tags: 1 });
courseSchema.index({ status: 1 });
courseSchema.index({ createdBy: 1 });

const Course = mongoose.model("Course", courseSchema);

// ✅ UPDATED Blog Schema & Model WITH TAGS, BANNER AND COURSE SUPPORT
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
    // 🆕 TAGS FIELD
    tags: { 
      type: [String], 
      default: [],
      validate: {
        validator: function(tags) {
          return tags.length <= 10; // Limit to 10 tags
        },
        message: 'Cannot have more than 10 tags'
      }
    },
    // ✅ Course references
    courses: [{
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Course'
    }],
    coursesData: [{
      courseId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Course'
      },
      name: String,
      description: String,
      courseImage: String,
      courseImagePublicId: String,
      courseUrl: String,
      order: {
        type: Number,
        default: 0
      }
    }]
  },
  { timestamps: true }
);

// 🆕 Add index for tags for better search performance
blogSchema.index({ tags: 1 });
blogSchema.index({ courses: 1 });

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

// ✅ Helper function to delete image from Cloudinary
const deleteCloudinaryImage = async (publicId) => {
  if (!publicId) return;
  try {
    console.log(`Attempting to delete Cloudinary image with public ID: ${publicId}`);
    const result = await cloudinary.uploader.destroy(publicId);
    console.log(`Cloudinary deletion result:`, result);
    return result;
  } catch (error) {
    console.error(`Error deleting Cloudinary image ${publicId}:`, error);
  }
};

// ✅ Helper function to delete course images from Cloudinary
const deleteCourseImages = async (coursesData) => {
  if (!coursesData || !Array.isArray(coursesData)) return;
  
  const deletePromises = [];
  coursesData.forEach(course => {
    if (course.courseImagePublicId) {
      deletePromises.push(deleteCloudinaryImage(course.courseImagePublicId));
    }
  });
  
  if (deletePromises.length > 0) {
    try {
      await Promise.all(deletePromises);
      console.log("✅ All course images deleted successfully");
    } catch (error) {
      console.error("❌ Error deleting some course images:", error);
    }
  }
};

// ✅ Enhanced Helper function to delete all blog images from Cloudinary
const deleteAllBlogImages = async (blog) => {
  const deletePromises = [];
  if (blog.imagePublicId) {
    deletePromises.push(deleteCloudinaryImage(blog.imagePublicId));
  }
  if (blog.bannerImagePublicId) {
    deletePromises.push(deleteCloudinaryImage(blog.bannerImagePublicId));
  }
  
  // Delete course images
  if (blog.coursesData && blog.coursesData.length > 0) {
    await deleteCourseImages(blog.coursesData);
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

// ✅ Configure multer for multiple image fields
const uploadFields = upload.fields([
  { name: 'image', maxCount: 1 },        // Featured image
  { name: 'bannerImage', maxCount: 1 }   // Banner image
]);

// ✅ Configure multer for course image uploads
const courseUploadFields = upload.fields([
  { name: 'courseImage', maxCount: 1 }
]);

// ✅ Configure multer for blog + course images
const blogCourseUploadFields = upload.fields([
  { name: 'image', maxCount: 1 },           // Blog featured image
  { name: 'bannerImage', maxCount: 1 },     // Blog banner image
  { name: 'courseImages', maxCount: 10 }    // Multiple course images
]);

// 🆕 Helper function to process tags from request
const processTags = (tagsInput) => {
  if (!tagsInput) return [];
  let tags = [];
  try {
    // Try to parse as JSON first (from frontend)
    if (typeof tagsInput === 'string') {
      tags = JSON.parse(tagsInput);
    } else if (Array.isArray(tagsInput)) {
      tags = tagsInput;
    }
  } catch (e) {
    // If JSON parsing fails, treat as comma-separated string
    if (typeof tagsInput === 'string') {
      tags = tagsInput.split(',').map(tag => tag.trim()).filter(Boolean);
    } else {
      tags = [];
    }
  }
  // Clean and validate tags
  return tags
    .map(tag => tag.toString().trim().toLowerCase())
    .filter(tag => tag.length > 0 && tag.length <= 50) // Max 50 chars per tag
    .slice(0, 10); // Max 10 tags
};

// --- Helper functions for slug generation ---
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

// ✅ Helper function to find unique slug for any model
const findUniqueSlugForModel = async (baseSlug, Model, excludeId = null) => {
  let slug = baseSlug;
  let counter = 0;
  
  while (true) {
    let query = { slug };
    if (excludeId) {
      query._id = { $ne: excludeId };
    }
    
    const existingDocument = await Model.findOne(query);
    if (!existingDocument) {
      return slug;
    }
    
    counter++;
    slug = `${baseSlug}-${counter}`;
  }
};

// --- JWT Authentication Middleware ---
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

// =================== COURSE MANAGEMENT ENDPOINTS ===================

// ✅ Create a new course
app.post("/api/courses", authenticateToken, courseUploadFields, async (req, res) => {
  try {
    const {
      name,
      description,
      courseUrl,
      category,
      subcategory,
      price,
      currency,
      duration,
      level,
      status,
      featured,
      tags: tagsInput,
      slug: providedSlug
    } = req.body;

    console.log("📚 Creating course with data:", {
      name,
      category,
      subcategory,
      level,
      status,
      files: req.files
    });

    // Generate unique slug
    let courseSlug;
    if (providedSlug) {
      courseSlug = generateSlug(providedSlug);
    } else {
      courseSlug = generateSlug(name);
    }
    courseSlug = await findUniqueSlugForModel(courseSlug, Course);

    // Handle course image upload
    let courseImagePath = null;
    let courseImagePublicId = null;
    if (req.files && req.files.courseImage && req.files.courseImage[0]) {
      const imageFile = req.files.courseImage[0];
      courseImagePath = imageFile.path;
      courseImagePublicId = imageFile.filename || getPublicIdFromUrl(courseImagePath);
      console.log("📸 Course image uploaded:", courseImagePath);
    }

    // Process tags
    const processedTags = processTags(tagsInput);

    const newCourse = new Course({
      name,
      slug: courseSlug,
      description,
      courseImage: courseImagePath,
      courseImagePublicId,
      courseUrl,
      category,
      subcategory,
      price: price ? parseFloat(price) : undefined,
      currency: currency || 'INR',
      duration,
      level: level || 'Beginner',
      status: status || 'Active',
      featured: featured === 'true' || featured === true,
      tags: processedTags,
      createdBy: req.user.id,
      author: req.user.username
    });

    await newCourse.save();
    console.log("✅ Course created successfully");

    res.status(201).json({
      message: "Course created successfully",
      course: newCourse
    });
  } catch (err) {
    // Cleanup uploaded image if course creation fails
    if (req.files && req.files.courseImage && req.files.courseImage[0]) {
      const imagePublicId = req.files.courseImage[0].filename || 
                           getPublicIdFromUrl(req.files.courseImage[0].path);
      await deleteCloudinaryImage(imagePublicId);
    }

    if (err.code === 11000 && err.keyPattern && err.keyPattern.slug) {
      return res.status(409).json({
        message: "A course with similar name already exists. Please choose a unique name or provide a custom slug.",
        error: err.message,
      });
    }
    console.error("Error creating course:", err);
    res.status(500).json({ message: "Error creating course", error: err.message });
  }
});

// ✅ Get all courses
app.get("/api/courses", async (req, res) => {
  try {
    const { 
      category, 
      subcategory, 
      level, 
      status, 
      featured, 
      tags, 
      limit, 
      skip, 
      search 
    } = req.query;
    
    let query = {};
    
    if (category) query.category = category;
    if (subcategory) query.subcategory = subcategory;
    if (level) query.level = level;
    if (status) query.status = status;
    if (featured !== undefined) query.featured = featured === 'true';
    
    // Tag filtering
    if (tags) {
      const tagArray = Array.isArray(tags) ? tags : tags.split(',').map(t => t.trim());
      query.tags = { $in: tagArray };
    }
    
    // Search functionality
    if (search) {
      const searchRegex = new RegExp(search, 'i');
      query.$or = [
        { name: searchRegex },
        { description: searchRegex },
        { tags: { $in: [searchRegex] } }
      ];
    }
    
    const parsedLimit = parseInt(limit) || 20;
    const parsedSkip = parseInt(skip) || 0;
    
    const courses = await Course.find(query)
      .populate('createdBy', 'username email')
      .sort({ createdAt: -1 })
      .skip(parsedSkip)
      .limit(parsedLimit + 1);
    
    const hasMore = courses.length > parsedLimit;
    const coursesToSend = hasMore ? courses.slice(0, parsedLimit) : courses;
    
    const totalCount = await Course.countDocuments(query);
    
    res.json({ 
      courses: coursesToSend, 
      hasMore,
      total: totalCount,
      page: Math.floor(parsedSkip / parsedLimit) + 1,
      limit: parsedLimit
    });
  } catch (err) {
    console.error("Error fetching courses:", err);
    res.status(500).json({ message: "Error fetching courses", error: err.message });
  }
});

// ✅ Get course by ID
app.get("/api/courses/:id", async (req, res) => {
  try {
    if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
      return res.status(400).json({ message: "Invalid Course ID format" });
    }
    
    const course = await Course.findById(req.params.id)
      .populate('createdBy', 'username email role');
    
    if (!course) {
      return res.status(404).json({ message: "Course not found" });
    }
    
    res.json(course);
  } catch (err) {
    console.error("Error fetching course:", err);
    res.status(500).json({ message: "Error fetching course", error: err.message });
  }
});

// ✅ Get course by slug
app.get("/api/courses/slug/:slug", async (req, res) => {
  try {
    const course = await Course.findOne({ slug: req.params.slug })
      .populate('createdBy', 'username email role');
    
    if (!course) {
      return res.status(404).json({ message: "Course not found" });
    }
    
    res.json(course);
  } catch (err) {
    console.error("Error fetching course:", err);
    res.status(500).json({ message: "Error fetching course", error: err.message });
  }
});

// ✅ Update course
app.put("/api/courses/:id", authenticateToken, courseUploadFields, async (req, res) => {
  try {
    if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
      return res.status(400).json({ message: "Invalid Course ID format" });
    }
    
    const existingCourse = await Course.findById(req.params.id);
    if (!existingCourse) {
      return res.status(404).json({ message: "Course not found" });
    }
    
    // Check permissions (users can only edit their own courses, admins can edit any)
    if (existingCourse.createdBy.toString() !== req.user.id && 
        !['admin', 'superadmin'].includes(req.user.role.toLowerCase())) {
      return res.status(403).json({ message: "Access denied. You can only edit your own courses." });
    }
    
    let updatedData = { ...req.body };
    
    // Process tags if provided
    if (req.body.tags !== undefined) {
      updatedData.tags = processTags(req.body.tags);
    }
    
    // Handle slug updates
    if (updatedData.name || updatedData.slug) {
      let baseSlug;
      if (updatedData.slug) {
        baseSlug = generateSlug(updatedData.slug);
      } else {
        baseSlug = generateSlug(updatedData.name || existingCourse.name);
      }
      
      if (baseSlug !== existingCourse.slug) {
        const uniqueSlug = await findUniqueSlugForModel(baseSlug, Course, existingCourse._id);
        updatedData.slug = uniqueSlug;
      }
    }
    
    // Handle course image update
    if (req.files && req.files.courseImage && req.files.courseImage[0]) {
      console.log("📸 Updating course image");
      // Delete old image
      if (existingCourse.courseImagePublicId) {
        await deleteCloudinaryImage(existingCourse.courseImagePublicId);
      }
      // Set new image
      updatedData.courseImage = req.files.courseImage[0].path;
      updatedData.courseImagePublicId = req.files.courseImage[0].filename || 
                                       getPublicIdFromUrl(req.files.courseImage[0].path);
    }
    
    // Convert string booleans to actual booleans
    if (updatedData.featured !== undefined) {
      updatedData.featured = updatedData.featured === 'true' || updatedData.featured === true;
    }
    
    // Convert price to number if provided
    if (updatedData.price !== undefined && updatedData.price !== '') {
      updatedData.price = parseFloat(updatedData.price);
    }
    
    const updatedCourse = await Course.findByIdAndUpdate(
      req.params.id,
      updatedData,
      { new: true, runValidators: true }
    ).populate('createdBy', 'username email');
    
    console.log("✅ Course updated successfully");
    res.json({ 
      message: "Course updated successfully", 
      course: updatedCourse 
    });
  } catch (err) {
    if (err.code === 11000 && err.keyPattern && err.keyPattern.slug) {
      return res.status(409).json({
        message: "A course with similar name already exists. Please choose a unique name or provide a custom slug.",
        error: err.message,
      });
    }
    console.error("Error updating course:", err);
    res.status(500).json({ message: "Error updating course", error: err.message });
  }
});

// ✅ Delete course
app.delete("/api/courses/:id", authenticateToken, async (req, res) => {
  try {
    if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
      return res.status(400).json({ message: "Invalid Course ID format" });
    }
    
    const courseToDelete = await Course.findById(req.params.id);
    if (!courseToDelete) {
      return res.status(404).json({ message: "Course not found" });
    }
    
    // Check permissions
    if (courseToDelete.createdBy.toString() !== req.user.id && 
        !['admin', 'superadmin'].includes(req.user.role.toLowerCase())) {
      return res.status(403).json({ message: "Access denied. You can only delete your own courses." });
    }
    
    // Delete course image from Cloudinary
    if (courseToDelete.courseImagePublicId) {
      console.log("🗑️ Deleting course image:", courseToDelete.courseImagePublicId);
      await deleteCloudinaryImage(courseToDelete.courseImagePublicId);
    }
    
    // Remove course references from blogs
    await Blog.updateMany(
      { courses: req.params.id },
      { 
        $pull: { 
          courses: req.params.id,
          coursesData: { courseId: req.params.id }
        }
      }
    );
    
    await Course.findByIdAndDelete(req.params.id);
    console.log("✅ Course and associated data deleted successfully");
    
    res.json({ 
      message: "Course and associated data deleted successfully",
      deletedCourse: {
        id: courseToDelete._id,
        name: courseToDelete.name,
        slug: courseToDelete.slug
      }
    });
  } catch (err) {
    console.error("Error deleting course:", err);
    res.status(500).json({ message: "Error deleting course", error: err.message });
  }
});

// ✅ Get user's courses
app.get("/api/courses/my-courses", authenticateToken, async (req, res) => {
  try {
    const { category, status, featured, limit, skip } = req.query;
    
    let query = { createdBy: req.user.id };
    
    if (category) query.category = category;
    if (status) query.status = status;
    if (featured !== undefined) query.featured = featured === 'true';
    
    const parsedLimit = parseInt(limit) || 50;
    const parsedSkip = parseInt(skip) || 0;
    
    const courses = await Course.find(query)
      .sort({ createdAt: -1 })
      .skip(parsedSkip)
      .limit(parsedLimit);
    
    console.log(`✅ Found ${courses.length} courses for user ${req.user.username}`);
    
    res.json({ 
      courses,
      total: courses.length,
      author: req.user.username
    });
  } catch (err) {
    console.error("Error fetching user courses:", err);
    res.status(500).json({ message: "Error fetching user courses", error: err.message });
  }
});

// ✅ Get course categories
app.get("/api/courses/categories", async (req, res) => {
  try {
    const categories = await Course.distinct("category");
    const categoriesWithCounts = await Course.aggregate([
      { $group: { _id: "$category", count: { $sum: 1 } } },
      { $sort: { count: -1 } }
    ]);
    
    res.json({ 
      categories: categories.sort(),
      categoriesWithCounts
    });
  } catch (err) {
    console.error("Error fetching course categories:", err);
    res.status(500).json({ message: "Error fetching categories", error: err.message });
  }
});

// ✅ Get course tags
app.get("/api/courses/tags", async (req, res) => {
  try {
    const tags = await Course.distinct("tags");
    const sortedTags = tags.sort();
    
    res.json({ 
      tags: sortedTags,
      count: sortedTags.length
    });
  } catch (err) {
    console.error("Error fetching course tags:", err);
    res.status(500).json({ message: "Error fetching course tags", error: err.message });
  }
});

// ✅ Search courses
app.get("/api/courses/search", async (req, res) => {
  try {
    const { q, category, level, minPrice, maxPrice, tags } = req.query;
    
    let query = {};
    
    if (q) {
      const searchRegex = new RegExp(q, 'i');
      query.$or = [
        { name: searchRegex },
        { description: searchRegex },
        { tags: { $in: [searchRegex] } }
      ];
    }
    
    if (category) query.category = category;
    if (level) query.level = level;
    
    if (minPrice !== undefined || maxPrice !== undefined) {
      query.price = {};
      if (minPrice !== undefined) query.price.$gte = parseFloat(minPrice);
      if (maxPrice !== undefined) query.price.$lte = parseFloat(maxPrice);
    }
    
    if (tags) {
      const tagArray = Array.isArray(tags) ? tags : tags.split(',').map(t => t.trim());
      query.tags = { $in: tagArray };
    }
    
    const courses = await Course.find(query)
      .populate('createdBy', 'username')
      .sort({ createdAt: -1 })
      .limit(50);
    
    res.json({ 
      courses,
      searchQuery: q,
      total: courses.length
    });
  } catch (err) {
    console.error("Error searching courses:", err);
    res.status(500).json({ message: "Error searching courses", error: err.message });
  }
});

// ✅ General ping endpoint
app.get("/api/ping", (req, res) => {
  res.json({ 
    message: "Server is running!", 
    timestamp: new Date().toISOString(),
    status: "healthy",
    server: "Express Blog Backend with Course Management"
  });
});

// ✅ Wake/Ping Endpoint
app.get("/api/blogs/ping", (req, res) => {
  res.status(200).json({ message: "Server is awake!" });
});

// ✅ Test endpoint for banner image upload
app.post("/api/test/banner-upload", uploadFields, (req, res) => {
  console.log("Test upload - Files received:", req.files);
  console.log("Test upload - Body:", req.body);
  res.json({
    message: "Test upload successful",
    files: req.files,
    body: req.body
  });
});

// ✅ Fetch all blogs WITH TAGS AND COURSE SUPPORT
app.get("/api/blogs", async (req, res) => {
  try {
    const { category, subcategory, status, tags, limit, skip } = req.query;
    let query = {};
    
    if (category) query.category = category;
    if (subcategory) query.subcategory = subcategory;
    if (status) query.status = status;
    
    // 🆕 Add tag filtering support
    if (tags) {
      const tagArray = Array.isArray(tags) ? tags : tags.split(',').map(t => t.trim());
      query.tags = { $in: tagArray };
    }
    
    const parsedLimit = parseInt(limit) || 8;
    const parsedSkip = parseInt(skip) || 0;
    
    const blogs = await Blog.find(query)
      .populate('courses', 'name slug courseImage courseUrl category level price')
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

// ✅ Fetch blog by SLUG
app.get("/api/blogs/slug/:slug", async (req, res) => {
  try {
    const blog = await Blog.findOne({ slug: req.params.slug })
      .populate('courses', 'name slug description courseImage courseUrl category level price duration tags');
    if (!blog) return res.status(404).json({ message: "Blog not found" });
    res.json(blog);
  } catch (err) {
    res.status(500).json({ message: "Error fetching blog", error: err.message });
  }
});

// ✅ Fetch blog by ID
app.get("/api/blogs/:id", async (req, res) => {
  try {
    if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
      return res.status(400).json({ message: "Invalid Blog ID format" });
    }
    
    const blog = await Blog.findById(req.params.id)
      .populate('courses', 'name slug description courseImage courseUrl category level price duration tags');
    if (!blog) return res.status(404).json({ message: "Blog not found" });
    res.json(blog);
  } catch (err) {
    res.status(500).json({ message: "Error fetching blog", error: err.message });
  }
});

// 🆕 UPDATED: Create a new blog WITH TAGS, BANNER AND COURSE SUPPORT
app.post(
  "/api/blogs",
  authenticateToken,
  blogCourseUploadFields,
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
      
      console.log("📝 Creating blog with data:", {
        title,
        category,
        subcategory,
        author,
        status,
        slug: providedSlug,
        tags: tagsInput,
        courses: coursesInput,
        files: req.files
      });
      
      let blogSlug;
      if (providedSlug) {
        blogSlug = generateSlug(providedSlug);
      } else {
        blogSlug = generateSlug(title);
      }
      blogSlug = await findUniqueSlug(blogSlug, Blog);
      
      // ✅ Handle Featured Image
      let imagePath = null;
      let imagePublicId = null;
      if (req.files && req.files.image && req.files.image[0]) {
        const imageFile = req.files.image[0];
        imagePath = imageFile.path;
        imagePublicId = imageFile.filename || getPublicIdFromUrl(imagePath);
        console.log("📸 Featured image uploaded:", imagePath);
      }
      
      // ✅ Handle Banner Image
      let bannerImagePath = null;
      let bannerImagePublicId = null;
      if (req.files && req.files.bannerImage && req.files.bannerImage[0]) {
        const bannerFile = req.files.bannerImage[0];
        bannerImagePath = bannerFile.path;
        bannerImagePublicId = bannerFile.filename || getPublicIdFromUrl(bannerImagePath);
        console.log("🖼️ Banner image uploaded:", bannerImagePath);
      }
      
      // 🆕 Process tags
      const processedTags = processTags(tagsInput);
      console.log("🏷️ Processed tags:", processedTags);
      
      // 🆕 Process courses data
      let coursesData = [];
      let courseReferences = [];
      
      if (coursesInput) {
        try {
          const coursesArray = typeof coursesInput === 'string' 
            ? JSON.parse(coursesInput) 
            : coursesInput;
          
          if (Array.isArray(coursesArray)) {
            coursesData = coursesArray.map((course, index) => {
              const courseData = {
                name: course.name || '',
                description: course.description || '',
                courseUrl: course.courseUrl || '',
                order: course.order || index
              };
              
              // Handle course images if uploaded
              if (req.files && req.files.courseImages && req.files.courseImages[index]) {
                const file = req.files.courseImages[index];
                courseData.courseImage = file.path;
                courseData.courseImagePublicId = file.filename || getPublicIdFromUrl(file.path);
              }
              
              // If courseId is provided, add to references
              if (course.courseId && mongoose.Types.ObjectId.isValid(course.courseId)) {
                courseReferences.push(course.courseId);
                courseData.courseId = course.courseId;
              }
              
              return courseData;
            });
          }
        } catch (e) {
          console.error('Error processing courses data:', e);
        }
      }
      
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
        courses: courseReferences,
        coursesData
      });
      
      await newBlog.save();
      console.log("✅ Blog created successfully with images, tags, and courses");
      
      res.status(201).json({ 
        message: "Blog created successfully", 
        blog: newBlog 
      });
    } catch (err) {
      // ✅ Cleanup uploaded files if blog creation fails
      if (req.files) {
        if (req.files.image && req.files.image[0]) {
          const imagePublicId = req.files.image[0].filename || getPublicIdFromUrl(req.files.image[0].path);
          await deleteCloudinaryImage(imagePublicId);
        }
        if (req.files.bannerImage && req.files.bannerImage[0]) {
          const bannerPublicId = req.files.bannerImage[0].filename || getPublicIdFromUrl(req.files.bannerImage[0].path);
          await deleteCloudinaryImage(bannerPublicId);
        }
        if (req.files.courseImages) {
          for (const file of req.files.courseImages) {
            const courseImagePublicId = file.filename || getPublicIdFromUrl(file.path);
            await deleteCloudinaryImage(courseImagePublicId);
          }
        }
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

// 🆕 UPDATED: Update a blog WITH TAGS, BANNER AND COURSE SUPPORT
app.put(
  "/api/blogs/:id",
  authenticateToken,
  blogCourseUploadFields,
  async (req, res) => {
    try {
      if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
        return res.status(400).json({ message: "Invalid Blog ID format" });
      }
      
      const existingBlog = await Blog.findById(req.params.id);
      if (!existingBlog)
        return res.status(404).json({ message: "Blog not found" });
      
      let updatedData = { ...req.body };
      
      // 🆕 Process tags if provided
      if (req.body.tags !== undefined) {
        updatedData.tags = processTags(req.body.tags);
        console.log("🏷️ Updated tags:", updatedData.tags);
      }
      
      // Handle slug updates
      if (updatedData.title || updatedData.slug) {
        let baseSlug;
        if (updatedData.slug) {
          baseSlug = generateSlug(updatedData.slug);
        } else {
          baseSlug = generateSlug(updatedData.title || existingBlog.title);
        }
        
        if (baseSlug !== existingBlog.slug) {
          const uniqueSlug = await findUniqueSlug(
            baseSlug,
            Blog,
            existingBlog._id
          );
          updatedData.slug = uniqueSlug;
        } else {
          updatedData.slug = existingBlog.slug;
        }
      }
      
      // ✅ Handle Featured Image Updates
      if (req.files && req.files.image && req.files.image[0]) {
        console.log("📸 Updating featured image");
        // Delete old featured image
        if (existingBlog.imagePublicId) {
          await deleteCloudinaryImage(existingBlog.imagePublicId);
        }
        // Set new featured image
        updatedData.image = req.files.image[0].path;
        updatedData.imagePublicId = req.files.image[0].filename || getPublicIdFromUrl(req.files.image[0].path);
      }
      
      // ✅ Handle Banner Image Updates
      if (req.files && req.files.bannerImage && req.files.bannerImage[0]) {
        console.log("🖼️ Updating banner image");
        // Delete old banner image
        if (existingBlog.bannerImagePublicId) {
          await deleteCloudinaryImage(existingBlog.bannerImagePublicId);
        }
        // Set new banner image
        updatedData.bannerImage = req.files.bannerImage[0].path;
        updatedData.bannerImagePublicId = req.files.bannerImage[0].filename || getPublicIdFromUrl(req.files.bannerImage[0].path);
      }
      
      // 🆕 Process courses data if provided
      if (req.body.courses !== undefined) {
        try {
          const coursesArray = typeof req.body.courses === 'string' 
            ? JSON.parse(req.body.courses) 
            : req.body.courses;
          
          let coursesData = [];
          let courseReferences = [];
          
          if (Array.isArray(coursesArray)) {
            // Delete old course images first
            if (existingBlog.coursesData) {
              await deleteCourseImages(existingBlog.coursesData);
            }
            
            coursesData = coursesArray.map((course, index) => {
              const courseData = {
                name: course.name || '',
                description: course.description || '',
                courseUrl: course.courseUrl || '',
                order: course.order || index
              };
              
              // Handle course images if uploaded
              if (req.files && req.files.courseImages && req.files.courseImages[index]) {
                const file = req.files.courseImages[index];
                courseData.courseImage = file.path;
                courseData.courseImagePublicId = file.filename || getPublicIdFromUrl(file.path);
              }
              
              // If courseId is provided, add to references
              if (course.courseId && mongoose.Types.ObjectId.isValid(course.courseId)) {
                courseReferences.push(course.courseId);
                courseData.courseId = course.courseId;
              }
              
              return courseData;
            });
          }
          
          updatedData.courses = courseReferences;
          updatedData.coursesData = coursesData;
        } catch (e) {
          console.error('Error processing courses update:', e);
        }
      }
      
      const updatedBlog = await Blog.findByIdAndUpdate(
        req.params.id,
        updatedData,
        { new: true, runValidators: true }
      ).populate('courses', 'name slug description courseImage courseUrl category level price duration tags');
      
      console.log("✅ Blog updated successfully with images, tags, and courses");
      res.json({ message: "Blog updated successfully", blog: updatedBlog });
    } catch (err) {
      if (err.code === 11000 && err.keyPattern && err.keyPattern.slug) {
        return res.status(409).json({
          message: "A blog with a similar title/slug already exists. Please choose a unique title or provide a custom slug.",
          error: err.message,
        });
      }
      console.error("Error updating blog:", err);
      res.status(500).json({ message: "Error updating blog", error: err.message });
    }
  }
);

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
    
    // 🆕 Add tag filtering for user posts
    if (tags) {
      const tagArray = Array.isArray(tags) ? tags : tags.split(',').map(t => t.trim());
      query.tags = { $in: tagArray };
    }
    
    const parsedLimit = parseInt(limit) || 50;
    const parsedSkip = parseInt(skip) || 0;
    
    const blogs = await Blog.find(query)
      .populate('courses', 'name slug courseImage courseUrl category level price')
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

// 🆕 NEW: Get all unique tags from all blogs
app.get("/api/blogs/tags", async (req, res) => {
  try {
    const tags = await Blog.distinct("tags");
    const sortedTags = tags.sort();
    
    res.json({ 
      tags: sortedTags,
      count: sortedTags.length
    });
  } catch (err) {
    console.error("Error fetching tags:", err);
    res.status(500).json({ message: "Error fetching tags", error: err.message });
  }
});

// 🆕 NEW: Search blogs by tags
app.get("/api/blogs/search/tags", async (req, res) => {
  try {
    const { tags, limit, skip } = req.query;
    
    if (!tags) {
      return res.status(400).json({ message: "Tags parameter is required" });
    }
    
    const tagArray = Array.isArray(tags) ? tags : tags.split(',').map(t => t.trim());
    const parsedLimit = parseInt(limit) || 10;
    const parsedSkip = parseInt(skip) || 0;
    
    const blogs = await Blog.find({ tags: { $in: tagArray } })
      .populate('courses', 'name slug courseImage courseUrl category level price')
      .sort({ createdAt: -1 })
      .skip(parsedSkip)
      .limit(parsedLimit);
    
    res.json({ 
      blogs,
      searchedTags: tagArray,
      count: blogs.length
    });
  } catch (err) {
    console.error("Error searching blogs by tags:", err);
    res.status(500).json({ message: "Error searching blogs", error: err.message });
  }
});

// ✅ Delete a blog WITH BANNER IMAGE AND COURSE CLEANUP
app.delete("/api/blogs/:id", authenticateToken, async (req, res) => {
  try {
    if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
      return res.status(400).json({ message: "Invalid Blog ID format" });
    }
    
    const blogToDelete = await Blog.findById(req.params.id);
    if (!blogToDelete)
      return res.status(404).json({ message: "Blog not found" });
    
    // ✅ Delete all associated images (featured, banner, and course images)
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
app.listen(PORT, () => console.log(`🚀 Blog server with Course Management running on port ${PORT}`));
