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
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
  credentials: true,
};

app.use(cors(corsOptions));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// ✅ Enhanced CORS and Error Handling Middleware
app.use((req, res, next) => {
  // Set CORS headers for all responses (including errors)
  res.header('Access-Control-Allow-Origin', req.headers.origin || '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
  res.header('Access-Control-Allow-Credentials', 'true');
  
  // Handle preflight OPTIONS requests
  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }
  
  next();
});

// ✅ Request Logging Middleware
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.url}`);
  console.log("Origin:", req.headers.origin);
  if (['POST', 'PUT'].includes(req.method) && req.body) {
    console.log('Body Keys:', Object.keys(req.body));
  }
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

userSchema.index({ username: 1 }, { unique: true });
userSchema.index({ email: 1 }, { unique: true, sparse: true });

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

userSchema.methods.comparePassword = async function(candidatePassword) {
  try {
    return await bcrypt.compare(candidatePassword, this.password);
  } catch (error) {
    console.error('Password comparison error:', error);
    throw error;
  }
};

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

// ✅ FIXED Blog Schema with Flexible Courses
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
    bannerImage: { type: String },
    bannerImagePublicId: { type: String },
    status: {
      type: String,
      enum: ["Trending", "Featured", "Editor's Pick", "Recommended", "None"],
      default: "None",
    },
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
    // ✅ FIXED: Flexible courses field
    courses: {
      type: [{
        heading: {
          type: String,
          required: false, // ✅ Changed to false
          trim: true,
          maxLength: 100,
          default: ''
        },
        description: {
          type: String,
          required: false, // ✅ Changed to false
          trim: true,
          maxLength: 300,
          default: ''
        },
        url: {
          type: String,
          required: false, // ✅ Changed to false
          trim: true,
          validate: {
            validator: function(v) {
              return !v || /^https?:\/\/.+/.test(v);
            },
            message: 'Please enter a valid URL or leave empty'
          },
          default: ''
        },
        image: {
          type: String,
          default: null
        },
        imagePublicId: {
          type: String,
          default: null
        }
      }],
      default: []
    }
  },
  { timestamps: true }
);

blogSchema.index({ tags: 1 });
const Blog = mongoose.model("Blog", blogSchema);

// ✅ Course Schema for Individual Course Management
const courseSchema = new mongoose.Schema(
  {
    heading: {
      type: String,
      required: true,
      trim: true,
      maxLength: [100, 'Course heading cannot be longer than 100 characters']
    },
    description: {
      type: String,
      required: true,
      trim: true,
      maxLength: [300, 'Course description cannot be longer than 300 characters']
    },
    url: {
      type: String,
      required: true,
      trim: true,
      validate: {
        validator: function(v) {
          return /^https?:\/\/.+/.test(v);
        },
        message: 'Please enter a valid URL starting with http:// or https://'
      }
    },
    image: { type: String },
    imagePublicId: { type: String },
    createdBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true
    },
    authorName: {
      type: String,
      required: true,
      trim: true
    },
    category: {
      type: String,
      trim: true,
      default: 'General'
    },
    isActive: {
      type: Boolean,
      default: true
    },
    priority: {
      type: Number,
      default: 0
    }
  },
  { 
    timestamps: true,
    toJSON: { virtuals: true },
    toObject: { virtuals: true }
  }
);

courseSchema.index({ heading: 1, category: 1 });
courseSchema.index({ createdBy: 1, createdAt: -1 });
const Course = mongoose.model("Course", courseSchema);

// ✅ Configure Cloudinary
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

// ✅ Helper Functions
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

const deleteCloudinaryImage = async (publicId) => {
  if (!publicId) return;
  try {
    console.log(`Attempting to delete Cloudinary image: ${publicId}`);
    const result = await cloudinary.uploader.destroy(publicId);
    console.log(`Cloudinary deletion result:`, result);
    return result;
  } catch (error) {
    console.error(`Error deleting Cloudinary image ${publicId}:`, error);
  }
};

// ✅ Course Validation Helper
const validateCourseData = (course) => {
  const errors = [];
  
  if (course.heading && course.heading.length > 100) {
    errors.push('Course heading cannot exceed 100 characters');
  }
  
  if (course.description && course.description.length > 300) {
    errors.push('Course description cannot exceed 300 characters');
  }
  
  if (course.url && course.url.trim() && !/^https?:\/\/.+/.test(course.url.trim())) {
    errors.push('Course URL must be a valid URL starting with http:// or https://');
  }
  
  return errors;
};

// ✅ Multer Configuration
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

// ✅ Tag Processing Helper
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

// ✅ Slug Generation Helpers
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

// ✅ Global Error Handler
app.use((error, req, res, next) => {
  res.header('Access-Control-Allow-Origin', req.headers.origin || '*');
  res.header('Access-Control-Allow-Credentials', 'true');
  
  console.error('❌ Global error handler:', error);
  
  res.status(error.status || 500).json({
    success: false,
    message: error.message || 'Internal server error',
    error: process.env.NODE_ENV === 'development' ? error.stack : undefined,
    timestamp: new Date().toISOString(),
    path: req.url,
    method: req.method
  });
});

// ================ HEALTH CHECK & TEST ENDPOINTS ================

// ✅ Health Check Endpoint
app.get("/api/health", async (req, res) => {
  try {
    const dbStatus = mongoose.connection.readyState === 1 ? 'connected' : 'disconnected';
    const blogCount = await Blog.countDocuments();
    
    res.json({
      success: true,
      message: "Blog API is healthy",
      timestamp: new Date().toISOString(),
      version: "1.0.0",
      environment: process.env.NODE_ENV || 'development',
      database: {
        status: dbStatus,
        blogCount: blogCount
      },
      server: {
        port: process.env.BLOG_PORT || 5002,
        uptime: process.uptime()
      }
    });
  } catch (err) {
    console.error('Health check error:', err);
    res.status(500).json({
      success: false,
      message: "Health check failed",
      error: err.message
    });
  }
});

// ✅ Course Testing Endpoint
app.post("/api/test/courses", authenticateToken, upload.fields([
  { name: 'courseImage0', maxCount: 1 },
  { name: 'courseImage1', maxCount: 1 }
]), async (req, res) => {
  try {
    console.log("🧪 Test courses endpoint");
    console.log("Body:", req.body);
    console.log("Files:", req.files);
    
    const { coursesData } = req.body;
    
    if (coursesData) {
      const parsed = JSON.parse(coursesData);
      console.log("Parsed courses:", parsed);
      
      const validationResults = parsed.map((course, index) => ({
        index,
        course,
        errors: validateCourseData(course)
      }));
      
      res.json({
        success: true,
        message: "Course test successful",
        coursesData,
        parsed,
        validationResults,
        files: Object.keys(req.files || {})
      });
    } else {
      res.json({
        success: false,
        message: "No coursesData provided",
        body: req.body
      });
    }
  } catch (err) {
    console.error("Test courses error:", err);
    res.status(500).json({
      success: false,
      error: err.message,
      coursesData: req.body.coursesData
    });
  }
});

// ================ AUTHENTICATION ENDPOINTS ================

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

app.post("/api/auth/logout", authenticateToken, async (req, res) => {
  try {
    res.json({ message: "Logged out successfully" });
  } catch (err) {
    console.error("Logout error:", err);
    res.status(500).json({ 
      message: "Error during logout", 
      error: err.message 
    });
  }
});

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

// ================ BLOG ENDPOINTS ================

// ✅ FIXED: Get all unique tags with better error handling
app.get("/api/blogs/tags", async (req, res) => {
  try {
    console.log("🏷️ Fetching tags...");
    
    const blogCount = await Blog.countDocuments();
    console.log(`Found ${blogCount} blogs in database`);
    
    if (blogCount === 0) {
      console.log("No blogs found, returning empty tags array");
      return res.json({ 
        success: true,
        tags: [],
        count: 0,
        message: "No blogs found"
      });
    }

    const tags = await Blog.distinct("tags");
    console.log("Raw tags from database:", tags);
    
    const validTags = tags
      .filter(tag => tag && typeof tag === 'string' && tag.trim().length > 0)
      .map(tag => tag.toLowerCase().trim())
      .filter((tag, index, array) => array.indexOf(tag) === index)
      .sort();

    console.log(`✅ Processed ${validTags.length} unique valid tags`);
    
    res.json({ 
      success: true,
      tags: validTags,
      count: validTags.length
    });
  } catch (err) {
    console.error("❌ Error fetching tags:", err);
    res.status(500).json({ 
      success: false,
      message: "Error fetching tags", 
      error: err.message 
    });
  }
});

// ✅ FIXED: Fetch blog by ID with detailed validation
app.get("/api/blogs/:id", async (req, res) => {
  try {
    const blogId = req.params.id;
    console.log(`🔍 Fetching blog with ID: ${blogId}`);

    if (!blogId || blogId.length !== 24) {
      console.log(`❌ Invalid Blog ID length: ${blogId?.length}/24 characters`);
      return res.status(400).json({ 
        success: false,
        message: "Invalid Blog ID format - must be 24 characters", 
        receivedId: blogId,
        expectedLength: 24,
        actualLength: blogId?.length || 0
      });
    }

    if (!mongoose.Types.ObjectId.isValid(blogId)) {
      console.log(`❌ Invalid Blog ID format: ${blogId}`);
      return res.status(400).json({ 
        success: false,
        message: "Invalid Blog ID format - not a valid MongoDB ObjectId",
        receivedId: blogId
      });
    }
    
    const blog = await Blog.findById(blogId);
    
    if (!blog) {
      console.log(`❌ Blog not found with ID: ${blogId}`);
      return res.status(404).json({ 
        success: false,
        message: "Blog not found",
        searchedId: blogId
      });
    }

    console.log(`✅ Blog found: "${blog.title}" (${blog._id})`);
    res.json({
      success: true,
      ...blog.toObject()
    });
    
  } catch (err) {
    console.error(`❌ Error fetching blog ${req.params.id}:`, err);
    
    if (err.name === 'CastError') {
      return res.status(400).json({ 
        success: false,
        message: "Invalid Blog ID format - MongoDB CastError",
        error: err.message,
        receivedId: req.params.id
      });
    }

    res.status(500).json({ 
      success: false,
      message: "Internal server error while fetching blog", 
      error: err.message,
      requestedId: req.params.id
    });
  }
});

app.get("/api/blogs", async (req, res) => {
  try {
    const { category, subcategory, status, tags, limit, skip } = req.query;
    let query = {};
    
    if (category) query.category = category;
    if (subcategory) query.subcategory = subcategory;
    if (status) query.status = status;
    
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

app.get("/api/blogs/slug/:slug", async (req, res) => {
  try {
    const blog = await Blog.findOne({ slug: req.params.slug });
    if (!blog) return res.status(404).json({ message: "Blog not found" });
    res.json(blog);
  } catch (err) {
    res.status(500).json({ message: "Error fetching blog", error: err.message });
  }
});

// ✅ FIXED: Create blog with proper course handling
app.post(
  "/api/blogs",
  authenticateToken,
  upload.fields([
    { name: 'image', maxCount: 1 },
    { name: 'bannerImage', maxCount: 1 },
    { name: 'courseImage0', maxCount: 1 },
    { name: 'courseImage1', maxCount: 1 },
    { name: 'courseImage2', maxCount: 1 },
    { name: 'courseImage3', maxCount: 1 },
    { name: 'courseImage4', maxCount: 1 },
    { name: 'courseImage5', maxCount: 1 },
    { name: 'courseImage6', maxCount: 1 },
    { name: 'courseImage7', maxCount: 1 },
    { name: 'courseImage8', maxCount: 1 },
    { name: 'courseImage9', maxCount: 1 }
  ]),
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
        coursesData
      } = req.body;
      
      console.log("📝 Creating blog with data:", {
        title,
        category,
        subcategory,
        author,
        status,
        slug: providedSlug,
        tags: tagsInput,
        coursesData: coursesData ? 'Present' : 'Not present',
        files: Object.keys(req.files || {})
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
      
      const processedTags = processTags(tagsInput);
      console.log("🏷️ Processed tags:", processedTags);
      
      // ✅ FIXED: Better courses processing
      let courses = [];
      if (coursesData) {
        try {
          console.log("🎓 Processing courses data:", coursesData);
          const parsedCourses = JSON.parse(coursesData);
          
          if (Array.isArray(parsedCourses)) {
            for (let i = 0; i < parsedCourses.length; i++) {
              const courseData = parsedCourses[i];
              
              // Skip empty courses
              if (!courseData.heading && !courseData.description && !courseData.url) {
                console.log(`Skipping empty course at index ${i}`);
                continue;
              }
              
              // Handle course image upload
              const courseImageField = `courseImage${i}`;
              let courseImagePath = null;
              let courseImagePublicId = null;
              
              if (req.files && req.files[courseImageField] && req.files[courseImageField][0]) {
                const courseImageFile = req.files[courseImageField][0];
                courseImagePath = courseImageFile.path;
                courseImagePublicId = courseImageFile.filename || getPublicIdFromUrl(courseImageFile.path);
                console.log(`📸 Course ${i} image uploaded:`, courseImagePath);
              }
              
              // Build course object with validation
              const courseObj = {
                heading: courseData.heading?.trim() || '',
                description: courseData.description?.trim() || '',
                url: courseData.url?.trim() || '',
                image: courseImagePath,
                imagePublicId: courseImagePublicId
              };
              
              // Only add course if it has meaningful content
              if (courseObj.heading || courseObj.description || courseObj.url) {
                courses.push(courseObj);
                console.log(`✅ Added course ${i}:`, courseObj.heading);
              }
            }
          }
        } catch (e) {
          console.error('❌ Error parsing courses data:', e);
          console.log('Raw coursesData:', coursesData);
          courses = [];
        }
      }
      
      console.log(`🎓 Final courses count: ${courses.length}`);

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
        courses: courses
      });
      
      await newBlog.save();
      console.log("✅ Blog created successfully with courses and images");
      
      res.status(201).json({ 
        message: "Blog created successfully", 
        blog: newBlog,
        coursesAdded: courses.length
      });
      
    } catch (err) {
      // Enhanced cleanup for failed blog creation
      if (req.files) {
        console.log("🧹 Cleaning up uploaded files due to error");
        const cleanupPromises = [];
        
        // Cleanup main images
        if (req.files.image && req.files.image[0]) {
          const imagePublicId = req.files.image[0].filename || getPublicIdFromUrl(req.files.image[0].path);
          cleanupPromises.push(deleteCloudinaryImage(imagePublicId));
        }
        if (req.files.bannerImage && req.files.bannerImage[0]) {
          const bannerPublicId = req.files.bannerImage[0].filename || getPublicIdFromUrl(req.files.bannerImage[0].path);
          cleanupPromises.push(deleteCloudinaryImage(bannerPublicId));
        }
        
        // Cleanup course images
        for (let i = 0; i < 10; i++) {
          const courseImageField = `courseImage${i}`;
          if (req.files[courseImageField] && req.files[courseImageField][0]) {
            const courseImagePublicId = req.files[courseImageField][0].filename || getPublicIdFromUrl(req.files[courseImageField][0].path);
            cleanupPromises.push(deleteCloudinaryImage(courseImagePublicId));
          }
        }
        
        if (cleanupPromises.length > 0) {
          await Promise.allSettled(cleanupPromises);
          console.log("🧹 Cleanup completed");
        }
      }
      
      if (err.code === 11000 && err.keyPattern && err.keyPattern.slug) {
        return res.status(409).json({
          message: "A blog with a similar title/slug already exists. Please choose a unique title or provide a custom slug.",
          error: err.message,
        });
      }
      
      console.error("❌ Error creating blog:", err);
      res.status(500).json({ 
        message: "Error creating blog", 
        error: err.message,
        details: process.env.NODE_ENV === 'development' ? err.stack : undefined
      });
    }
  }
);

// ✅ Blog Update and Delete endpoints (shortened for space)
app.put("/api/blogs/:id", authenticateToken, upload.fields([
  { name: 'image', maxCount: 1 },
  { name: 'bannerImage', maxCount: 1 }
]), async (req, res) => {
  try {
    if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
      return res.status(400).json({ message: "Invalid Blog ID format" });
    }
    
    const existingBlog = await Blog.findById(req.params.id);
    if (!existingBlog)
      return res.status(404).json({ message: "Blog not found" });
    
    let updatedData = { ...req.body };
    
    if (req.body.tags !== undefined) {
      updatedData.tags = processTags(req.body.tags);
    }
    
    if (updatedData.title || updatedData.slug) {
      let baseSlug;
      if (updatedData.slug) {
        baseSlug = generateSlug(updatedData.slug);
      } else {
        baseSlug = generateSlug(updatedData.title || existingBlog.title);
      }
      
      if (baseSlug !== existingBlog.slug) {
        const uniqueSlug = await findUniqueSlug(baseSlug, Blog, existingBlog._id);
        updatedData.slug = uniqueSlug;
      } else {
        updatedData.slug = existingBlog.slug;
      }
    }
    
    if (req.files && req.files.image && req.files.image[0]) {
      if (existingBlog.imagePublicId) {
        await deleteCloudinaryImage(existingBlog.imagePublicId);
      }
      updatedData.image = req.files.image[0].path;
      updatedData.imagePublicId = req.files.image[0].filename || getPublicIdFromUrl(req.files.image[0].path);
    }
    
    if (req.files && req.files.bannerImage && req.files.bannerImage[0]) {
      if (existingBlog.bannerImagePublicId) {
        await deleteCloudinaryImage(existingBlog.bannerImagePublicId);
      }
      updatedData.bannerImage = req.files.bannerImage[0].path;
      updatedData.bannerImagePublicId = req.files.bannerImage[0].filename || getPublicIdFromUrl(req.files.bannerImage[0].path);
    }
    
    const updatedBlog = await Blog.findByIdAndUpdate(
      req.params.id,
      updatedData,
      { new: true, runValidators: true }
    );
    
    res.json({ message: "Blog updated successfully", blog: updatedBlog });
  } catch (err) {
    console.error("Error updating blog:", err);
    res.status(500).json({ message: "Error updating blog", error: err.message });
  }
});

app.delete("/api/blogs/:id", authenticateToken, async (req, res) => {
  try {
    if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
      return res.status(400).json({ message: "Invalid Blog ID format" });
    }
    
    const blogToDelete = await Blog.findById(req.params.id);
    if (!blogToDelete)
      return res.status(404).json({ message: "Blog not found" });
    
    const deletePromises = [];
    
    if (blogToDelete.imagePublicId) {
      deletePromises.push(deleteCloudinaryImage(blogToDelete.imagePublicId));
    }
    
    if (blogToDelete.bannerImagePublicId) {
      deletePromises.push(deleteCloudinaryImage(blogToDelete.bannerImagePublicId));
    }
    
    // Delete course images
    if (blogToDelete.courses && blogToDelete.courses.length > 0) {
      blogToDelete.courses.forEach(course => {
        if (course.imagePublicId) {
          deletePromises.push(deleteCloudinaryImage(course.imagePublicId));
        }
      });
    }
    
    if (deletePromises.length > 0) {
      await Promise.all(deletePromises);
    }
    
    await Blog.findByIdAndDelete(req.params.id);
    
    res.json({ message: "Blog and associated images deleted successfully" });
  } catch (err) {
    console.error("Error deleting blog:", err);
    res.status(500).json({ message: "Error deleting blog", error: err.message });
  }
});

// ================ COURSE MANAGEMENT ENDPOINTS ================

app.get("/api/courses", async (req, res) => {
  try {
    const { category, limit, skip, createdBy } = req.query;
    let query = { isActive: true };
    
    if (category) query.category = category;
    if (createdBy) query.createdBy = createdBy;
    
    const parsedLimit = parseInt(limit) || 50;
    const parsedSkip = parseInt(skip) || 0;
    
    const courses = await Course.find(query)
      .sort({ priority: -1, createdAt: -1 })
      .skip(parsedSkip)
      .limit(parsedLimit + 1)
      .populate('createdBy', 'username');
    
    const hasMore = courses.length > parsedLimit;
    const coursesToSend = hasMore ? courses.slice(0, parsedLimit) : courses;
    
    res.json({ 
      success: true,
      courses: coursesToSend, 
      hasMore,
      total: coursesToSend.length
    });
  } catch (err) {
    console.error("Error fetching courses:", err);
    res.status(500).json({ 
      success: false,
      message: "Error fetching courses", 
      error: err.message 
    });
  }
});

app.post("/api/courses", authenticateToken, upload.single('image'), async (req, res) => {
  try {
    const { heading, description, url, category, priority } = req.body;
    
    if (!heading || !description || !url) {
      return res.status(400).json({
        success: false,
        message: 'Heading, description, and URL are required'
      });
    }

    let imagePath = null;
    let imagePublicId = null;
    if (req.file) {
      imagePath = req.file.path;
      imagePublicId = req.file.filename || getPublicIdFromUrl(imagePath);
    }

    const courseData = {
      heading: heading.trim(),
      description: description.trim(),
      url: url.trim(),
      category: category?.trim() || 'General',
      priority: parseInt(priority) || 0,
      image: imagePath,
      imagePublicId,
      createdBy: req.user.id,
      authorName: req.user.username
    };

    const course = new Course(courseData);
    await course.save();
    await course.populate('createdBy', 'username');
    
    res.status(201).json({
      success: true,
      message: 'Course created successfully',
      course
    });
  } catch (error) {
    if (req.file) {
      const imagePublicId = req.file.filename || getPublicIdFromUrl(req.file.path);
      await deleteCloudinaryImage(imagePublicId);
    }
    
    console.error('Error creating course:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to create course',
      error: error.message
    });
  }
});

// Add other course endpoints (PUT, DELETE, GET by ID)...

// ================ GENERAL ENDPOINTS ================

app.get("/api/ping", (req, res) => {
  res.json({ 
    message: "Server is running!", 
    timestamp: new Date().toISOString(),
    status: "healthy",
    server: "Express Blog Backend"
  });
});

// ✅ Start the server
const PORT = process.env.BLOG_PORT || 5002;
app.listen(PORT, () => console.log(`🚀 Blog server running on port ${PORT}`));
