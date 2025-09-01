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
  "http://localhost:3000",
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

// ✅ Blog Schema & Model (EXACTLY as you had it)
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
    status: {
      type: String,
      enum: ["Trending", "Featured", "Editor's Pick", "Recommended", "None"],
      default: "None",
    },
  },
  { timestamps: true }
);

const Blog = mongoose.model("Blog", blogSchema);

// ✅ Configure Cloudinary (EXACTLY as you had it)
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

// ✅ Helper function to extract public_id from Cloudinary URL (EXACTLY as you had it)
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

// ✅ Helper function to delete image from Cloudinary (EXACTLY as you had it)
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

// ✅ Multer Storage for Cloudinary (EXACTLY as you had it)
const storage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: {
    folder: "blog-images",
    format: async (req, file) => "png",
    public_id: (req, file) =>
      Date.now() + "-" + file.originalname.split(".")[0],
  },
});

const upload = multer({ storage });

// --- Helper functions for slug generation (EXACTLY as you had it) ---
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

// --- JWT Authentication Middleware (Enhanced) ---
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
// Add this endpoint after your existing auth routes in blogsPanel.js

// ✅ Validate JWT Token Endpoint
app.get("/api/auth/validate-token", authenticateToken, async (req, res) => {
    try {
      // The authenticateToken middleware has already validated the token
      // and attached user info to req.user
      
      // Optionally fetch fresh user data from database
      const user = await User.findById(req.user.id);
      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }
  
      if (!user.isActive) {
        return res.status(403).json({ message: "Account is inactive" });
      }
  
      // Return user profile data
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
  
  // ✅ Optional: Logout Endpoint (for cleanup on backend if needed)
  app.post("/api/auth/logout", authenticateToken, async (req, res) => {
    try {
      // Optional: Update user's last logout time or invalidate refresh tokens
      const user = await User.findById(req.user.id);
      if (user) {
        // You could add a lastLogout field to your User model if needed
        // user.lastLogout = new Date();
        // await user.save();
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

// Register User (Enhanced)
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

// Login User (Enhanced)
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
// Add these after your existing auth routes

// ✅ Get all users (Admin/SuperAdmin only)
app.get("/api/auth/users", authenticateToken, async (req, res) => {
  try {
    // Check if user has admin or superadmin role
    if (!['admin', 'superadmin'].includes(req.user.role.toLowerCase())) {
      return res.status(403).json({ 
        message: "Access denied. Admin privileges required.",
        requiredRole: ["admin", "superadmin"],
        currentRole: req.user.role
      });
    }

    console.log(`Admin ${req.user.username} fetching all users`);
    
    // Fetch all users from database (exclude passwords)
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

// ✅ Get specific user by ID (Admin/SuperAdmin only)
app.get("/api/auth/users/:id", authenticateToken, async (req, res) => {
  try {
    if (!['admin', 'superadmin'].includes(req.user.role.toLowerCase())) {
      return res.status(403).json({ 
        message: "Access denied. Admin privileges required." 
      });
    }

    const { id } = req.params;

    // Validate MongoDB ObjectId format
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

// ✅ Update user (Admin/SuperAdmin only)
app.put("/api/auth/users/:id", authenticateToken, async (req, res) => {
  try {
    if (!['admin', 'superadmin'].includes(req.user.role.toLowerCase())) {
      return res.status(403).json({ 
        message: "Access denied. Admin privileges required." 
      });
    }

    const { id } = req.params;
    const { username, email, role, isActive } = req.body;

    // Validate MongoDB ObjectId format
    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({ message: "Invalid user ID format" });
    }

    // Find the user to update
    const userToUpdate = await User.findById(id);
    if (!userToUpdate) {
      return res.status(404).json({ message: "User not found" });
    }

    // Prevent updating main admin
    if (userToUpdate.username === 'admin' && username && username !== 'admin') {
      return res.status(403).json({ 
        message: "Cannot change main admin username" 
      });
    }

    // Only superadmin can promote to superadmin
    if (role === 'superadmin' && req.user.role.toLowerCase() !== 'superadmin') {
      return res.status(403).json({ 
        message: "Only superadmin can promote users to superadmin role" 
      });
    }

    // Update user fields
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

// ✅ Delete user (Admin/SuperAdmin only)
app.delete("/api/auth/users/:id", authenticateToken, async (req, res) => {
  try {
    // Check if user has admin or superadmin role
    if (!['admin', 'superadmin'].includes(req.user.role.toLowerCase())) {
      return res.status(403).json({ 
        message: "Access denied. Admin privileges required." 
      });
    }

    const { id } = req.params;
    console.log(`Admin ${req.user.username} attempting to delete user: ${id}`);

    // Validate MongoDB ObjectId format
    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({ message: "Invalid user ID format" });
    }

    // Find the user to delete
    const userToDelete = await User.findById(id);
    if (!userToDelete) {
      return res.status(404).json({ message: "User not found" });
    }

    console.log(`Found user to delete: ${userToDelete.username}`);

    // Prevent deletion of main admin
    if (userToDelete.username === 'admin') {
      return res.status(403).json({ 
        message: "Cannot delete the main admin user" 
      });
    }

    // Prevent self-deletion
    if (userToDelete._id.toString() === req.user.id) {
      return res.status(403).json({ 
        message: "Cannot delete yourself" 
      });
    }

    // Only superadmin can delete other superadmins
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

// ✅ Add general ping endpoint for frontend health checks
app.get("/api/ping", (req, res) => {
  res.json({ 
    message: "Server is running!", 
    timestamp: new Date().toISOString(),
    status: "healthy",
    server: "Express Blog Backend"
  });
});


// === Wake/Ping Endpoint (EXACTLY as you had it) ===
app.get("/api/blogs/ping", (req, res) => {
  res.status(200).json({ message: "Server is awake!" });
});

// ✅ Fetch all blogs (EXACTLY as you had it)
app.get("/api/blogs", async (req, res) => {
  try {
    const { category, subcategory, status, limit, skip } = req.query;
    let query = {};
    if (category) query.category = category;
    if (subcategory) query.subcategory = subcategory;
    if (status) query.status = status;

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

// ✅ Fetch blog by SLUG (EXACTLY as you had it)
app.get("/api/blogs/slug/:slug", async (req, res) => {
  try {
    const blog = await Blog.findOne({ slug: req.params.slug });
    if (!blog) return res.status(404).json({ message: "Blog not found" });

    res.json(blog);
  } catch (err) {
    res.status(500).json({ message: "Error fetching blog", error: err.message });
  }
});

// ✅ Fetch blog by ID (EXACTLY as you had it)
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

// ✅ Create a new blog (EXACTLY as you had it)
app.post(
  "/api/blogs",
  authenticateToken,
  upload.single("image"),
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
      } = req.body;

      let blogSlug;
      if (providedSlug) {
        blogSlug = generateSlug(providedSlug);
      } else {
        blogSlug = generateSlug(title);
      }
      blogSlug = await findUniqueSlug(blogSlug, Blog);

      let imagePath = null;
      let imagePublicId = null;

      if (req.file) {
        imagePath = req.file.path;
        imagePublicId = req.file.filename || getPublicIdFromUrl(imagePath);
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
        status: status || "None",
      });

      await newBlog.save();

      res.status(201).json({ message: "Blog created successfully", blog: newBlog });
    } catch (err) {
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

// ✅ Update a blog (EXACTLY as you had it)
app.put(
  "/api/blogs/:id",
  authenticateToken,
  upload.single("image"),
  async (req, res) => {
    try {
      if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
        return res.status(400).json({ message: "Invalid Blog ID format" });
      }

      const existingBlog = await Blog.findById(req.params.id);
      if (!existingBlog)
        return res.status(404).json({ message: "Blog not found" });

      let updatedData = { ...req.body };

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

      if (req.file) {
        if (existingBlog.imagePublicId) {
          await deleteCloudinaryImage(existingBlog.imagePublicId);
        }
        updatedData.image = req.file.path;
        updatedData.imagePublicId =
          req.file.filename || getPublicIdFromUrl(req.file.path);
      }

      const updatedBlog = await Blog.findByIdAndUpdate(
        req.params.id,
        updatedData,
        { new: true, runValidators: true }
      );

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
    const { category, subcategory, status, limit, skip } = req.query;
    
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
// ✅ Delete a blog (EXACTLY as you had it)
app.delete("/api/blogs/:id", authenticateToken, async (req, res) => {
  try {
    if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
      return res.status(400).json({ message: "Invalid Blog ID format" });
    }

    const blogToDelete = await Blog.findById(req.params.id);
    if (!blogToDelete)
      return res.status(404).json({ message: "Blog not found" });

    if (blogToDelete.imagePublicId) {
      await deleteCloudinaryImage(blogToDelete.imagePublicId);
    }

    await Blog.findByIdAndDelete(req.params.id);

    res.json({ message: "Blog and associated image deleted successfully" });
  } catch (err) {
    console.error("Error deleting blog:", err);
    res.status(500).json({ message: "Error deleting blog", error: err.message });
  }
});


// ✅ Start the blog server (EXACTLY as you had it)
const PORT = process.env.BLOG_PORT || 5002;
app.listen(PORT, () => console.log(`🚀 Blog server running on port ${PORT}`));
