const express = require("express");
const cors = require("cors");
require("dotenv").config();
const cookieParser = require("cookie-parser");
const app = express();
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

// Middleware
app.use(
  cors({
    origin: ["http://localhost:5173"],
    credentials: true,
  })
);
app.use(express.json());
app.use(cookieParser());

// Port
const port = process.env.PORT || 5000;

// MongoDB Setup
const { MongoClient, ServerApiVersion } = require("mongodb");
const uri = process.env.URI;

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});
const verifyToken = (req, res, next) => {
  const token = req.cookies.token;

  if (!token) {
    return res.status(401).json({ message: "Unauthorized: No token" });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(403).json({ message: "Forbidden: Invalid token" });
  }
};

async function run() {
  try {
    await client.connect();
    await client.db("admin").command({ ping: 1 });
    console.log(" Connected to MongoDB");

    const districtCollection = client.db("GeocodeDB").collection("Districts");
    const upazilaCollection = client.db("GeocodeDB").collection("Upazilas");
    const UsersCollection = client.db("UserDB").collection("Users");
    const TaskCollection = client.db("TaskDB").collection("Tasks");

    // Route: Upload all upazila data
    app.post("/upload-upazilas", async (req, res) => {
      try {
        const upazilas = req.body;

        // Validate data
        if (!Array.isArray(upazilas) || upazilas.length === 0) {
          return res.status(400).json({ message: "Invalid or empty data" });
        }

        // Insert into MongoDB
        const result = await upazilaCollection.insertMany(upazilas);

        res.status(201).json({
          message: "Upazilas uploaded successfully",
          insertedCount: result.insertedCount,
        });
      } catch (error) {
        console.error(" Upload error:", error);
        res.status(500).json({ message: "Internal Server Error", error });
      }
    });

    // Route: Get all upazilas
    app.get("/geocode/upazilas", async (req, res) => {
      try {
        const upazilas = await upazilaCollection.find().toArray();
        res.status(200).json(upazilas);
      } catch (error) {
        console.error("Fetch error:", error);
        res.status(500).json({ message: "Internal Server Error", error });
      }
    });

    // Route: Upload all upazila data
    app.post("/upload-districts", async (req, res) => {
      try {
        const districts = req.body;

        // Validate data
        if (!Array.isArray(districts) || districts.length === 0) {
          return res.status(400).json({ message: "Invalid or empty data" });
        }

        // Insert into MongoDB
        const result = await districtCollection.insertMany(districts);

        res.status(201).json({
          message: "districts uploaded successfully",
          insertedCount: result.insertedCount,
        });
      } catch (error) {
        console.error(" Upload error:", error);
        res.status(500).json({ message: "Internal Server Error", error });
      }
    });

    // Route: Get all districts
    app.get("/geocode/districts", async (req, res) => {
      try {
        const districts = await districtCollection.find().toArray();
        res.status(200).json(districts);
      } catch (error) {
        console.error("Fetch error:", error);
        res.status(500).json({ message: "Internal Server Error", error });
      }
    });

    //Upload user to Database
    app.post("/api/register", async (req, res) => {
      try {
        const {
          name,
          email,
          phone,
          passwordHash, // frontend sends plain password in "passwordHash"
          avatarUrl,
          roles,
          bloodGroup,
          status,
          ratingAvg,
          ratingCount,
          address, // contains district & upazila
          createdAt,
        } = req.body;

        // Check if user already exists
        const existingUser = await UsersCollection.findOne({ email });
        if (existingUser) {
          return res.status(409).json({ message: "User already exists" });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(passwordHash, 10);

        // Create new user
        const newUser = {
          name,
          email,
          phone,
          password: hashedPassword,
          avatar: avatarUrl,
          roles: roles || ["user"],
          bloodGroup,
          status: status || "active",
          ratingAvg: ratingAvg || 0,
          ratingCount: ratingCount || 0,
          address: {
            district: address?.district || "",
            upazila: address?.upazila || "",
          },
          createdAt: createdAt ? new Date(createdAt) : new Date(),
        };

        // Insert into database
        const result = await UsersCollection.insertOne(newUser);

        // Generate JWT
        const token = jwt.sign({ email }, process.env.JWT_SECRET, {
          expiresIn: "7d",
        });

        // Set cookie
        res.cookie("token", token, {
          httpOnly: true,
          secure: true, // required for cross-site cookies
          sameSite: "none", // required for cross-site cookies
          maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
        });

        res.status(201).json({
          message: "Registration successful",
          userId: result.insertedId,
        });
      } catch (error) {
        console.error("Registration Error:", error);
        res.status(500).json({
          message: "Registration failed",
          error: error.message,
        });
      }
    });

    //user login
    app.post("/api/login", async (req, res) => {
      try {
        const { email, password } = req.body;

        const user = await UsersCollection.findOne({ email });
        if (!user) return res.status(404).json({ message: "User not found" });

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch)
          return res.status(401).json({ message: "Invalid password" });

        const token = jwt.sign({ email: user.email }, process.env.JWT_SECRET, {
          expiresIn: "7d",
        });

        res.cookie("token", token, {
          httpOnly: true,
          secure: true, //  required for cross-site cookies
          sameSite: "none", //  required for cross-site cookies
          maxAge: 7 * 24 * 60 * 60 * 1000,
        });
        res.status(200).json({ message: "Login successful", user });
      } catch (err) {
        res.status(500).json({ message: "Login failed", error: err.message });
      }
    });

    //Logout user
    app.post("/api/logout", (req, res) => {
      res.clearCookie("token", {
        httpOnly: true,
        secure: true,
        sameSite: "none",
      });

      res.status(200).json({ message: "Logout successful" });
    });

    //Check if user is logged in
    app.get("/api/me", async (req, res) => {
      try {
        const token = req.cookies.token;
        if (!token) return res.status(401).json({ message: "Unauthorized" });

        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const user = await UsersCollection.findOne({ email: decoded.email });

        if (!user) return res.status(404).json({ message: "User not found" });

        res.status(200).json({ user });
      } catch (err) {
        res.status(401).json({ message: "Unauthorized", error: err.message });
      }
    });

    // ✅ Update user profile (name, phone, bloodGroup, avatar, district, upazila)
    app.patch("/api/users/:email", verifyToken, async (req, res) => {
      try {
        const { email } = req.params;
        const {
          name,
          phone,
          bloodGroup,
          avatarUrl,
          address, // contains district & upazila
        } = req.body;

        // Authorization check
        if (req.user.email !== email) {
          return res
            .status(403)
            .json({ message: "Forbidden: Not your profile" });
        }

        // Prepare update object dynamically
        const updateDoc = {
          $set: {},
        };

        if (name) updateDoc.$set.name = name;
        if (phone) updateDoc.$set.phone = phone;
        if (bloodGroup) updateDoc.$set.bloodGroup = bloodGroup;
        if (avatarUrl) updateDoc.$set.avatar = avatarUrl;
        if (address) {
          updateDoc.$set["address.district"] = address.district || "";
          updateDoc.$set["address.upazila"] = address.upazila || "";
        }

        const result = await UsersCollection.updateOne({ email }, updateDoc);

        if (result.matchedCount === 0) {
          return res.status(404).json({ message: "User not found" });
        }

        const updatedUser = await UsersCollection.findOne({ email });
        res.status(200).json({
          message: "Profile updated successfully",
          user: updatedUser,
        });
      } catch (error) {
        console.error("Profile Update Error:", error);
        res.status(500).json({
          message: "Profile update failed",
          error: error.message,
        });
      }
    });
    // Create a new service task
app.post("/api/services", verifyToken, async (req, res) => {
  try {
    const {
      serviceType,
      description,
      district,
      upazila,
      contact,
      availability,
    } = req.body;

    // Fetch user info from DB
    const user = await UsersCollection.findOne({ email: req.user.email });
    if (!user) return res.status(404).json({ message: "User not found" });

    const newTask = {
      userId: user._id,
      userName: user.name,
      userAvatar: user.avatar || "", // automatically use user's avatar
      serviceType,
      description,
      district: district || user.address?.district || "",
      upazila: upazila || user.address?.upazila || "",
      contact: contact || user.phone || "",
      availability: availability || "",
      createdAt: new Date(),
      status: "pending", // default status
    };

    const result = await TaskCollection.insertOne(newTask);

    res.status(201).json({
      message: "Service task created successfully",
      taskId: result.insertedId,
      task: newTask,
    });
  } catch (error) {
    console.error("Create Service Task Error:", error);
    res.status(500).json({
      message: "Failed to create service task",
      error: error.message,
    });
  }
});

  } catch (error) {
    console.error(" MongoDB connection failed:", error);
  }
}

run().catch(console.dir);

// Root route
app.get("/", (req, res) => {
  res.send(" Server is Running...");
});

// Start the server
app.listen(port, () => {
  console.log(` Server is running on port ${port}`);
});
