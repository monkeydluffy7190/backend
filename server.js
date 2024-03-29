// server.js

const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const cron = require("node-cron");
const moment = require("moment");
require("dotenv").config();

const app = express();
const port = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());

// Mongoose connection
mongoose.connect(process.env.MONGO_DB_URL);

const db = mongoose.connection;
db.on("error", console.error.bind(console, "MongoDB connection error:"));
db.once("open", () => {
  console.log("Connected to MongoDB");
});

// Define the User Schema
const userSchema = new mongoose.Schema({
  username: { type: String, unique: true, required: true },
  password: { type: String, required: true },
  lastLogin: { type: Date, default: null }, // Added lastLogin field
});

// Hash the password before saving it to the database
userSchema.pre("save", async function (next) {
  const user = this;
  if (!user.isModified("password")) return next();

  const hashedPassword = await bcrypt.hash(user.password, 10);
  user.password = hashedPassword;
  next();
});

const User = mongoose.model("User", userSchema);

const formDataSchema = new mongoose.Schema({
  accountName: { type: String, required: true },
  sentInvitation: [{ type: Number, required: false }],
  connections:[{ type: Number, required: false }],
  noOfBotFileNames: [{ type: Number, required: false }],
  Dates: [{type: Date, require: true}],
  owner:{type: mongoose.Schema.Types.ObjectId, ref:'User'}
});

const FormData = mongoose.model("FormData", formDataSchema);

const isAuth = (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ message: "Unauthorized: No token provided" });
  }

  const token = authHeader.split(" ")[1];

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;

    // Check if the token has expired
    const currentTimestamp = Math.floor(Date.now() / 1000);
    if (decoded.exp < currentTimestamp) {
      return res
        .status(401)
        .json({ message: "Unauthorized: Token has expired" });
    }

    next();
  } catch (error) {
    return res.status(401).json({ message: "Unauthorized: Invalid token" });
  }
};

// Signup API
app.post("/api/signup", async (req, res) => {
  try {
    const { username, password } = req.body;

    // Check if username already exists
    const existingUser = await User.findOne({ username });

    if (existingUser) {
      // User with the same username already exists
      return res.status(409).json({ message: "Username already exists" });
    }

    const newUser = new User({ username, password });
    await newUser.save();
    res.status(201).json({ message: "User registered successfully" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Internal Server Error" });
  }
});

// Login API
app.post("/api/login", async (req, res) => {
  try {
    const { username, password} = req.body;
    const user = await User.findOne({ username });
    const id= user._id;
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      return res.status(401).json({ message: "Invalid password" });
    }

    // Check if the user is logging in after 12 hours
     const lastLoginTime = moment(user.lastLogin);
     const currentTime = moment();
     const duration = moment.duration(currentTime.diff(lastLoginTime));
     const hoursSinceLastLogin = duration.asHours();

     if (hoursSinceLastLogin >= 12) {
       // Run the cron job function
       const total_absent=hoursSinceLastLogin/12;
      for(let i=0;i<total_absent;i++)
      {
        await runCronJob(id);
      }
     }

    // Check if the user is logging in after 10 seconds (changed from 12 hours)
   // const lastLoginTime = moment(user.lastLogin);
   // const currentTime = moment();
   // const duration = moment.duration(currentTime.diff(lastLoginTime));
   // const secondsSinceLastLogin = duration.asSeconds();

   // if (secondsSinceLastLogin >= 10) {
      // Run the cron job function
    //  const total_absent=secondsSinceLastLogin/10;
    //  for(let i=0;i<total_absent;i++)
    //  {
    //    await runCronJob(id);
    //  }
      
    //}

    // Update lastLogin timestamp
    user.lastLogin = new Date();
    await user.save();

    // Generate JWT token
    const token = jwt.sign(
      { userId: user._id, username: user.username },
      process.env.JWT_SECRET,
      {
        expiresIn: "1h", // You can set the expiration time as per your requirements
      }
    );

    // Include the token in the response
    res
      .status(200)
      .json({ id: user._id , message: "Login successful", username: user.username, token });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Internal Server Error" });
  }
});

app.post("/api/formdata", isAuth, async (req, res) => {
  try {
    const { accountName, sentInvitation, connections, noOfBotFileNames , id } =
      req.body;
    const data = await FormData.findOne({accountName:accountName, owner:id})
    if(data)
    {
      await FormData.findOneAndUpdate({accountName:accountName, owner:id}, {
          accountName,
          $push :{"sentInvitation": sentInvitation, "connections": connections, "noOfBotFileNames": noOfBotFileNames, "Dates":new Date()},
          owner: id
      })
      
    }
    else
    {
      await FormData.create({
        accountName,
        sentInvitation:[sentInvitation],
        connections:[connections],
        noOfBotFileNames:[noOfBotFileNames],
        Dates: [new Date()],
        owner:id
      })
      
  }
    res.status(201).json({ message: "Form data saved successfully" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Internal Server Error" });
  }
});





app.get("/api/formdata/:id", isAuth, async (req, res) => {
  try {
    const allFormData = await FormData.find({owner:req.params.id});
    res.status(200).json(allFormData);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Internal Server Error" });
  }
});

app.use('*',(req,res)=>{
    res.send('You are looking at backend apis')
})

// Cron job to update entries with null values to -1 every 10 seconds
//for 12 hours use this 0 */12 * * *
// Function to run the cron job
const runCronJob = async (id) => {
  try {
    // Find entries with null values
    console.log(id)
    await FormData.updateMany({owner:id}, {
      $push :{"sentInvitation": -1, "connections": -1, "noOfBotFileNames": -1,"Dates":new Date()},
      owner: id
  })

    console.log("Cron job executed successfully");
  } catch (error) {
    console.error("Error in cron job:", error);
  }
};
// Start the server
app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
