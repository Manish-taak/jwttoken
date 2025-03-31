require("dotenv").config(); // ✅ .env file se environment variables load karta hai

const express = require("express"); // ✅ Express framework import kar raha hai
const bcrypt = require("bcryptjs"); // ✅ Password hashing ke liye bcrypt import kiya
const jwt = require("jsonwebtoken"); // ✅ Authentication ke liye JWT import kiya
const cors = require("cors"); // ✅ Cross-origin requests allow karne ke liye CORS import kiya
const db = require("./models"); // ✅ Apni database models import kar raha hai

const app = express(); // ✅ Express app initialize kiya
app.use(express.json()); // ✅ JSON request body ko parse karne ka middleware
app.use(cors()); // ✅ CORS enable karne ka middleware

const PORT = process.env.PORT || 5000; // ✅ Port environment variable se lega, warna 5000 use karega
const SECRET_KEY = process.env.JWT_SECRET || "your_secret_key"; // ✅ JWT secret key set kar raha hai

// ✅ Database se connect ho raha hai aur tables sync kar raha hai
db.sequelize
    .sync({ force: false }) // ✅ Tables delete nahi karega, sirf sync karega
    .then(() => console.log("Database Connected and Synced")) // ✅ Agar connection ho gaya to message show karega
    .catch((err) => console.log("Error:", err)); // ✅ Agar koi error aaya to console mein show karega

const User = db.User; // ✅ User model ko access kar raha hai

// ✅ User Register Route (Naya user register karne ke liye)
app.post("/register", async (req, res) => {
    try {
        const { name, email, password } = req.body; // ✅ Frontend se name, email aur password le raha hai

        // ✅ Check kar raha hai ki user already exist to nahi karta
        const existingUser = await User.findOne({ where: { email } });
        if (existingUser) return res.status(400).json({ message: "User already exists" });

        // ✅ Password ko hash kar raha hai taaki secure rahe
        const hashedPassword = await bcrypt.hash(password, 10);

        // ✅ Naya user database mein save kar raha hai
        const newUser = await User.create({ name, email, password: hashedPassword });

        // ✅ Successfully register hone ka response bhej raha hai
        res.status(201).json({ message: "User registered successfully", user: newUser });
    } catch (error) {
        res.status(500).json({ message: "Internal Server Error", error }); // ✅ Agar koi error aaya to bata raha hai
    }
});

// ✅ User Login Route (User login hone ke liye)
app.post("/login", async (req, res) => {
    try {
        const { email, password } = req.body; // ✅ User se email aur password le raha hai

        // ✅ Check kar raha hai ki user database mein exist karta hai ya nahi
        const user = await User.findOne({ where: { email } });
        if (!user) return res.status(400).json({ message: "User not found" });

        // ✅ Jo password user ne diya hai, usko database wale hashed password se match kar raha hai
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).json({ message: "Invalid credentials" });

        // ✅ JWT token generate kar raha hai jo 1 hour tak valid rahega
        const token = jwt.sign({ id: user.id, email: user.email }, SECRET_KEY, { expiresIn: "1h" });

        // ✅ Login success hone ka response bhej raha hai
        res.status(200).json({ message: "Login successful", token });
    } catch (error) {
        res.status(500).json({ message: "Internal Server Error", error }); // ✅ Agar koi error aaya to bata raha hai
    }
});

// ✅ Middleware jo token check karega (Protected routes ke liye)
const authenticate = (req, res, next) => {
    const token = req.headers.authorization?.split(" ")[1]; // ✅ Request ke headers se token nikal raha hai
    if (!token) return res.status(401).json({ message: "Unauthorized" }); // ✅ Token nahi hai to error dega

    // ✅ JWT token ko verify kar raha hai
    jwt.verify(token, SECRET_KEY, (err, decoded) => {
        if (err) return res.status(403).json({ message: "Invalid token" }); // ✅ Token galat hai to error dega
        req.user = decoded; // ✅ Token sahi hai to user data request object mein save karega
        next(); // ✅ Next middleware ya route ko allow karega
    });
};

// ✅ Protected Route (Jo sirf logged-in users ke liye access hai)
app.get("/profile", authenticate, async (req, res) => {
    const user = await User.findByPk(req.user.id); // ✅ User ki details database se le raha hai
    res.json({ message: "Profile accessed", user }); // ✅ User ka data return kar raha hai
});

// ✅ Server ko start kar raha hai
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`); // ✅ Server start hone ka message show karega
});
