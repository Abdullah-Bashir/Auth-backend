import dotenv from "dotenv"
dotenv.config()
import express from "express"
import cors from "cors"
import mongoose from "mongoose"
import cookieParser from "cookie-parser"
import rateLimit from "express-rate-limit" // to take control how much requests user can make with server in specified time
import authRoutes from "./routes/auth.js"
import userRoutes from "./routes/user.js"
import { errorHandler } from "./middleware/errorHandler.js"

const app = express()

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per windowMs
})

// Middleware
app.use(cors({
    origin: 'http://localhost:3000', // Explicitly allow your frontend origin
    credentials: true, // Allow credentials (cookies)
}));

app.use(express.json())
app.use(cookieParser())
app.use(limiter)

// Routes
app.use("/api/auth", authRoutes)
app.use("/api/users", userRoutes)

// Error handling middleware
app.use(errorHandler)

// Connect to MongoDB
mongoose
    .connect(process.env.MONGODB_URI, {
        useNewUrlParser: true,
        useUnifiedTopology: true,
    })
    .then(() => console.log("Connected to MongoDB"))
    .catch((err) => console.error("MongoDB connection error:", err))

const PORT = process.env.PORT || 5000
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`)
})

