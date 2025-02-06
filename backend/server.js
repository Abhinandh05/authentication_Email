import express from 'express';
import cors from 'cors';
import 'dotenv/config';
import cookieParser from 'cookie-parser';
import connectDB from './config/db.js';
import authRouter from './routes/authRoutes.js';

const app = express();
const port = process.env.PORT || 8000;

// Connect to MongoDB
connectDB();

// Middleware
app.use(express.json());
app.use(cookieParser());
app.use(cors({
    origin: process.env.CLIENT_URL || "http://localhost:3000",
    credentials: true,
}));

// API Endpoints
app.get('/', (req, res) => {
    res.send('Hello World!');
});

// Authentication Routes (Register, Login, Logout)
app.use("/api/auth", authRouter);

// Start the Server
app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});
