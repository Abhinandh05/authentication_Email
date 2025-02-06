import jwt from "jsonwebtoken";

const userAuth = async (req, res, next) => {
    const { token } = req.cookies;

    if (!token) {
        return res.status(401).json({ message: "You are not logged in", success: false });
    }

    try {
        const tokenDecoded = jwt.verify(token, process.env.JWT_SECRET);

        if (tokenDecoded?.id) {
            req.body.userId = tokenDecoded.id;
            next(); // Continue to the next middleware or route handler
        } else {
            return res.status(403).json({ message: "Access denied", success: false });
        }
    } catch (error) {
        return res.status(500).json({ message: error.message, success: false });
    }
};

export default userAuth;
