export const errorHandler = (err, req, res, next) => {
    console.error(err.stack)

    // Mongoose validation error
    if (err.name === "ValidationError") {
        const errors = Object.values(err.errors).map((error) => error.message)
        return res.status(400).json({ message: "Validation Error", errors })
    }

    // Mongoose duplicate key error
    if (err.code === 11000) {
        const field = Object.keys(err.keyPattern)[0]
        return res.status(400).json({ message: `${field} already exists` })
    }

    // Default to 500 server error
    res.status(500).json({ message: "Internal Server Error" })
}

