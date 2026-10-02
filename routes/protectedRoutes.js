const express = require("express");
const router = express.Router();

// Import authentication middleware
const {
    authenticateToken
} = require("../middleware/authMiddleware");

// Import authorization middleware
const {
    authorizeRoles
} = require("../middleware/roleMiddleware");

// 1. GENERAL PROTECTED Route (any logged-in user can visit)

router.get("/dashboard",authenticateToken,(req, res) => {
    res.json({
        message: "Welcome to the protected dashboard",
        user: req.user
    });
});

// 2. ADMIN PROTECTED ROUTE (only admin can access)

router.get("/admin",authenticateToken,authorizeRoles("admin"),(req, res) => {
    res.json({
        message: "Admin access granted",
        user: req.user
    });
});

// 3. FACULTY PROTECTED ROUTE (only faculty)

router.get("/faculty",authenticateToken,authorizeRoles("faculty"),(req, res) => {
    res.json({
        message: "Faculty access granted",
        user: req.user
    });
});

// 4. STUDENT PROTECTED ROUTE (only student)

router.get("/student",authenticateToken,authorizeRoles("student"),(req, res) => {
    res.json({
        message: "Student access granted",
        user: req.user
    });
});

// Export router
module.exports = router;