const jwt = require("jsonwebtoken");

// Use the same secret key used when creating JWTs
const JWT_SECRET =
process.env.JWT_SECRET || "change-this-demo-secret";

function authenticateToken(req, res, next) {

// Read authorization header
const authHeader = req.headers.authorization;

//req.headers.authorization : standard http header where clients pass tokens using convention Bearer<jwt_token>

// Check whether token is provided or empty. format : "Bearer <token>"
if (!authHeader ||
    !authHeader.startsWith("Bearer ")) {

    return res.status(401).json({
        message: "Access token required"
    });
}

// Extract token after the string
const token = authHeader.split(" ")[1];

try {

    // Verify JWT token (cryptographic signature & expiration).
    const decoded = jwt.verify(

        // jwt.verify(token,secret) - validates token was signed with server's private secret and hasn't expired.
                        //if the verification fails it throws an error.
        token,
        JWT_SECRET
    );

    // Attach decoded payload to req obj.
    req.user = decoded;

    //req.user=decoded - the paylod:(username:XXX,role:YYY) is attached directly to request obj.

    next();
    // next() this instructs the express to move on to next handler or middleware in chain.

} catch (error) {
    //Tokenn was tampered with, fake, or expired
    return res.status(401).json({
        message: "Invalid or expired token"
    });
}
}

module.exports = {
authenticateToken
};