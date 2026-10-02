//1. setup,configuration,state
const express = require("express");
const bcrypt = require("bcrypt");
//bcrypt     -> a cryptograpic lib used to securly hash and compare user password using one way hashing with salt rounds
const jwt = require("jsonwebtoken");

const app = express();//app the running express application instance

app.use(express.json());
//app.use    -> (express.json()) BUilt-in express middleware that parses incnmg req bodies formatted as json,exposing the parsed data on req.body

// Use an environment variable in real applications.
const JWT_SECRET =
    process.env.JWT_SECRET || "change-this-demo-secret";

//JWT_secret -> the secret signature key.if a sys env var exists, it uses process.env.JWT_SECRET,otherwise falls back to demo str


/*

//1.why jwt_secret is needed?

JWT_secret consists of three parts - header,payload,signature

anyone can decode the first two parts header,payload,bcuz they are simple base64 encoded strings.

without the secretkey -> a random user could take their token,change their role to thier wanted role.

with secretkey -> when client sends token back, jwwt.verify(token,JWT_secert) recaluclates the signature using server's secret
if an attacker alters single char then it mismatches and and jwt.verify throws an error.


//2.process.env.JWT_SEcret?

process -> is a global obj providing info about current node.js runtime process
env     -> stands for environment variables 
process.env.JWT_SEcret -> reads the env var named JWT_SEcret from host sys.
*/



// Temporary in-memory user storage
const users = [];
//const users-> an in-memory arr acting as a mock database.
                //Every time the server restarts(node server.js),the arr is set back to empty(which explains why prev registerd users disappear after the restart)

// if you use the external database like postgresql or MongoDB replace users arr with that.

//2. User REGISTER ROUTE (POST)

app.post("/register", async (req, res) => {
    //we use async bcuz of the time taking process of pass hashing at bcrypt
    try {
        const { username, password, role } = req.body;
        //validation check - password and username must not be empty
        if (!username || !password) {
            return res.status(400).json({
                message: "Username and password are required"
            });
        }
        //adding password constriants - we can add anythings like caps should include or must include spl char etc.
        if (password.length < 6) {
            return res.status(400).json({
                //400 -> Bad request
                message: "Password must contain at least 6 characters"
            });
        }
        //Duplicate check - does the user already exists.
        const existingUser = users.find(user => user.username === username);
        if (existingUser) {
            return res.status(409).json({
                //409 ->conflict
                message: "User already exists"
            });
        }
        //pass word hashing - hashing the password using saltrounds.
        const hashedPassword = await bcrypt.hash(password, 10);
        //record creation - new id creation
        const newUser = {
            id: users.length + 1,
            username,
            password: hashedPassword,
            role: role || "student"
        };
        //pushes record into storage. 
        users.push(newUser);
        //generate JWT token after successful registration
        const token = jwt.sign(
            {
                userId: newUser.id,
                username: newUser.username,
                role: newUser.role
            },
            JWT_SECRET,
            { expiresIn: "1h" }
        );
        //sending success response
        res.status(201).json({
            //201 -> when the password field is intentionally omitted.
            message: "User registered successfully",
            token,
            user: {
                id: newUser.id,
                username: newUser.username,
                role: newUser.role
            }
        });
     // if anything fails then it will throw an error.
    } catch (error) {
        res.status(500).json({
            message: "Registration failed"
        });
    }
});


//bcrypt.hash(password,10) -> automatically salts and hashes the raw pass using 10 hashing rounds.Raw passwords never saved.
//role -> role||"student"  if the req omits a role,it defaults to student
//sanitized response -> password feild is intentionally omitted from the response sent back to client(res.status(201))





//3. LOGIN ROUTE (POST)

app.post("/login", async (req, res) => {

    try {
        const { username, password } = req.body;
        //req.body -> extracts the plain text username,password.
        const user = users.find(
            user => user.username === username
        );

        //user.find -> matches the user with username

        if (!user) {//if no such account presents return 401 status 
            return res.status(401).json({
                message: "Invalid username or password"
            });
        }

        const isMatch = await bcrypt.compare(
            password,
            user.password
        );
        //bcrypt.compare -> compares the plain text password from request body with the stored hash using bcrypt.compare
        if (!isMatch) {
            return res.status(401).json({
                message: "Invalid username or password"
            });
        }
        //401 -> Unathurized : invalid username or password

        const token = jwt.sign( //generation of the json web token(JWT)
            {
                userId: user.id,
                username: user.username,
                role: user.role
            },
            JWT_SECRET,
            {
                expiresIn: "1h"
            }
        );

        //jwt sign(...) -> builds the signed token containing payload(userid,username,role),signed using JWT_SECRET,valid for 1 hr.

        res.json({//returning the success response
            message: "Login successful",
            token
        });

    } catch (error) {//error handling.
        res.status(500).json({
            message: "Login failed"
        });
    }
});


//4.Middleware handlers - (AUTHENTICATION MIDDLEWARE,ROLE AUTHORIZATION MIDDLEWARE)

//AUTHENTICATION MIDDLEWARE - who are you?

function authenticateToken(req, res, next) {
    const authHeader = req.headers.authorization;
    //reads req.headers.authorization
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
        return res.status(401).json({
            message: "Access token required"
        });
    }
    //if missing or non bearer headers it returns 401 status.
    const token = authHeader.split(" ")[1];
    //takes token without double qoutes
    try {
        const decoded = jwt.verify(token, JWT_SECRET);

        //calls jwt.verify for verification
            //it checks whether the token is expired or not (1hr time) set at login.
            //checks mathematically also whether it is true or not.

        req.user = decoded;//true case -> attaches the payload to the request.
        next();//move to next middleware
    } catch (error) {//if any error occurs.
        return res.status(401).json({
            message: "Invalid or expired token"
        });
    }
}

// ROLE AUTHORIZATION MIDDLEWARE - are u permitted here?

function authorizeRoles(...allowedRoles) {
    return (req, res, next) => {
        if (!req.user || !allowedRoles.includes(req.user.role)) {
            // checks if the req.user.role is inside allowedRoles
            return res.status(403).json({
                message: "Access denied: insufficient permissions"
            });
        }
        //403 -> access denied
        next();//move to next middleware
    };
}

//5.Role gaurded endpoints 


// PROTECTED ROUTE
app.get("/dashboard",authenticateToken,(req, res) => {res.json({message: "Welcome to the protected dashboard",user: req.user});});

// ADMIN-ONLY ROUTE
app.get("/admin",
    authenticateToken,
    authorizeRoles("admin"),
    (req, res) => {
        res.json({message: "Welcome Admin",user: req.user});
    });


// FACULTY-ONLY ROUTE
app.get("/faculty",authenticateToken,authorizeRoles("faculty"),(req, res) => {res.json({message: "Welcome Faculty",user: req.user});});

// STUDENT-ONLY ROUTE
app.get("/student",authenticateToken,authorizeRoles("student"),(req, res) => {res.json({message: "Welcome Student",user: req.user});});


//6. static asset serving and server boost
// START SERVER

const PORT = 3000;//defines the network port number your local computer reserves for the express

app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
});
//app.listen -> starts the http server listening for connections on port 3000 
//callback function runs once the server is successfully bound to port.

//it is for the html file PLEASE LEAVE THIS 
//app.use(express.static("public"));
//app.use(express.static("public")) above app.listen() so all static routing handlers are registered before server begins accepting requests