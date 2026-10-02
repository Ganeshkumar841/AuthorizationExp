
function authorizeRoles(...allowedRoles) {

    // ...allowedRoles (rest parameter) ->
        //Allows u to pass one or multiple roles into the function
        // ex : autherizeRoles("admin") or autherizeRoles("faculty","admin")
        // It gathers into the array.["faculty","admin"]

    return (req, res, next) => {

        //(req, res, next) -> function retains the access to allowedRoles whenever an incmng req hits that specific route.

        // Check if user data exists and if thier role is permitted
        if (!req.user ||
            !allowedRoles.includes(req.user.role)) {

                //req.user.role -> reiles on authMiddleware having already executed and populated req.user.

            return res.status(403).json({
                message: "Access denied: insufficient permissions"
            });
        }

        //403 Forbidden - HTTP status code meaning the server understands who the user is,but refuses to give them access to that resource.

        // User role matches requirement -> proceed
        next();
    };
}

module.exports = {
    authorizeRoles
};