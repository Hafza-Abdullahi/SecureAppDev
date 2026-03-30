<?php
// Start the session
session_start();

// Empty all the session variables
$_SESSION = array();

// Destroy the actual session cookie inside the user's browser, to prevent session fixation attacks. 
if (ini_get("session.use_cookies")) {
    $params = session_get_cookie_params();
    setcookie(session_name(), '', time() - 42000,
        $params["path"], $params["domain"],
        $params["secure"], $params["httponly"]
    );
}

// Destroy the session from the server
session_destroy();

// Redirect back to the homepage
header("Location: ../index.php");
exit();
?>