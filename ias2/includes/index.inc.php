<?php session_start();
// Load environment variables
function loadEnv($path) {
if (file_exists(Spath)) {
Slines = file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES); foreach ($lines as $line) {
if (strpos($line, '=') !== false) {
list($key, $value) = explode('=', $line, 2);
$key = trim($key);
$value = trim($value);
putenv("$key=$value");
$_ENV[$key] = Svalue;
}
}
}
Load .env file
loadEnv(_DIR_..env');
// Database connection function
function connectDB() {
try {
Spdo = new PDO("mysql:host=". getenv('DB_HOST'). ";dbname=". getenv('DB_NAME'),
getenv('DB_USER'),
getenv('DB_PASS'));
Spdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
return $pdo;
} catch (PDOException $e) {
die("Database connection failed: ". $e->getMessage());
}
}
// User login function
function login User($username, $password) {
$pdo connectDB();
$stmt = $pdo->prepare("SELECT id, username, password, role FROM users WHERE username = username LIMIT 1");
$stmt->bindParam(":username', $username, PDO::PARAM_STR);
$stmt->execute();


if (Suser = $stmt->fetch(PDO::FETCH_ASSOC)) {
    if (password_verify($password, $user['password'])) { return $user;
    }
    }
    return false;
    }
    // Process login
    if ($_SERVER['REQUEST_METHOD"]
    ===
    'POST') {
    $username = filter_input(INPUT_POST, 'username', FILTER_SANITIZE_STRING); $password = $_POST['password'];
    $user = login User(Susername, $password);
    if (Suser) {
    $_SESSION['user_id'] = Suser['id'];
    $_SESSION['username'] = $user['username'];
    $_SESSION['role'] = $user['role'];
    Smessage = ($user['role'] | === 'admin') ? "You are logged in as admin": "You are logged in as user":
    echo "<script>alert("$message');</script>";
    } else {
    echo "<script>alert('Invalid username or password');</script>";
    }
    }
    // Check if user is logged in
    function isLoggedIn() {
    }
    return isset($_SESSION['user_id']);
    // Check if user is admin
    function isAdmin() {
    }
    return isset($_SESSION['role']) && $_SESSION['role'] === 'admin';
    // Logout function
    function logout() {
    session_unset(); session_destroy():
    header("Location: login.php");


    
}
exit();
// Handle logout
if (isset($_GET['logout'])) { logout();
}
?>
