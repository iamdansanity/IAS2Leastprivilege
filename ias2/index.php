
<?php 
require_once "includes/dbh.inc.php";
session_start();
// Load environment variables
function loadEnv($path) {
    if (file_exists(Spath)) {
        $lines = file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES); 
        foreach ($lines as $line) {
            if (strpos($line, '=') !== false) {
                list($key, $value) = explode('=', $line, 2);
                $key = trim($key);
                $value = trim($value);
                putenv("$key=$value");
                $_ENV[$key] = Svalue;
            }
        }
    }
}

//Load .env file
/* loadEnv(__DIR__.'/.env');
 */
// Database connection function
/* function connectDB() {
    try {
        $pdo = new PDO("mysql:host=". getenv('DB_HOST'). ";dbname=" . getenv('DB_NAME'),
            getenv('DB_USER'),
            getenv('DB_PASS'));
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        return $pdo;
    } catch (PDOException $e) {
        die("Database connection failed: ". $e->getMessage());
    }
} */


// User login function
function loginUser($pdo, $username, $password) {
    

    $stmt = $pdo->prepare("SELECT id, username, password, role FROM users WHERE username = :username LIMIT 1");
    $stmt->bindParam(":username", $username, PDO::PARAM_STR);
    $stmt->execute();

    if ($user = $stmt->fetch(PDO::FETCH_ASSOC)) {
        $hashedPwd = $user['password'];
        if (password_verify($password, $hashedPwd)) { 
            return $user;
        }
    }
    return false;
}

function insert_user($pdo, $username, $password) {
    $sql = "INSERT into users (username, password)VALUES(:username, :password);";
    $stmt = $pdo->prepare($sql);
    $hashedPwd = password_hash($password, PASSWORD_BCRYPT);
    $stmt->bindParam(":username", $username);
    $stmt->bindParam(":password", $hashedPwd);
    $stmt->execute();
}


// Process login
if ($_SERVER["REQUEST_METHOD"] === 'POST') {

    
    $username = filter_input(INPUT_POST, 'username', FILTER_SANITIZE_STRING); 
    $password = $_POST['password'];

    $user = loginUser($pdo, $username, $password);

    if(isset($_POST['Register'])) {
    
        insert_user($pdo, $username, $password);
        header("Location: index.php?signup=success");
        exit();
    }
    if(isset($_POST['Login'])) {
    
   
    if ($user) {
        $_SESSION['user_id'] = $user['id'];
        $_SESSION['username'] = $user['username'];
        $_SESSION['role'] = $user['role'];
        
        $message = ($user['role'] === 'Admin') ? "You are logged in as admin" : "You are logged in as user";
        echo "<script>alert('$message');</script>";
    } else {
        echo "<script>alert('Invalid username or password');</script>";
    }

    }
}



// Check if user is logged in
function isLoggedIn() {
    return isset($_SESSION['user_id']);
}

// Check if user is admin
function isAdmin() {
    return isset($_SESSION['role']) && $_SESSION['role'] === 'admin';
}

// Logout function
function logout() {
    session_unset(); 
    session_destroy();
    header("Location: index.php");
    exit();
}

// Handle logout
if (isset($_GET['logout'])) { 
    logout();
}
?>

<!DOCTYPE html>
<html>
<head>
    <title>User Login</title>
</head>
<body>
    <?php if (isLoggedIn()): ?>
        <h1>Welcome, <?php echo htmlspecialchars($_SESSION['username']); ?></h1> 
        <p>You are logged in as: <?php echo htmlspecialchars($_SESSION['role']); ?></p> 
        <?php if (isAdmin()): ?>
        <h2>Admin Panel</h2>
        <!-- add admin-specific content here  -->
        <?php else: ?>
        <h2>User Dashboard</h2>
        <!-- Add user-specific content here -->
        <?php endif; ?>
        <a href="?logout">Logout</a>
        <?php else: ?>
        <h1>Login</h1>
        <form method="post" action="">
            <p>Register</p>
            <input type="text" name="username" required placeholder="Username">
            <input type="password" name="password" required placeholder="Password"> 
            <input type="submit" name="Register" value="Register">
        </form>
            <br>
            <p>login</p>
        <form method="post" action="">
            <input type="text" name="username" required placeholder="Username">
            <input type="password" name="password" required placeholder="Password"> 
            <input type="submit" name="Login" value="Login">
        </form>
    <?php endif; ?>
</body>
</html>