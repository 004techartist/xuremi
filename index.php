<?php
// Database connection details
$host = 'localhost';
$dbname = 'xuremi_db';
$username = 'root';
$password = 'Cerufixime250.';

try {
    $pdo = new PDO("mysql:host=$host;dbname=$dbname", $username, $password);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    die(json_encode(["error" => "Database connection failed: " . $e->getMessage()]));
}


session_start(); // Start the session

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'signup') {
    $name = trim($_POST['name']);
    $email = trim($_POST['email']);
    $password = password_hash($_POST['password'], PASSWORD_BCRYPT);

    // Validate input
    if (empty($name) || empty($email) || empty($_POST['password'])) {
        echo json_encode(["error" => "All fields are required."]);
        exit;
    }

    // Check for existing user
    $stmt = $pdo->prepare("SELECT COUNT(*) FROM users WHERE email = ?");
    $stmt->execute([$email]);
    if ($stmt->fetchColumn() > 0) {
        echo json_encode(["error" => "Email already in use."]);
        exit;
    }

    // Check if it's the first user
    $stmt = $pdo->query("SELECT COUNT(*) FROM users");
    $count = $stmt->fetchColumn();
    $role = ($count == 0) ? 'superadmin' : 'user';

    $stmt = $pdo->prepare("INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)");
    try {
        $stmt->execute([$name, $email, $password, $role]);
        $_SESSION['user'] = [
            'name' => $name,
            'email' => $email,
            'role' => $role
        ];
        echo json_encode(["success" => true]); // Send success response
        exit;
    } catch (PDOException $e) {
        echo json_encode(["error" => "Failed to register user: " . $e->getMessage()]);
        exit;
    }
}

// Handle user login
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'login') {
    $email = $_POST['email'];
    $password = $_POST['password'];

    $stmt = $pdo->prepare("SELECT * FROM users WHERE email = ?");
    $stmt->execute([$email]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($user && password_verify($password, $user['password'])) {
        $_SESSION['user'] = [
            'name' => $user['name'],
            'email' => $user['email'],
            'role' => $user['role']
        ];

        // Redirect based on role
        if ($user['role'] === 'superadmin' || $user['role'] === 'admin') {
            echo json_encode(["success" => true, "redirect" => "admindash.html"]);
        } else {
            echo json_encode(["success" => true, "redirect" => "About.html"]);
        }
        exit;
    } else {
        echo json_encode(["error" => "Invalid email or password."]);
        exit;
    }
}

// Check if user is logged in and is an admin
function isAdmin() {
    return isset($_SESSION['user']) && ($_SESSION['user']['role'] === 'admin' || $_SESSION['user']['role'] === 'superadmin');
}

// If it's a GET request to fetch products
if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['action']) && $_GET['action'] === 'get_products') {
    // Retrieve products
    $stmt = $pdo->query("SELECT name, description, image_filename, file_filename FROM apps");
    $apps = [];
    while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
        $apps[] = [
            'name' => $row['name'],
            'description' => $row['description'],
            'image_url' => 'uploads/' . $row['image_filename'],
            'file_url' => 'uploads/' . $row['file_filename']
        ];
    }
    header('Content-Type: application/json');
    echo json_encode($apps);
    exit;
}


// Check if it's a GET request to fetch products
if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['action']) && $_GET['action'] === 'get_products') {
    // Retrieve products
    $stmt = $pdo->query("SELECT name, description, image_filename, file_filename FROM apps");
    $apps = [];
    while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
        $apps[] = [
            'name' => $row['name'],
            'description' => $row['description'],
            'image_url' => 'uploads/' . $row['image_filename'],
            'file_url' => 'uploads/' . $row['file_filename']
        ];
    }
    header('Content-Type: application/json');
    echo json_encode($apps);
    exit;
}


// If it's a POST request, handle file upload (admin functionality)
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Validate and get form inputs
    $appName = $_POST['appName'];
    $appDescription = $_POST['appDescription'];
    
    // Handle file uploads
    $uploadDir = 'uploads/';
    $imageFile = $uploadDir . basename($_FILES['image']['name']);
    $appFile = $uploadDir . basename($_FILES['file']['name']);




    if (move_uploaded_file($_FILES['image']['tmp_name'], $imageFile) && move_uploaded_file($_FILES['file']['tmp_name'], $appFile)) {
        $stmt = $pdo->prepare("INSERT INTO apps (name, description, image_filename, file_filename, credit_score) VALUES (?, ?, ?, ?, ?)");
        if ($stmt->execute([$appName, $appDescription, $_FILES['image']['name'], $_FILES['file']['name'], 0])
        ) {
            $successMessage = "App uploaded successfully!";
        } else {
            $errorMessage = "Failed to save app data in the database.";
        }
    } else {
        $errorMessage = "Failed to upload files.";
    }
}


if (isset($_GET['file']) && !empty($_GET['file'])) {
    $fileName = basename($_GET['file']);
    $filePath = 'uploads/' . $fileName;

    if (file_exists($filePath)) {
        // Correct headers for forcing file download
        header('Content-Description: File Transfer');
        header('Content-Type: application/octet-stream');
        header('Content-Disposition: attachment; filename="' . $fileName . '"');
        header('Expires: 0');
        header('Cache-Control: must-revalidate');
        header('Pragma: public');
        header('Content-Length: ' . filesize($filePath));
        readfile($filePath);
        exit;
    } else {
        echo "File does not exist.";
    }
}





ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);




?>
<!DOCTYPE html>
<html lang="en">
<head>
    <title>Xuremi</title>
    <link rel="stylesheet" href="style.css">
    <script type="module" src="https://unpkg.com/ionicons@5.5.2/dist/ionicons/ionicons.esm.js"></script>
    <script nomodule src="https://unpkg.com/ionicons@5.5.2/dist/ionicons/ionicons.js"></script>
    <link href="https://fonts.googleapis.com/css2?family=Amarante&display=swap" rel="stylesheet">
</head>
<body>
    <div class="main">
        <div class="navbar">
            <div class="icon">
                <h2 class="logo">xuremi</h2>
            </div>
            <div class="menu" id="menu">
                <ul>
                    <li><a href="index.php">HOME</a></li>
                    
                    <li><a href="customercompany.php">PRODUCTS</a></li>
                    <li><a href="About.html">ABOUT</a></li>
                    
                    <li><a href="news.html">NEWS</a></li>
                    <li><a href="#">REVIEWS</a></li>
                    <li class="search-menu-item">
                        <div class="search">
                            <input type="text" class="search__input" placeholder="Search...">
                            <div class="search__icon">
                                <ion-icon name="search"></ion-icon>
                            </div>
                        </div>
                    </li>
                </ul>
            </div>
            <div class="hamburger" id="hamburger">
                <ion-icon name="menu-outline"></ion-icon>
            </div>
        </div>
    </div>

    <div class="account-question" href="">
        <p>Already have an account?</p>
    </div>

    <div class="content">
        <h1>Join a community of innovators <br>
            <span>DOWNLOAD ready-to-use <br>
            <span>applications or PARTNER with us <br> </span>
        <span>to design a solution just for you.</span></span>
        </h1>
        <div class="description">
            <p>At Xuremi, we are dedicated to developing innovative solutions <br>that meet the diverse needs of modern businesses and individuals. <br>  From cutting-edge AI and machine learning technologies to responsive web <br> development and custom applications,  we offer a wide range of products  <br>designed to streamline operations, enhance user experiences,  and drive success. <br> Partner with us to bring your ideas to life with personalized solutions tailored to your goals.</p>
        </div>
    </div>

    <div class="auth-buttons">
        <button class="btn sign-up">Sign Up</button>
        <button class="btn sign-in">Sign In</button>
    </div>

    <div class="right-cards">
    <div class="cards-container">
        <div class="card active">

            <h3>Artificial Intelligence</h3>
            <p>Explore advanced AI solutions and technologies.</p>
            <img src="images/future-artificial-intelligence-robot-network-system-background_432372-88.avif" alt="AI Image">
        </div>
        <div class="card">
            <h3>Machine Learning</h3>
            <p>Discover the power of data-driven decision making.</p>
            <img src="images/ai-ml-ds-jpg.webp" alt="ML Image">
        </div>
        <div class="card">
            <h3>Web Development</h3>
            <p>Build modern, responsive websites with the latest technologies.</p>
            <img src="/images/web dev.jpg" alt="WebDev Image"> <!-- Ensure file is named correctly -->
        </div>
        <div class="card">
            <h3>Web Design</h3>
            <p>Create visually stunning and user-friendly web designs.</p>
            <img src="images/webdevdesign.jpg" alt="Web Design Image">
        </div>
        <div class="card">
            <h3>Mobile and Desktop Application Development</h3>
            <p>Develop high-performance mobile apps for all platforms as well as design powerful and reliable desktop applications.</p>
            <img src="images/mobiledesktop.jpg" alt="Mobile Desktop Image">
        </div>
        <div class="card">
            <h3>Customized Application Development</h3>
            <p>Create powerful and reliable applications that are designed to turn your app idea into a reality.</p>
            <img src="images/Custom-Software-Application-Development.jpg" alt="Custom Made Apps Image">
        </div>
    </div>
</div>


    <div class="container" id="container">
        <div class="form-container sign-up-container">
            <form action="#">
                <div class="signup">
                    <h1>
                        Create Account
                    </h1>
                </div>
                <style>

                    .signup{
                        color: black;
                        margin-top: 2%;
                        
                    }
                </style>
                <div class="social-container">
                    
                    <a href="#" class="social"><i class="fab fa-facebook-f"></i></a>
                    <a href="#" class="social"><i class="fab fa-google-plus-g"></i></a>
                    <a href="#" class="social"><i class="fab fa-linkedin-in"></i></a>
                </div>
                <span>or use your email for registration</span>
                <input type="text" placeholder="Name" />
                <input type="email" placeholder="Email" />
                <input type="password" placeholder="Password" />
                <button>Sign Up</button>
            </form>
        </div>
        <div class="form-container sign-in-container">
            <form action="#">
                <div class="signin">
                    <h1>Sign in</h1>
                </div>
                
                <style>
                    .signin{
                        color: black;
                        
                    }
                </style>

                <div class="social-container">
                    <a href="#" class="social"><i class="fab fa-facebook-f"></i></a>
                    <a href="#" class="social"><i class="fab fa-google-plus-g"></i></a>
                    <a href="#" class="social"><i class="fab fa-linkedin-in"></i></a>
                </div>
                <span>or use your account</span>
                <input type="email" placeholder="Email" />
                <input type="password" placeholder="Password" />
                <a href="forgot_password.html">Forgot your password?</a>

                <button>Sign In</button>
            </form>
        </div>
        <div class="overlay-container">
            <div class="overlay">
                <div class="overlay-panel overlay-left">
                    <h1>Welcome Back!</h1>
                    <p>To keep connected with us please login with your personal info</p>
                    <button class="ghost" id="signIn">Sign In</button>
                </div>
                <div class="overlay-panel overlay-right">
                    <h1>Hello, Friend!</h1>
                    <p>Enter your personal details and start journey with us</p>
                    <button class="ghost" id="signUp">Sign Up</button>
                </div>
            </div>
        </div>
    </div>
    


    <script src="script.js"></script>
</body>
</html>           