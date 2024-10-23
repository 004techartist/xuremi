<?php
// Database connection details
require 'C:\Users\DELL\Desktop\projects\xuremi web\src\Exception.php';
require 'C:\Users\DELL\Desktop\projects\xuremi web\src\PHPMailer.php';
require 'C:\Users\DELL\Desktop\projects\xuremi web\src\SMTP.php';

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

$host = 'localhost';
$dbname = 'xuremi_db';
$username = 'root';
$password = 'Cerufixime250.';

try {
    $pdo = new PDO("mysql:host=$host;dbname=$dbname", $username, $password);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    die("Database connection failed: " . $e->getMessage());
}

session_start();

if (!isset($_SESSION['user'])) {
    die("Please log in to view your private apps.");
}

$userEmail = $_SESSION['user']['email']; // Customer's email from session

// Fetch the apps uploaded for this user
$stmt = $pdo->prepare("SELECT * FROM private_apps WHERE user_email = ?");
$stmt->execute([$userEmail]);
$privateApps = $stmt->fetchAll(PDO::FETCH_ASSOC);


// Fetch user profile picture

$user_id = $_SESSION['user']['id'] ?? null; // Adjust based on your session structure



// Handle form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['request_app'])) {
    $appDescription = trim($_POST['app_description']);
    $paymentMethod = trim($_POST['payment_method']);
    $cardDetails = trim($_POST['card_details']);
    $password = trim($_POST['password']);
    
    // Save request details to a table
    $stmt = $pdo->prepare("INSERT INTO app_requests (user_email, app_description, payment_method, card_details, password) VALUES (?, ?, ?, ?, ?)");
    $stmt->execute([$userEmail, $appDescription, $paymentMethod, $cardDetails, password_hash($password, PASSWORD_BCRYPT)]);
    
    // Generate a receipt
    $receipt = "Receipt for app request:\nEmail: $userEmail\nDescription: $appDescription\nPayment Method: $paymentMethod";
    file_put_contents("receipts/receipt_$userEmail.txt", $receipt);

    echo "<script>alert('Your request has been submitted! A receipt will be generated.');</script>";
}

function sendInvoice($userEmail, $appDescription, $paymentMethod, $amount) {
    $invoiceId = uniqid('inv_');
    $subject = "Your Invoice - $invoiceId";
    $body = "Invoice ID: $invoiceId\n";
    $body .= "Email: $userEmail\n";
    $body .= "App Description: $appDescription\n";
    $body .= "Payment Method: $paymentMethod\n";
    $body .= "Amount Due: $amount\n";

    $mail = new PHPMailer(true);
    try {
        $mail->isSMTP();
        $mail->Host       = 'smtp.gmail.com';  // Replace with your SMTP server
        $mail->SMTPAuth   = true;
        $mail->Username   = 'murithikelvin595@gmail.com';  // Your email address
        $mail->Password   = 'Cerufixime250.';     // Your email password
        $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
        $mail->Port       = 587;

        $mail->setFrom('no-reply@yourdomain.com', 'Your Company Name');
        $mail->addAddress($userEmail);

        $mail->isHTML(false);
        $mail->Subject = $subject;
        $mail->Body    = $body;

        $mail->send();
        echo "<script>alert('Invoice sent successfully!');</script>";
    } catch (Exception $e) {
        echo "<script>alert('Invoice could not be sent. Mailer Error: {$mail->ErrorInfo}');</script>";
    }
}

// Logout Logic
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'logout') {
  session_unset(); // Remove all session variables
  session_destroy(); // Destroy the session
  echo json_encode(["success" => true, "message" => "You have been logged out."]);
  exit;
}

// Check if the form should be displayed
$showRequestForm = isset($_GET['request']) && $_GET['request'] === 'true';






$email = $_SESSION['user']['email'];

// Get user ID based on email
$stmt = $pdo->prepare("SELECT id FROM users WHERE email = ?");
$stmt->execute([$email]);
$user_id = $stmt->fetchColumn();

// Fetch user profile data if user_id is found
$profile_picture = '';
$bio = '';
$location = '';

if ($user_id) {
    $stmt = $pdo->prepare("SELECT profile_picture, bio, location FROM user_profiles WHERE user_id = ?");
    $stmt->execute([$user_id]);
    $profile = $stmt->fetch(PDO::FETCH_ASSOC);

    $profile_picture = $profile['profile_picture'] ?? '';
    $bio = $profile['bio'] ?? '';
    $location = $profile['location'] ?? '';
}


?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="style.css">
    <script type="module" src="https://unpkg.com/ionicons@5.5.2/dist/ionicons/ionicons.esm.js"></script>
    <script nomodule src="https://unpkg.com/ionicons@5.5.2/dist/ionicons/ionicons.js"></script>
    <link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:opsz,wght,FILL,GRAD@20..48,100..700,0..1,-50..200" />
    <link href="https://fonts.googleapis.com/css2?family=Amarante&display=swap" rel="stylesheet">
    <title>Your Requested Products</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #000000;
            color: #333;
            margin: 0;
            padding: 20px;
        }
        .navbar {
    width: 100%;
    height: 75px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 0 20px;
    
}
        h2 {
            color: #FFFFFF;
            margin-bottom: 20px;
        }
        .app-container {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
            gap: 20px;
            margin: 20px;
            margin-left: 85px;
        }
        .app-card {
            background-color: #ecf0f3;
            border-radius: 20px;
            transition: box-shadow 0.3s ease-in-out;
            padding: 20px;
            text-align: center;
            color: #000000;
            height: 200px;
        }
        .app-card:hover {
            transform: scale(1.02);
        }
        .app-card img {
            width: 100px;
            height: 100px;
            border-radius: 10px;
        }
        .app-card h3 {
            font-size: 1.2em;
            margin: 10px 0;
        }
        .app-card p {
            font-size: 0.9em;
            color: #666;
        }
        .download-link {
            display: inline-block;
            margin-top: 10px;
            padding: 10px 15px;
            background-color: #3498db;
            color: white;
            text-decoration: none;
            border-radius: 4px;
            transition: background-color 0.3s;
        }
        .download-link:hover {
            background-color: #2980b9;
        }
        .no-apps {
            text-align: center;
            font-size: 1.1em;
            color: #999;
        }
        .request-form {
            background-color: #ecf0f3;
            padding: 20px;
            border-radius: 10px;
            margin-top: 20px;
        }
        .request-form label {
            display: block;
            margin: 10px 0 5px;
        }
        .request-form input, .request-form textarea {
            width: 100%;
            padding: 10px;
            margin-bottom: 10px;
            border-radius: 5px;
            border: 1px solid #ccc;
        }
        .request-form button {
            background-color: #3498db;
            color: white;
            border: none;
            padding: 10px 15px;
            border-radius: 5px;
            cursor: pointer;
        }
        .request-form button:hover {
            background-color: #2980b9;
        }



.main{
    margin-left: 85px; /* Set margin equal to the initial width of the sidebar */
    padding: 20px;
    transition: margin-left 0.4s ease;
    

    display: flex;
    align-items: center;
    justify-content: center;
    background-color: #131419;
    box-shadow: 8px 8px 15px #0e0f13, -8px -8px 15px #17181d;
    border-radius: 20px;
    margin: 20px;
   

}





.request-card{
    margin-left: 85px;
    
}
        .sidebar {
  position: fixed;
  top: 16%;
  bottom: 32%;
  left: 5px;
  height: 80%;
  width: 85px;
  display: flex;
  overflow-x: hidden;
  flex-direction: column;
  background: #161a2d;
  padding: 25px 20px;
  transition: all 0.4s ease;
  z-index: 1000; /* Ensure sidebar stays on top */
  border-radius: 30%;
}

.sidebar:hover {
  width: 200px;
}

.sidebar .sidebar-header {
  display: flex;
  align-items: center;
}

.sidebar .sidebar-header img {
  width: 42px;
  border-radius: 50%;
}

.sidebar .sidebar-header h2 {
  color: #fff;
  font-size: 1.25rem;
  font-weight: 600;
  white-space: nowrap;
  margin-left: 23px;
}

.sidebar-links h4 {
  color: #fff;
  font-weight: 500;
  white-space: nowrap;
  margin: 10px 0;
  position: relative;
}

.sidebar-links h4 span {
  opacity: 0;
}

.sidebar:hover .sidebar-links h4 span {
  opacity: 1;
}

.sidebar-links .menu-separator {
  position: absolute;
  left: 0;
  top: 50%;
  width: 100%;
  height: 1px;
  transform: scaleX(1);
  transform: translateY(-50%);
  background: #4f52ba;
  transform-origin: right;
  transition-delay: 0.2s;
}

.sidebar:hover .sidebar-links .menu-separator {
  transition-delay: 0s;
  transform: scaleX(0);
}

.sidebar-links {
  list-style: none;
  margin-top: 20px;
  height: 80%;
  overflow-y: auto;
  scrollbar-width: none;
}

.sidebar-links::-webkit-scrollbar {
  display: none;
}

.sidebar-links li a {
  display: flex;
  align-items: center;
  gap: 0 20px;
  color: #fff;
  font-weight: 500;
  white-space: nowrap;
  padding: 15px 10px;
  text-decoration: none;
  transition: 0.2s ease;
}

.sidebar-links li a:hover {
  color: #161a2d;
  background: #fff;
  border-radius: 4px;
}

.user-account {
  margin-top: 5%;
  
  padding: 12px 10px;
  margin-left: -10px;
}

.user-profile {
  display: flex;
  align-items: center;
  color: #161a2d;
  
}

.user-profile img {
  width: 42px;
  border-radius: 50%;
  border: 2px solid #fff;
}

.user-profile h3 {
  font-size: 1rem;
  font-weight: 600;
}

.user-profile span {
  font-size: 0.775rem;
  font-weight: 600;
}

.user-detail {
  margin-left: 23px;
  white-space: nowrap;
  
}

.sidebar:hover .user-account {
  background: #fff;
  border-radius: 4px;
}





 
    </style>
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
                    
                    <li><a href="news.php">NEWS</a></li>
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

    <aside class="sidebar">
   
    <ul class="sidebar-links">
      <h4>
        <span>Main Menu</span>
        <div class="menu-separator"></div>
      </h4>
      <li>
        <a href="customercompany.php">
          <span class="material-symbols-outlined"> dashboard </span>Dashboard</a>
      </li>

      <h4>
        <span>General</span>
        <div class="menu-separator"></div>
      </h4>
      <li>
        <a href="upload.php"><span class="material-symbols-outlined"> folder </span>Projects</a>
      </li>
      <li>
        <a href="#"><span class="material-symbols-outlined"> groups </span>Refferals</a>
      </li>
      <li>
        <a href="changepassword.php"><span class="material-symbols-outlined"> move_up </span>Password</a>
      </li>
      <li>
        <a href="#"><span class="material-symbols-outlined"> flag </span>All Invoices</a>
      </li>
      <li>
        <a href="user_messages.php"><span class="material-symbols-outlined">
            notifications_active </span>Notifications</a>
      </li>
      <h4>
        <span>Account</span>
        <div class="menu-separator"></div>
      </h4>
      <li>
        <a href="profile.php"><span class="material-symbols-outlined"> account_circle </span>Profile</a>
      </li>
      
      <li>
        <a href="index.php"><span class="material-symbols-outlined"> logout </span>Logout</a>
  
      </li>
    </ul>
<!-- Logout Form -->
<form id="logout-form" method="POST" action="#" style="display: none;">
    <input type="hidden" name="action" value="logout">
</form>


<div class="user-account">
        <div class="user-profile">
        <?php if ($profile_picture): ?>
        <img src="<?= htmlspecialchars($profile_picture) ?>" alt="Profile Picture" class="profile-picture" width="100"><br>
        <!-- The filename display line has been removed -->
        <?php endif; ?>

            <div class="user-detail">
                <h3><?= htmlspecialchars($_SESSION['user']['email']) ?></h3>
                <span>Email</span>
            </div>
        </div>
    </div>

  </aside>

<div class="jjj">

<h2>Your Requested Apps</h2>
<style>
    .jjj{
        margin-left: 120px;
    }
</style>
</div>


<!-- Request Product Card -->
<div class="request-card">
    <a href="upload.php">
        <ion-icon name="add-circle-outline" size="large"></ion-icon>
        <h4>Request a Product</h4>

    </a>
    <div class="message"><p>Click here to request your product.</p></div>
</div>






<div class="app-container">
    <?php if (count($privateApps) > 0): ?>
        <?php foreach ($privateApps as $app): ?>
            <div class="app-card">
                <h3><?php echo htmlspecialchars($app['name']); ?></h3>
                <img src="<?php echo htmlspecialchars('uploads/' . $app['image_filename']); ?>" alt="<?php echo htmlspecialchars($app['name']); ?>">
                <p><?php echo htmlspecialchars($app['description']); ?></p>
                <a class="download-link" href="<?php echo htmlspecialchars('uploads/' . $app['file_filename']); ?>">Download</a>
            </div>
        <?php endforeach; ?>
    <?php else: ?>
        <div class="no-apps">No private apps found.</div>
    <?php endif; ?>
</div>


<script>


// Click outside the request form to collapse it
document.addEventListener('click', function(event) {
    const requestForm = document.getElementById('requestForm');
    const requestCard = document.querySelector('.request-card');

    if (!requestForm.contains(event.target) && !requestCard.contains(event.target)) {
        requestForm.style.display = 'none';
    }
});




    document.getElementById('logout-link').addEventListener('click', function(e) {
        e.preventDefault(); // Prevent the default link behavior
        
        const formData = new FormData(document.getElementById('logout-form'));
        
        fetch('', { // Empty URL to send request to the same page
            method: 'POST',
            body: formData
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                alert(data.message); // Display success message
                window.location.href = 'admupload.php'; // Redirect to the login page
            } else {
                alert(data.error); // Display error message
            }
        })
        .catch(error => console.error('Error:', error));
    });
</script>
<script src="script.js"></script>
</body>
</html>
