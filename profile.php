<?php
session_start();

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

// Check if user is logged in
if (!isset($_SESSION['user'])) {
    echo "You need to log in to access your profile.";
    exit;
}

$email = $_SESSION['user']['email'];

// Get user ID based on email
$stmt = $pdo->prepare("SELECT id FROM users WHERE email = ?");
$stmt->execute([$email]);
$user_id = $stmt->fetchColumn();

// Handle profile update
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $location = $_POST['location'];
    $bio = $_POST['bio'];
    $profilePicture = '';

    // Handle file upload
    if (isset($_FILES['profile_picture']) && $_FILES['profile_picture']['error'] == 0) {
        $targetDir = "uploads/";
        $targetFile = $targetDir . basename($_FILES["profile_picture"]["name"]);
        if (move_uploaded_file($_FILES["profile_picture"]["tmp_name"], $targetFile)) {
            $profilePicture = $targetFile;
        }
    }

    // Update user profile
    if ($user_id) {
        $stmt = $pdo->prepare("INSERT INTO user_profiles (user_id, profile_picture, bio, location) VALUES (?, ?, ?, ?) ON DUPLICATE KEY UPDATE profile_picture = ?, bio = ?, location = ?");
        if ($stmt->execute([$user_id, $profilePicture, $bio, $location, $profilePicture, $bio, $location])) {
            echo "Profile updated successfully!";
        } else {
            echo "Error: " . implode(", ", $stmt->errorInfo());
        }
    } else {
        echo "Error: User not found.";
    }
}

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
    <title>User Profile</title>
    <link rel="stylesheet" href="style.css"> <!-- Link to your CSS file -->

   <link rel="stylesheet" href="#">
    <script type="module" src="https://unpkg.com/ionicons@5.5.2/dist/ionicons/ionicons.esm.js"></script>
    <script nomodule src="https://unpkg.com/ionicons@5.5.2/dist/ionicons/ionicons.js"></script>
    <link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:opsz,wght,FILL,GRAD@20..48,100..700,0..1,-50..200" />
    <link href="https://fonts.googleapis.com/css2?family=Amarante&display=swap" rel="stylesheet">
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #f4f4f4;
            margin: 0;
            padding: 20px;
        }
        
        h2 {
            text-align: center;
            color: #333;
        }
        label {
            font-weight: bold;
            margin-top: 10px;
            display: block;
            color: #555;
        }
        input[type="text"], input[type="email"], input[type="file"], textarea {
            width: 100%;
            padding: 10px;
            margin: 5px 0 20px;
            border: 1px solid #ccc;
            border-radius: 4px;
        }
        input[type="submit"] {
            background-color: #5cb85c;
            color: white;
            border: none;
            padding: 10px 15px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 16px;
            width: 100%;
        }
        input[type="submit"]:hover {
            background-color: #4cae4c;
        }
        .profile-picture {
            display: block;
            margin: 20px auto;
            border-radius: 50%;
            border: 2px solid #5cb85c;
        }
        .current-email {
            font-size: 16px;
            margin-top: 20px;
            text-align: center;
            color: #555;
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

<link rel="stylesheet" href="style.css"> <!-- Link to your CSS file -->
<style>
    .container {
            max-width: 800px;
            margin: auto;
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
            margin-top: 7%;
            margin-left: 30%;
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

    <div class="container">
        <h2>User Profile</h2>
        <form action="profile.php" method="POST" enctype="multipart/form-data">
    <label for="profile_picture">Profile Picture:</label>
    <input type="file" name="profile_picture" accept="image/*">
    <?php if ($profile_picture): ?>
        <img src="<?= htmlspecialchars($profile_picture) ?>" alt="Profile Picture" class="profile-picture" width="100"><br>
        <!-- The filename display line has been removed -->
    <?php endif; ?>

    <label for="bio">Bio:</label>
    <textarea name="bio" rows="4"><?= htmlspecialchars($bio) ?></textarea>

    <label for="location">Location:</label>
    <input type="text" name="location" value="<?= htmlspecialchars($location) ?>">

    <input type="submit" value="Update Profile">
</form>


        <div class="current-email">
            <h3>Current Email: <?= htmlspecialchars($email) ?></h3>
            <form action="change_email.php" method="POST">
                <label for="new_email">Change Email:</label>
                <input type="email" name="new_email" required>
                <input type="submit" value="Update Email">
            </form>
        </div>
    </div>
</body>
</html>
