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

session_start();

// Check if the logged-in user is an admin
if (!isset($_SESSION['user']) || ($_SESSION['user']['role'] !== 'admin' && $_SESSION['user']['role'] !== 'superadmin')) {
    die("Unauthorized access.");
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $userEmail = trim($_POST['user_email']);
    $appName = trim($_POST['app_name']);
    $appDescription = trim($_POST['app_description']);

    // Check if the email exists in the database
    $stmt = $pdo->prepare("SELECT COUNT(*) FROM users WHERE email = ?");
    $stmt->execute([$userEmail]);
    if ($stmt->fetchColumn() == 0) {
        echo json_encode(["error" => "The product cannot be sent; the email does not exist in the database."]);
        exit;
    }

    // Handle file uploads
    $uploadDir = 'uploads/';
    $imageFile = $uploadDir . basename($_FILES['image']['name']);
    $appFile = $uploadDir . basename($_FILES['file']['name']);

    // Move the uploaded files
    if (move_uploaded_file($_FILES['image']['tmp_name'], $imageFile) && move_uploaded_file($_FILES['file']['tmp_name'], $appFile)) {
        // Insert product into the database, associated with the specific user
        $stmt = $pdo->prepare("INSERT INTO private_apps (name, description, image_filename, file_filename, user_email) VALUES (?, ?, ?, ?, ?)");
        if ($stmt->execute([$appName, $appDescription, $_FILES['image']['name'], $_FILES['file']['name'], $userEmail])) {
            echo json_encode(["success" => "Private upload for $userEmail was successful!"]);
        } else {
            echo json_encode(["error" => "Failed to save private app data in the database."]);
        }
    } else {
        echo json_encode(["error" => "Failed to upload files."]);
    }
}
?> 

<!DOCTYPE html>
<html lang="en">
<style>
             body {
            font-family: 'Merriweather', serif;
            background-color: #f4f4f9;
            margin: 0;
            padding: 0;
        }
        .navbar {
            width: 100%;
            height: 75px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 0 20px;
            background-color: #5e72e4;
            position: fixed; /* Make the navbar fixed */
            top: 0; /* Align it to the top */
            z-index: 1000; /* Ensure it stays above other content */
        }
        .navbar ul {
            list-style-type: none;
            margin: 0;
            padding: 0;
            display: flex;
            justify-content: center;
        }
        .navbar li {
            margin: 0 15px;
        }
        .navbar a {
            color: white;
            text-decoration: none;
            font-size: 18px;
        }
        .navbar a:hover {
            text-decoration: underline;
        }

        .form-container {
            background-color: #fff;
            padding: 40px;
            border-radius: 10px;
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
            max-width: 600px;
            width: 100%;
        }

        h2 {
            font-family: 'Montserrat', sans-serif;
            color: #007BFF;
            text-align: center;
            margin-bottom: 30px;
        }

        label {
            display: block;
            font-weight: bold;
            margin-bottom: 5px;
            color: #333;
        }

        input[type="text"],
        input[type="email"],
        input[type="file"],
        textarea {
            width: 100%;
            padding: 10px;
            border: 1px solid #ccc;
            border-radius: 5px;
            margin-bottom: 20px;
            font-size: 1rem;
            box-sizing: border-box;
        }

        button {
            background-color: #007BFF;
            color: white;
            padding: 10px 20px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            width: 100%;
            font-size: 1.2rem;
            transition: background-color 0.3s;
        }

        button:hover {
            background-color: #0056b3;
        }

        .success-message, .error-message {
            text-align: center;
            margin-top: 20px;
        }

        .success-message {
            color: green;
        }

        .error-message {
            color: red;
        }

        /* Responsive Design */
        @media (max-width: 600px) {
            .form-container {
                padding: 20px;
            }

            h2 {
                font-size: 1.8rem;
            }

            button {
                font-size: 1rem;
            }
        }
    </style>
   <link rel="stylesheet" href="adm.css">
   <link href="https://fonts.googleapis.com/css2?family=Amarante&display=swap" rel="stylesheet">
<head>
    <title>Private App Upload</title>
</head>
<body>
<div class="main"></div>
    <div class="navbar">
        <div class="icon">
            <h2 class="logo">xuremi</h2>
        </div>
        <div class="menu" id="menu">
            <ul>
                <li><a href="index.php">HOME</a></li>
                <li><a href="customercompany.php">PRODUCTS</a></li>
                <li><a href="About.html">ABOUT</a></li>
                <li><a href="#">CONTACTS</a></li>
                <li><a href="news.php">NEWS</a></li>
                <li><a href="#">REVIEWS</a></li>
                <li><a href="admindash.html">DASHBOARD</a></li>
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
    <h2>Upload Private App for Specific User</h2>
    <form action="private_upload.php" method="POST" enctype="multipart/form-data">
        <label for="app_name">App Name:</label>
        <input type="text" name="app_name" required><br>

        <label for="app_description">App Description:</label>
        <textarea name="app_description" required></textarea><br>

        <label for="user_email">User Email:</label>
        <input type="email" name="user_email" required><br>

        <label for="image">App Image:</label>
        <input type="file" name="image" required><br>

        <label for="file">App File:</label>
        <input type="file" name="file" required><br>

        <button type="submit">Upload Private App</button>
    </form>
</body>
</html>
