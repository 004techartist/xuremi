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

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $fileDescription = $_POST['description'];
    $file = $_FILES['file'];
    $userEmail = $_SESSION['user']['email'];

    // Handle file upload
    $targetDir = "uploads/";
    $targetFile = $targetDir . basename($file["name"]);

    if (move_uploaded_file($file["tmp_name"], $targetFile)) {
        $stmt = $pdo->prepare("INSERT INTO user_uploads (user_email, file_name, file_description, file_path, file_type) VALUES (?, ?, ?, ?, ?)");
        $fileType = pathinfo($file["name"], PATHINFO_EXTENSION);

        if ($stmt->execute([$userEmail, basename($file["name"]), $fileDescription, $targetFile, $fileType])) {
            header('Location: upload.php?success=1');
            exit;
        } else {
            echo "<p class='error'>Failed to save upload information in the database.</p>";
        }
    } else {
        echo "<p class='error'>File upload failed.</p>";
    }
}

// Fetch user uploads
$userEmail = $_SESSION['user']['email'];
$uploads = $pdo->query("SELECT * FROM user_uploads WHERE user_email = '$userEmail'")->fetchAll();
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Upload Your Designs</title>
    <link rel="stylesheet" href="styles.css"> <!-- Link to an external CSS file for better organization -->
    <link href="https://fonts.googleapis.com/css2?family=Amarante&display=swap" rel="stylesheet">
    <style>
      
      body {
            font-family: 'Arial', sans-serif;
            background-color: #000000;
            margin: 0;
            padding: 20px;
            display: flex;
            flex-direction: column;
            align-items: center;
        }
        h1 {
            color: #fff;
            margin-bottom: 20px;
        }
        .upload-form {
            background: #fff;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
            margin-bottom: 30px;
            width: 100%;
            max-width: 600px;
        }
        textarea {
            width: 100%;
            height: 80px;
            padding: 10px;
            border: 1px solid #ccc;
            border-radius: 5px;
            margin-bottom: 10px;
        }
        input[type="file"] {
            margin: 10px 0;
        }
        input[type="submit"] {
            background-color: #007bff;
            color: white;
            padding: 10px 15px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            width: 100%;
            font-size: 16px;
        }
        input[type="submit"]:hover {
            background-color: #0056b3;
        }
        .uploads {
            display: flex;
            flex-wrap: wrap;
            gap: 15px;
            justify-content: center;
        }
        .cardi {
            background: #fff;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
            padding: 15px;
            width: 200px;
            text-align: center;
        }
        .cardi h3 {
            font-size: 1.2em;
            margin: 0;
        }
        .cardi p {
            color: #666;
        }
        .cardi a {
            text-decoration: none;
            color: #007bff;
        }
        .cardi a:hover {
            text-decoration: underline;
        }
        .error {
            color: red;
        }

/* MAIN CONTAINER */
.main {
    display: flex;
    align-items: center;
    justify-content: center;
    background-color: #131419;
    box-shadow: 8px 8px 15px #0e0f13, -8px -8px 15px #17181d;
    border-radius: 20px;
    margin: 20px;
   
}

/* NEUMORPHIC NAVBAR */
.navbar {
    width: 100%;
    height: 75px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 0 20px;
}

/* LOGO */
.logo {
    color: #FFFFFF;
    font-size: 35px;
    font-family: 'Amarante', cursive;
}
.logo-image {
    height: 50px; /* Adjust height as needed */
    width: auto; /* Maintain aspect ratio */
    margin-right: 15px; /* Space between logo and text */
}

/* MENU */
.menu {
    display: flex;
    align-items: center;
    
}

.menu ul {
    display: flex;
    justify-content: space-around;
    width: 100%;
    align-items: center;
}

.menu ul li {
    list-style: none;
    margin: 0 20px;
   
}

.menu ul li a {
    text-decoration: none;
    color: #FBFFFF;
    font-family: Arial, Helvetica, sans-serif;
    font-weight: bold;
    font-size: 14px;
    transition: 0.4s ease-in-out;
    
}

.menu ul li a:hover {
    color:  #F08080;
}

/* NEUMORPHIC SEARCH BAR */
.search {
    position: relative;
    display: flex;
    align-items: center;
}

.search__input {
    width: 250px;
    height: 40px;
    border: none;
    border-radius: 20px;
    padding-left: 50px;
    background-color: #131419;
    box-shadow: inset 8px 8px 15px #0e0f13, inset -8px -8px 15px #17181d;
    color: #FBFFFF;
    font-size: 14px;
}

.search__input::placeholder {
    color: #aaaaaa;
}

.search__icon {
    position: absolute;
    left: 15px;
    color: #aaaaaa;
    font-size: 20px;
}

/* HAMBURGER MENU */
.hamburger {
    display: none;
    font-size: 30px;
    color: #FBFFFF;
    cursor: pointer;
}

/* DROPDOWN EFFECT FOR MENU */
.menu ul {
    transition: max-height 0.3s ease;
}

.menu ul.collapsed {
    max-height: 0;
    overflow: hidden;
    display: none;
    position: fixed;
}

.menu ul.expanded {
    max-height: 500px;
    display: flex;
    flex-direction: column;
    background-color: #131419;
    border-radius: 20px;
    box-shadow: 8px 8px 15px #0e0f13, -8px -8px 15px #17181d;
    position: absolute;
    top: 75px;
    right: 20px;
    width: 250px;
}
        /* Responsive styles */
        @media (max-width: 768px) {
            .menu ul {
                display: none;
                flex-direction: column;
                position: absolute;
                top: 60px;
                left: 0;
                background: #131419;
                width: 100%;
            }
            .menu ul.active {
                display: flex;
            }
            .hamburger {
                display: block;
            }
        }
    </style>
     
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

    <h1>Upload Your Designs</h1>

    <div class="upload-form">
        <form action="upload.php" method="POST" enctype="multipart/form-data">
            <textarea name="description" placeholder="Describe your content (e.g., design details)" required></textarea>
            <input type="file" name="file" accept=".jpg,.jpeg,.png,.pdf" required>
            <small>Upload your designs here (JPG, PNG, PDF formats are allowed).</small><br>
            <input type="submit" value="Upload">
        </form>
    </div>

    <h2>Your Uploaded Files</h2>
    <div class="uploads">
        <?php foreach ($uploads as $upload): ?>
            <div class="cardi">
                <h3><?php echo htmlspecialchars($upload['file_name']); ?></h3>
                <p><?php echo htmlspecialchars($upload['file_description']); ?></p>
                <a href="<?php echo htmlspecialchars($upload['file_path']); ?>" target="_blank">Download</a>
            </div>
        <?php endforeach; ?>
    </div>

    <script>
        document.getElementById("hamburger").addEventListener("click", function() {
            const menu = document.getElementById("menu").querySelector("ul");
            menu.classList.toggle("active");
        });
    </script>
    <script src="script.js"></script>
</body>
</html>
