<?php
// Database connection
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

// Fetch the specific blog post by ID
if (isset($_GET['id'])) {
    $stmt = $pdo->prepare("SELECT title, content, image AS image_filename, created_at FROM blogs WHERE id = :id");
    $stmt->bindValue(':id', $_GET['id'], PDO::PARAM_INT);
    $stmt->execute();
    $blog = $stmt->fetch(PDO::FETCH_ASSOC);

    // Check if the blog exists
    if (!$blog) {
        echo "Blog post not found.";
        exit; // or redirect to the news page
    }
} else {
    // Redirect or show error
    header('Location: news.php');
    exit;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= htmlspecialchars($blog['title']) ?> - Xuremi</title>
    <link rel="stylesheet" href="style.css">
    <style>
        body {
            font-family: 'Helvetica', sans-serif;
            background-color: #f0f0f5;
            margin: 0;
            padding: 0;
            line-height: 1.6;
        }

        /* Hero Section */
        .hero {
            background: url('uploads/<?= htmlspecialchars($blog['image_filename']) ?>') no-repeat center center/cover;
            height: 400px;
            display: flex;
            justify-content: center;
            align-items: center;
            color: #fff;
            text-align: center;
            position: relative;
            box-shadow: inset 0 0 0 2000px rgba(0, 0, 0, 0.5);
        }

        .hero h1 {
            font-size: 50px;
            font-weight: bold;
            text-transform: uppercase;
            letter-spacing: 2px;
        }

        /* Main Content */
        .main-content {
            max-width: 900px;
            margin: -50px auto 40px;
            background: #fff;
            padding: 40px;
            border-radius: 10px;
            box-shadow: 0 8px 20px rgba(0, 0, 0, 0.1);
            position: relative;
            z-index: 1;
        }

        .content-title {
            font-size: 28px;
            margin-bottom: 20px;
            color: #333;
            text-align: center;
            font-weight: 600;
        }

        .content-body {
            font-size: 18px;
            color: #555;
            line-height: 1.8;
        }

        .content-body p {
            margin-bottom: 15px;
        }

        .date {
            font-size: 14px;
            color: #999;
            margin-top: 20px;
            text-align: right;
            border-top: 1px solid #eee;
            padding-top: 10px;
        }

        /* Button Style */
        .back-button {
            display: inline-block;
            margin-top: 20px;
            padding: 12px 30px;
            background-color: #007bff;
            color: white;
            text-decoration: none;
            border-radius: 25px;
            transition: background-color 0.3s ease;
            font-weight: bold;
            text-align: center;
        }

        .back-button:hover {
            background-color: #0056b3;
        }

        /* Responsive Design */
        @media screen and (max-width: 768px) {
            .hero h1 {
                font-size: 36px;
            }

            .main-content {
                padding: 20px;
                margin: 20px;
            }
        }
    </style>
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

    <!-- Hero Section -->
    <div class="hero">

        <h1><?= htmlspecialchars($blog['title']) ?></h1>
    </div>

    <!-- Main Blog Content -->
    <div class="main-content">
        <h2 class="content-title"><?= htmlspecialchars($blog['title']) ?></h2>
        
       
        <div class="content-body">
            <?= $blog['content'] ?>
        </div>

        
        
        <p class="date">Posted on: <?= date('F j, Y', strtotime($blog['created_at'])) ?></p>
        
        <a href="news.php" class="back-button">Back to News</a>
    </div>

</body>
</html>