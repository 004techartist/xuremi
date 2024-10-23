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

// Fetch all unique user emails
$userEmails = $pdo->query("SELECT DISTINCT user_email FROM user_uploads")->fetchAll(PDO::FETCH_COLUMN);

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['note'])) {
    $userEmail = $_POST['user_email'];
    $note = $_POST['note'];

    // Insert sticky note
    $stmt = $pdo->prepare("INSERT INTO user_notes (user_email, note) VALUES (?, ?)");
    $stmt->execute([$userEmail, $note]);
}

// Fetch notes for a specific user
$notes = [];
if (isset($_GET['user_email'])) {
    $userEmail = $_GET['user_email'];
    $notes = $pdo->query("SELECT * FROM user_notes WHERE user_email = '$userEmail'")->fetchAll();
    $uploads = $pdo->query("SELECT * FROM user_uploads WHERE user_email = '$userEmail'")->fetchAll();
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Dashboard</title>
    <link href="https://fonts.googleapis.com/css2?family=Roboto:wght@400;500&display=swap" rel="stylesheet">
    <style>
        body {
            font-family: 'Roboto', sans-serif;
            margin: 0;
            padding: 0;
            background-color: #f4f4f9;
            color: #333;
            display: flex;
            flex-direction: column;
            align-items: center;
        }

        .navbar {
            width: 100%;
            height: 75px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 0 20px;
            background-color: #5e72e4;
            position: fixed;
            top: 0;
            left: 0;
            z-index: 1000;
        }

        .navbar ul {
            list-style-type: none;
            margin: 0;
            padding: 0;
            display: flex;
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

        .content {
            max-width: 1000px;
            width: 100%;
            margin-top: 100px; /* To make space for the fixed navbar */
            padding: 20px;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
        }

        h1, h2, h3 {
            color: #444;
        }

        ul {
            list-style-type: none;
            padding: 0;
        }

        li {
            padding: 10px;
            border-bottom: 1px solid #e0e0e0;
        }

        li:last-child {
            border-bottom: none;
        }

        a {
            text-decoration: none;
            color: #007bff;
        }

        a:hover {
            text-decoration: underline;
        }

        textarea {
            width: 100%;
            height: 100px;
            padding: 10px;
            border: 1px solid #ccc;
            border-radius: 5px;
            margin-top: 10px;
            resize: none;
        }

        input[type="submit"] {
            background-color: #007bff;
            color: white;
            border: none;
            padding: 10px 15px;
            border-radius: 5px;
            cursor: pointer;
            margin-top: 10px;
        }

        input[type="submit"]:hover {
            background-color: #0056b3;
        }
    </style>
</head>
<body>

<div class="navbar">
    <div class="icon">
        <h2 class="logo">Xuremi</h2>
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
</div>

<div class="content">
    <h1>Admin Dashboard</h1>
    <h2>User Emails</h2>
    <ul>
        <?php foreach ($userEmails as $email): ?>
            <li>
                <a href="?user_email=<?php echo urlencode($email); ?>"><?php echo htmlspecialchars($email); ?></a>
            </li>
        <?php endforeach; ?>
    </ul>

    <?php if (isset($userEmail)): ?>
        <h3>Uploads by <?php echo htmlspecialchars($userEmail); ?></h3>
        <ul>
            <?php foreach ($uploads as $upload): ?>
                <li>
                    <?php echo htmlspecialchars($upload['file_name']); ?> - <?php echo htmlspecialchars($upload['file_description']); ?>
                    <a href="<?php echo htmlspecialchars($upload['file_path']); ?>">Download</a>
                    <?php echo $upload['is_read'] ? ' (Read)' : ' (Unread)'; ?>
                </li>
            <?php endforeach; ?>
        </ul>

        <h3>Sticky Notes</h3>
        <form method="POST">
            <input type="hidden" name="user_email" value="<?php echo htmlspecialchars($userEmail); ?>">
            <textarea name="note" placeholder="Add a sticky note" required></textarea><br>
            <input type="submit" value="Add Note">
        </form>
        
        <ul>
            <?php foreach ($notes as $note): ?>
                <li>
                    <?php echo htmlspecialchars($note['note']); ?> - <?php echo htmlspecialchars($note['created_at']); ?>
                    <?php echo $note['is_read'] ? ' (Read)' : ' (Unread)'; ?>
                </li>
            <?php endforeach; ?>
        </ul>
    <?php endif; ?>
</div>

</body>
</html>
