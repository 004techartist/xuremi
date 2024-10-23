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

// Admin email
$admin_email = 'murithikelvin396@gmail.com';

// Fetch unique users who sent messages
$users = $pdo->query("
    SELECT DISTINCT sender_email 
    FROM messages
    WHERE receiver_email = '$admin_email'
    ORDER BY sender_email
")->fetchAll(PDO::FETCH_ASSOC);

// Handle message sending
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['message'], $_POST['recipient_email'])) {
    $recipient_email = $_POST['recipient_email'];
    $message = $_POST['message'];

    $stmt = $pdo->prepare("INSERT INTO messages (sender_email, receiver_email, message) VALUES (?, ?, ?)");
    $stmt->execute([$admin_email, $recipient_email, $message]);

    // Redirect to avoid resubmission
    header("Location: " . $_SERVER['PHP_SELF'] . "?user_email=" . urlencode($recipient_email));
    exit;
}

// Get messages for a specific user if selected
$selected_user = null;
$messages = [];

if (isset($_GET['user_email'])) {
    $selected_user = $_GET['user_email'];
    $stmt = $pdo->prepare("
        SELECT * FROM messages
        WHERE (sender_email = ? AND receiver_email = ?) OR (sender_email = ? AND receiver_email = ?)
        ORDER BY created_at ASC
    ");
    $stmt->execute([$selected_user, $admin_email, $admin_email, $selected_user]);
    $messages = $stmt->fetchAll(PDO::FETCH_ASSOC);
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Admin Messages</title>
    <link href="https://fonts.googleapis.com/css2?family=Roboto:wght@400;500&display=swap" rel="stylesheet">
    <style>
        body {
            font-family: 'Roboto', sans-serif;
            margin: 0;
            padding: 0; /* Remove padding */
            background-color: #f4f4f9;
            color: #333;
        }
        .navbar {
            width: 100%;
            height: 75px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 0 20px;
            background-color: #5e72e4;
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
        .container {
            display: flex;
            max-width: 1000px;
            width: 100%;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
            margin-top: 20px; /* Space below the navbar */
            padding: 20px; /* Space inside the container */
            margin-left: 25%;
        }
        .user-list {
            width: 30%;
            border-right: 1px solid #e0e0e0;
            padding: 20px;
            box-sizing: border-box;
        }
        .message-area {
            width: 70%;
            padding: 20px;
            box-sizing: border-box;
        }
        /* Additional styles remain the same */
        .message-area {
            width: 70%;
            padding: 20px;
            box-sizing: border-box;
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
        .sent {
            background-color: #d0ffd8; /* Light green for sent messages */
            text-align: right;
            border-radius: 5px;
            padding: 10px;
        }
        .received {
            background-color: #f9f9f9; /* Light gray for received messages */
            text-align: left;
            border-radius: 5px;
            padding: 10px;
        }
        .unread {
            font-weight: bold;
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
        button {
            background-color: #007bff;
            color: white;
            border: none;
            padding: 10px 15px;
            border-radius: 5px;
            cursor: pointer;
            margin-top: 10px;
        }
        button:hover {
            background-color: #0056b3;
        }
    </style>
    <link rel="stylesheet" href="adm.css">
</head>
<body>

<div class="navbar">
    <div class="icon">
        <h2 class="logo">Xuremi</h2>
    </div>
    <div class="menu" id="menu">
        <ul>
            <li><a href="index.php">HOME</a></li>
            <li><a href="Products.html">PRODUCTS</a></li>
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
</div>

<div class="container">
        <div class="user-list">
            <h2>User List</h2>
            <ul>
                <?php foreach ($users as $user): ?>
                    <li>
                        <a href="?user_email=<?php echo urlencode($user['sender_email']); ?>">
                            <?php echo htmlspecialchars($user['sender_email']); ?>
                        </a>
                    </li>
                <?php endforeach; ?>
            </ul>
        </div>

        <div class="message-area">
            <h1>Messages from Users</h1>

            <?php if ($selected_user): ?>
                <h2>Messages with <?php echo htmlspecialchars($selected_user); ?></h2>
                <ul>
                    <?php foreach ($messages as $message): ?>
                        <li class="<?php echo $message['sender_email'] === $admin_email ? 'sent' : 'received ' . (!$message['is_read'] ? 'unread' : ''); ?>">
                            <strong><?php echo htmlspecialchars($message['sender_email']); ?></strong>: <?php echo htmlspecialchars($message['message']); ?>
                            <span><?php echo $message['is_read'] ? ' (Read)' : ' (Unread)'; ?></span>
                            <br>
                            <small><?php echo $message['created_at']; ?></small>
                        </li>
                    <?php endforeach; ?>
                </ul>

                <h3>Reply to <?php echo htmlspecialchars($selected_user); ?></h3>
                <form method="POST">
                    <input type="hidden" name="recipient_email" value="<?php echo htmlspecialchars($selected_user); ?>">
                    <textarea name="message" placeholder="Reply..." required></textarea>
                    <button type="submit">Send Response</button>
                </form>
            <?php else: ?>
                <p>Select a user to see their messages.</p>
            <?php endif; ?>
        </div>
    </div>
</body>
</html>
