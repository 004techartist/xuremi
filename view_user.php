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
    header('Content-Type: application/json');
    echo json_encode(["error" => "Database connection failed: " . $e->getMessage()]);
    exit;
}

$user_id = $_GET['id'];

// Fetch messages for the user
$messages = $pdo->query("SELECT * FROM messages WHERE user_id = $user_id")->fetchAll();
?>

<!DOCTYPE html>
<html>
<head>
    <title>User Messages</title>
</head>
<body>
    <h1>User Messages</h1>
    <h2>Messages for User ID: <?php echo $user_id; ?></h2>

    <ul>
        <?php foreach ($messages as $message): ?>
            <li><?php echo htmlspecialchars($message['message']); ?> - <?php echo $message['is_read'] ? 'Read' : 'Unread'; ?></li>
        <?php endforeach; ?>
    </ul>
</body>
</html>
