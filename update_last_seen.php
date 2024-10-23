<?php
session_start();
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

// Check if the user is logged in
if (isset($_SESSION['user'])) {
    $user_email = $_SESSION['user']['email'];

    // Update only the logged-in user's last_seen and is_online status
    $stmt = $pdo->prepare("UPDATE users SET last_seen = NOW(), is_online = 1 WHERE email = :email");
    $stmt->execute(['email' => $user_email]);
}

echo "Success";
