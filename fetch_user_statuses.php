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

// Set timeout to 5 minutes (300 seconds)
$timeoutDuration = 300;
$currentTimestamp = time();

// Fetch all users' online status
$stmt = $pdo->query("SELECT email, role, is_online, last_seen FROM users");
$users = $stmt->fetchAll(PDO::FETCH_ASSOC);

// Check if users should be marked as offline
foreach ($users as &$user) {
    $lastSeenTimestamp = strtotime($user['last_seen']);
    if ($currentTimestamp - $lastSeenTimestamp > $timeoutDuration) {
        $user['is_online'] = 0;
    }
}

// Total online count
$totalOnline = count(array_filter($users, fn($user) => $user['is_online']));

// Return JSON response
echo json_encode([
    'totalOnline' => $totalOnline,
    'users' => $users,
]);
?>
