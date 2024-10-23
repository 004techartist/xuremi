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

// Start session
session_start();

// Check if user is logged in
if (isset($_SESSION['user'])) {
    $user_email = $_SESSION['user']['email'];

    // Update user online status on page load
    $stmt = $pdo->prepare("UPDATE users SET last_seen = NOW(), is_online = 1 WHERE email = :email");
    $stmt->execute(['email' => $user_email]);

    // Fetch all users including their roles
    $stmt = $pdo->query("SELECT email, last_seen, is_online, role FROM users");
    $users = $stmt->fetchAll(PDO::FETCH_ASSOC);

    // Mark users as offline if they haven't been active for a certain time (e.g., 5 minutes)
    $timeoutDuration = 300; // 5 minutes in seconds
    $currentTimestamp = time();

    foreach ($users as &$user) {
        $lastSeenTimestamp = strtotime($user['last_seen']);
        if ($currentTimestamp - $lastSeenTimestamp > $timeoutDuration) {
            // Mark as offline
            $stmt = $pdo->prepare("UPDATE users SET is_online = 0 WHERE email = :email");
            $stmt->execute(['email' => $user['email']]);
            $user['is_online'] = 0; // Update local array for display
        }
    }
} else {
    echo "User not logged in.";
    exit;
}
// Fetch statistics
$totalSignUpsStmt = $pdo->query("SELECT COUNT(*) FROM users");
$totalSignUps = $totalSignUpsStmt->fetchColumn();

$totalOnlineStmt = $pdo->query("SELECT COUNT(*) FROM users WHERE is_online = 1");
$totalOnline = $totalOnlineStmt->fetchColumn();

$todayDate = date('Y-m-d');
$totalDailyUsersStmt = $pdo->prepare("SELECT COUNT(*) FROM users WHERE DATE(created_at) = :today");
$totalDailyUsersStmt->execute(['today' => $todayDate]);
$totalDailyUsers = $totalDailyUsersStmt->fetchColumn();

// Fetch all users including their roles
$stmt = $pdo->query("SELECT email, last_seen, is_online, role FROM users");
$users = $stmt->fetchAll(PDO::FETCH_ASSOC);


?>

<!DOCTYPE html>
<html lang="en">
<head>
    <title>Admin Dashboard - Users</title>
    <link rel="stylesheet" href="adm.css">
    <link href="https://fonts.googleapis.com/css2?family=Amarante&display=swap" rel="stylesheet">
    <style>
        .online { color: green; }
        .offline { color: red; }
    </style>
</head>
<body>
<div class="main"></div>
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
    <h1>Admin Dashboard: User Status</h1>
    <div class="user-stats">
    <h2>User Statistics</h2>
    <div class="dashboardsignup">
        <div class="cardsignup">
            <h2>Total Sign-ups</h2>
            <p><?= $totalSignUps ?></p>
        </div>
        <div class="cardsignup">
            <h2>Currently Online</h2>
            <p><?= $totalOnline ?></p>
        </div>
        <div class="cardsignup">
            <h2>Total Daily Sign-ups</h2>
            <p><?= $totalDailyUsers ?></p>
        </div>
    </div>
</div>

    <table border="1"  class="userT">
        <thead>
            <tr>
                <th>Email</th>
                <th>Status</th>
                <th>Role</th>
            </tr>
        </thead>
        <tbody>
            <?php foreach ($users as $user): ?>
                <tr>
                    <td><?= htmlspecialchars($user['email']) ?></td>
                    <td class="<?= $user['is_online'] ? 'online' : 'offline' ?>">
                        <?= $user['is_online'] ? 'Online' : 'Offline' ?>
                    </td>
                    <td><?= htmlspecialchars($user['role']) ?></td>
                </tr>
            <?php endforeach; ?>
        </tbody>
    </table>
    <script src="script.js"></script>
</body>
</html>