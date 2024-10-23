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

// Fetch all apps
$stmt = $pdo->query("SELECT id, name, created_at FROM apps");
$apps = $stmt->fetchAll(PDO::FETCH_ASSOC); // Fetch all results as an associative array

// Delete an app
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['delete'])) {
    $appId = $_POST['app_id'];

    // Delete the app from the database
    $stmt = $pdo->prepare("DELETE FROM apps WHERE id = :id");
    $stmt->execute(['id' => $appId]);

    // Redirect to refresh the page
    header("Location: appdeletion.php");
    exit;
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <title>Admin Dashboard - Delete App</title>
    <link rel="stylesheet" href="adm.css">
    <script type="module" src="https://unpkg.com/ionicons@5.5.2/dist/ionicons/ionicons.esm.js"></script>
    <script nomodule src="https://unpkg.com/ionicons@5.5.2/dist/ionicons/ionicons.js"></script>
</head>
<body>
<div class="main">
        <div class="navbar">
            <div class="icon">
                <h2 class="logo">Xuremi</h2>
            </div>
            <div class="menu" id="menu">
                <ul>
                    <li><a href="index.php">HOME</a></li>
                    
                    <li><a href="customercompany.php">PRODUCTS</a></li>
                    <li><a href="About.html">ABOUT</a></li>
                    
                    <li><a href="news.html">NEWS</a></li>
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
    </div>

    <h1>Admin Dashboard: Delete Apps</h1>
    <table border="1" class="blTable" >
        <thead>
            <tr>
                <th>App Name</th>
                <th>Upload Date</th>
                <th>Action</th>
            </tr>
        </thead>
        <tbody>
            <?php if (!empty($apps)): ?>
                <?php foreach ($apps as $app): ?>
                    <tr>
                        <td><?= htmlspecialchars($app['name']) ?></td>
                        <td><?= $app['created_at'] ?></td>
                        <td>
                            <form method="post">
                                <input type="hidden" name="app_id" value="<?= $app['id'] ?>">
                                <button type="submit" name="delete">Delete</button>
                            </form>
                        </td>
                    </tr>
                <?php endforeach; ?>
            <?php else: ?>
                <tr>
                    <td colspan="3">No apps found.</td>
                </tr>
            <?php endif; ?>
        </tbody>
    </table>
</body>
</html>
