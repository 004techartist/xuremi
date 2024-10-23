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

// Fetch all blogs
$stmt = $pdo->prepare("SELECT id, title, content, image AS image_filename, created_at FROM blogs ORDER BY created_at DESC");
$stmt->execute();
$blogs = $stmt->fetchAll(PDO::FETCH_ASSOC); // Fetch all blog entries into an array

// Delete a blog
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['delete'])) {
    $blogId = $_POST['blog_id'];

    // Delete the blog from the database
    $stmt = $pdo->prepare("DELETE FROM blogs WHERE id = :blog_id");
    $stmt->execute(['blog_id' => $blogId]);

    // Redirect to refresh the page
    header("Location: blogDeletion.php");
    exit;
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <title>Admin Dashboard - Delete Blog</title>
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

    <h1>Admin Dashboard: Delete Blogs</h1>
    <table border="1" class="blTable">
        <thead>
            <tr>
                <th>Title</th>
                <th>Created At</th>
                <th>Action</th>
            </tr>
        </thead>
        <tbody>
            <?php if (!empty($blogs)): ?>
                <?php foreach ($blogs as $blog): ?>
                    <tr>
                        <td><?= htmlspecialchars($blog['title']) ?></td>
                        <td><?= $blog['created_at'] ?></td>
                        <td>
                            <form method="post">
                                <input type="hidden" name="blog_id" value="<?= $blog['id'] ?>">
                                <button type="submit" name="delete">Delete</button>
                            </form>
                        </td>
                    </tr>
                <?php endforeach; ?>
            <?php else: ?>
                <tr>
                    <td colspan="3">No blogs found.</td>
                </tr>
            <?php endif; ?>
        </tbody>
    </table>
</body>
</html>
