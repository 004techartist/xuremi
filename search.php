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

// Handle the search query
$query = '';
$results = [];

if (isset($_GET['query'])) {
    $query = trim($_GET['query']);

    // Fetch data from blogs
    $stmt = $pdo->prepare("SELECT * FROM blogs WHERE title LIKE :query OR summary LIKE :query");
    $stmt->execute(['query' => "%$query%"]);
    $results['blogs'] = $stmt->fetchAll(PDO::FETCH_ASSOC);

    // Fetch data from trending news
    $stmt = $pdo->prepare("SELECT * FROM trending_news WHERE title LIKE :query OR summary LIKE :query");
    $stmt->execute(['query' => "%$query%"]);
    $results['trendingNews'] = $stmt->fetchAll(PDO::FETCH_ASSOC);
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Search Results</title>
    <link rel="stylesheet" href="styles.css">
</head>
<body>

<div class="container">
    <h1>Search Results for "<?php echo htmlspecialchars($query); ?>"</h1>

    <h2>Blogs</h2>
    <div class="search-results">
        <?php if (!empty($results['blogs'])): ?>
            <?php foreach ($results['blogs'] as $blog): ?>
                <div class="searchable-item">
                    <h3><?php echo htmlspecialchars($blog['title']); ?></h3>
                    <p><?php echo htmlspecialchars($blog['summary']); ?></p>
                    <a href="read.php?id=<?php echo $blog['id']; ?>">Read more</a>
                </div>
            <?php endforeach; ?>
        <?php else: ?>
            <p>No blogs found.</p>
        <?php endif; ?>
    </div>

    <h2>Trending News</h2>
    <div class="search-results">
        <?php if (!empty($results['trendingNews'])): ?>
            <?php foreach ($results['trendingNews'] as $news): ?>
                <div class="searchable-item">
                    <h3><?php echo htmlspecialchars($news['title']); ?></h3>
                    <p><?php echo htmlspecialchars($news['summary']); ?></p>
                    <a href="read.php?id=<?php echo $news['id']; ?>">Read more</a>
                </div>
            <?php endforeach; ?>
        <?php else: ?>
            <p>No trending news found.</p>
        <?php endif; ?>
    </div>
</div>

</body>
</html>
