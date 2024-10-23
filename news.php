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

// Fetch blog posts
$stmt = $pdo->query("SELECT * FROM blogs ORDER BY id DESC");
$blogs = $stmt->fetchAll(PDO::FETCH_ASSOC);

// Fetch trending news
$stmt = $pdo->query("SELECT * FROM trending_news ORDER BY popularity DESC LIMIT 5");
$trendingNews = $stmt->fetchAll(PDO::FETCH_ASSOC);

// Fetch most-read blogs
$stmt = $pdo->query("SELECT * FROM blogs ORDER BY views DESC LIMIT 5");
$mostReadBlogs = $stmt->fetchAll(PDO::FETCH_ASSOC);

// Fetch events
$stmt = $pdo->query("SELECT * FROM events ORDER BY event_date ASC");
$events = $stmt->fetchAll(PDO::FETCH_ASSOC);


// Get current date
$currentDate = new DateTime();

// Debugging output (comment out for production)
// echo "<pre>";
// print_r($blogs);
// print_r($trendingNews);
// print_r($mostReadBlogs);
// print_r($events);
// echo "</pre>";
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>News Page</title>
    <link rel="stylesheet" href="styles.css">
    <link href="https://fonts.googleapis.com/css2?family=Merriweather:wght@400&family=Montserrat:wght@700&display=swap" rel="stylesheet">
    <style>
        /* CSS styles will go here */
        body {
    font-family: 'Merriweather', serif;
    line-height: 1.6;
    background-color: #000000;
    color: #343A40;
    margin: 0;
    padding: 20px;
}

.container {
    max-width: 1200px;
    margin: auto;
    padding: 20px;
    background: #fff;
    box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
    border-radius: 8px;
}

h1 {
    font-family: 'Montserrat', sans-serif;
    color: #007BFF;
    font-size: 2.5rem;
    margin-bottom: 20px;
}

h2 {
    font-family: 'Montserrat', sans-serif;
    color: #FF6F61;
    font-size: 2rem;
    margin-top: 40px;
}

 .trending-news, .most-read-blogs, .events {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
    gap: 20px;
}

.news-card, .blog-card, .event-card {
    background: #fff;
    border: 1px solid #e2e2e2;
    border-radius: 8px;
    padding: 15px;
    transition: transform 0.2s, box-shadow 0.2s;
    box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
}


.latest-news {
    position: relative;
    height: 60vh; /* Adjust height as needed */
    overflow: hidden; /* Hide overflow for sliding effect */
}
.news-slider {
    display: flex;
    width: 100%;
    height: 100%;
    margin-left: 0%;
    transition: transform 0.5s ease-in-out; /* Smooth transition */
}

.news-item {
    flex: 0 0 100%; /* Each item takes up full width */
    width: 100%; /* Ensure full width */
    box-sizing: border-box; /* Avoid any padding/margin affecting width */
    background-size: cover;
    background-position: center;
    color: white;
    padding: 20px;
    display: flex;
    flex-direction: column;
    justify-content: flex-end;
    text-shadow: 0 1px 3px rgba(0, 0, 0, 0.7);
    opacity: 0; /* Start hidden */
    transition: opacity 0.5s ease-in-out; /* Smooth opacity transition */
    margin-left: 0%;
}


.news-item.active {
    opacity: 1; /* Show active slide */
}





.upload-date {
    font-size: 0.9rem;
    margin: 5px 0;
    color: #FFD700; /* Gold color for the date */
}
.news-item:hover, .news-card:hover, .blog-card:hover, .event-card:hover {
    transform: translateY(-5px);
    box-shadow: 0 4px 20px rgba(0, 0, 0, 0.15);
}

img {
    max-width: 100%;
    border-radius: 8px;
}

a {
    text-decoration: none;
    color: #007BFF;
    font-weight: bold;
}

a:hover {
    text-decoration: underline;
}

button {
    background-color: #007BFF;
    color: white;
    padding: 10px 15px;
    border: none;
    border-radius: 5px;
    cursor: pointer;
    transition: background-color 0.3s;
}

button:hover {
    background-color: #0056b3; /* Darker shade */
}

/* Responsive Styles */
@media (max-width: 768px) {
    .container {
        padding: 10px;
    }

    h1 {
        font-size: 2rem;
    }

    h2 {
        font-size: 1.5rem;
    }
}





/* MAIN CONTAINER */
.main {
    display: flex;
    align-items: center;
    justify-content: center;
    background-color: #131419;
    box-shadow: 8px 8px 15px #0e0f13, -8px -8px 15px #17181d;
    border-radius: 20px;
    margin: 20px;
    
   
}

/* NEUMORPHIC NAVBAR */
.navbar {
    width: 100%;
    height: 75px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 0 20px;
}

/* LOGO */
.logo {
    color: #FFFFFF;
    font-size: 35px;
    font-family: 'Amarante', cursive;
}
.logo-image {
    height: 50px; /* Adjust height as needed */
    width: auto; /* Maintain aspect ratio */
    margin-right: 15px; /* Space between logo and text */
}

/* MENU */
.menu {
    display: flex;
    align-items: center;
    
}

.menu ul {
    display: flex;
    justify-content: space-around;
    width: 100%;
    align-items: center;
}

.menu ul li {
    list-style: none;
    margin: 0 20px;
   
}

.menu ul li a {
    text-decoration: none;
    color: #FBFFFF;
    font-family: Arial, Helvetica, sans-serif;
    font-weight: bold;
    font-size: 14px;
    transition: 0.4s ease-in-out;
    
}

.menu ul li a:hover {
    color:  #F08080;
}

/* NEUMORPHIC SEARCH BAR */
.search {
    position: relative;
    display: flex;
    align-items: center;
}

.search__input {
    width: 250px;
    height: 40px;
    border: none;
    border-radius: 20px;
    padding-left: 50px;
    background-color: #131419;
    box-shadow: inset 8px 8px 15px #0e0f13, inset -8px -8px 15px #17181d;
    color: #FBFFFF;
    font-size: 14px;
}

.search__input::placeholder {
    color: #aaaaaa;
}

.search__icon {
    position: absolute;
    left: 15px;
    color: #aaaaaa;
    font-size: 20px;
}

/* HAMBURGER MENU */
.hamburger {
    display: none;
    font-size: 30px;
    color: #FBFFFF;
    cursor: pointer;
}

/* DROPDOWN EFFECT FOR MENU */
.menu ul {
    transition: max-height 0.3s ease;
}

.menu ul.collapsed {
    max-height: 0;
    overflow: hidden;
    display: none;
    position: fixed;
}

.menu ul.expanded {
    max-height: 500px;
    display: flex;
    flex-direction: column;
    background-color: #131419;
    border-radius: 20px;
    box-shadow: 8px 8px 15px #0e0f13, -8px -8px 15px #17181d;
    position: absolute;
    top: 75px;
    right: 20px;
    width: 250px;
}

.events {
    margin-top: 1%;
    display: flex;
    flex-wrap: wrap; /* Allow wrapping to new rows */
    gap: 20px; /* Space between cards */
    padding: 10px 0; /* Optional padding */


}

.event-category {
    margin-bottom: 30px; /* Space between categories */
}

.event-category h3 {
    font-size: 1.8rem;
    color: #007BFF;
    margin-bottom: 15px;
}

.event-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
    gap: 20px; /* Space between cards */
}

.event-card {
    flex: 1 1 250px; /* Allow cards to grow and shrink, with a base width of 250px */
    max-width: 300px; /* Optional max width to keep cards uniform */
    padding: 20px;
    border: 1px solid #e2e2e2;
    border-radius: 8px;
    background: #f9f9f9;
    box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
    transition: transform 0.2s, box-shadow 0.2s;
}

.event-card h4 {
    font-size: 1.5rem;
    color: #343A40;
    margin-bottom: 10px;
}

.event-card p {
    margin: 5px 0;
    color: #6c757d; /* Slightly muted text color */
}

.event-card:hover {
    transform: translateY(-5px);
    box-shadow: 0 4px 20px rgba(0, 0, 0, 0.15);
}


.past-events{
    margin-top: auto;
    display: flex;
    gap: 20px;
    flex-wrap: wrap;
    margin-top: 30px;
}
.upcoming-events{
   
    display: flex;
    gap: 20px;
    flex-wrap: wrap;
    margin-top: 30px;
    
}


    </style>
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
                    <li class="search-menu-item">
                    <form action="search.php" method="GET" class="search">
                        <input type="text" name="query" class="search__input" placeholder="Search..." required>
                        <button type="submit" class="search__icon">
                            <ion-icon name="search"></ion-icon>
                        </button>
                    </form>
                </li>
                </ul>
            </div>
            <div class="hamburger" id="hamburger">
                <ion-icon name="menu-outline"></ion-icon>
            </div>
        </div>
    </div>
    <div class="container">
        <h1>Latest News</h1>
        <div class="latest-news">
        
    <div class="news-slider">
        <?php if (!empty($blogs)): ?>
            <?php foreach ($blogs as $blog): ?>
                

                <div class="news-item" style="background-image: url('uploads/<?php echo htmlspecialchars($blog['image']); ?>');">

              

                    <h3><?php echo htmlspecialchars($blog['title']); ?></h3>
                    <p class="upload-date"><?php echo date("F j, Y", strtotime($blog['created_at'])); ?></p>
                    <p><?php echo htmlspecialchars($blog['summary']); ?></p>
                    <a href="read.php?id=<?php echo $blog['id']; ?>">Read more</a>
               

                </div>
                
                
            <?php endforeach; ?>
        <?php else: ?>
            <p>No blogs available.</p>
        <?php endif; ?>
    </div>
</div>




        <h2>Trending News</h2>
       

         <div class="trending-news">
            <?php if (!empty($trendingNews)): ?>
                <?php foreach ($trendingNews as $news): ?>
                    <div class="news-card">
                        <h3><?php echo htmlspecialchars($news['title']); ?></h3>
                        <p><?php echo htmlspecialchars($news['summary']); ?></p>
                        <a href="read.php?id=<?php echo $news['id']; ?>">Read more</a>
                    </div>
                <?php endforeach; ?>
            <?php else: ?>
                <p>No trending news available.</p>
            <?php endif; ?>
        </div>
        
       

        <h2>Most Read Blogs</h2>

        
            
    <div class="most-read-blogs">

            <?php if (!empty($mostReadBlogs)): ?>
                <?php foreach ($mostReadBlogs as $blog): ?>
                    <div class="blog-card">
                        <h3><?php echo htmlspecialchars($blog['title']); ?></h3>
                        <img src="uploads/<?php echo htmlspecialchars($blog['image']); ?>" alt="<?php echo htmlspecialchars($blog['title']); ?>">
                        <p><?php echo htmlspecialchars($blog['summary']); ?></p>
                        <a href="read.php?id=<?php echo $blog['id']; ?>">Read more</a>
                    </div>
                <?php endforeach; ?>
            <?php else: ?>
                <p>No most read blogs available.</p>
            <?php endif; ?>
        </div>
   
        



        <div class="events">


        <h2>Events</h2>

        
        
        <div class="events">
        
       
    <?php if (!empty($events)): ?>
        <?php
        // Get current date
        $currentDate = new DateTime();
        
        // Initialize arrays for upcoming and past events
        $upcomingEvents = [];
        $pastEvents = [];

        foreach ($events as $event): 
            // Convert event date to DateTime object
            $eventDate = new DateTime($event['event_date']);
            // Check if the event is past
            if ($eventDate < $currentDate) {
                $pastEvents[] = $event;
            } else {
                $upcomingEvents[] = $event;
            }
        endforeach;
        ?>

        
        <div class="upcoming-events">
        
            <?php if (!empty($upcomingEvents)): ?>
                <?php foreach ($upcomingEvents as $event): ?>
                    <div class="event-card">
                        <h3><?php echo htmlspecialchars($event['title']); ?></h3>
                        <p>Date: <strong><?php echo htmlspecialchars(date("F j, Y", strtotime($event['event_date']))); ?></strong></p>
                        <p><?php echo htmlspecialchars($event['description']); ?></p>
                    </div>
                <?php endforeach; ?>
            <?php else: ?>
                <p>No upcoming events available.</p>
            <?php endif; ?>
        </div>

       
        <div class="past-events">
        <h3>Past Events</h3>
            <?php if (!empty($pastEvents)): ?>
                <?php foreach ($pastEvents as $event): ?>
                    <div class="event-card">
                        <h3><?php echo htmlspecialchars($event['title']); ?></h3>
                        <p>Date: <strong><?php echo htmlspecialchars(date("F j, Y", strtotime($event['event_date']))); ?></strong> <span style="color: red;">(Past)</span></p>
                        <p><?php echo htmlspecialchars($event['description']); ?></p>
                    </div>
                <?php endforeach; ?>
            <?php else: ?>
                <p>No past events available.</p>
            <?php endif; ?>
        </div>

    <?php else: ?>
        <p>No events available.</p>
    <?php endif; ?>
</div>




</div>

</div>

    </div>
    <script>
   let currentIndex = 0;
const items = document.querySelectorAll('.news-item');
const slider = document.querySelector('.news-slider');

function showNextItem() {
    // Hide the current item
    items[currentIndex].classList.remove('active');

    // Move to the next item
    currentIndex = (currentIndex + 1) % items.length;

    // Show the next item
    items[currentIndex].classList.add('active');

    // Translate the slider to match the current slide position
    slider.style.transform = `translateX(-${currentIndex * 100}%)`;
}

// Initial setup: hide all except the first
items.forEach((item, index) => {
    item.classList.remove('active');
    if (index === 0) {
        item.classList.add('active');
    }
});

// Automatically move to the next slide every 5 seconds
setInterval(showNextItem, 5000);

</script>
<script src="script.js"></script>

</body>
</html>