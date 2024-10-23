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

// Get the user's email from the session
$user_email = $_SESSION['user']['email'];

// Handle message sending
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['message'])) {
    $admin_email = 'murithikelvin396@gmail.com'; // Replace with actual admin email
    $message = $_POST['message'];

    $stmt = $pdo->prepare("INSERT INTO messages (sender_email, receiver_email, message) VALUES (?, ?, ?)");
    $stmt->execute([$user_email, $admin_email, $message]);
}

// Fetch messages sent by the user
$messages = $pdo->query("
    SELECT * FROM messages
    WHERE sender_email = '$user_email' OR receiver_email = '$user_email'
    ORDER BY created_at DESC
")->fetchAll(PDO::FETCH_ASSOC);



$email = $_SESSION['user']['email'];

// Get user ID based on email
$stmt = $pdo->prepare("SELECT id FROM users WHERE email = ?");
$stmt->execute([$email]);
$user_id = $stmt->fetchColumn();

// Fetch user profile data if user_id is found
$profile_picture = '';
$bio = '';
$location = '';

if ($user_id) {
    $stmt = $pdo->prepare("SELECT profile_picture, bio, location FROM user_profiles WHERE user_id = ?");
    $stmt->execute([$user_id]);
    $profile = $stmt->fetch(PDO::FETCH_ASSOC);

    $profile_picture = $profile['profile_picture'] ?? '';
    $bio = $profile['bio'] ?? '';
    $location = $profile['location'] ?? '';
}

?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>User Messages</title>
    <link href="https://fonts.googleapis.com/css2?family=Roboto:wght@400;500&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="style.css">
    <link rel="stylesheet" href="user.css">
    <script type="module" src="https://unpkg.com/ionicons@5.5.2/dist/ionicons/ionicons.esm.js"></script>
    <script nomodule src="https://unpkg.com/ionicons@5.5.2/dist/ionicons/ionicons.js"></script>
    <link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:opsz,wght,FILL,GRAD@20..48,100..700,0..1,-50..200" />
    <link href="https://fonts.googleapis.com/css2?family=Amarante&display=swap" rel="stylesheet">
    <style>
       body {
    font-family: 'Arial', sans-serif;
    background-color: #000000;
    color: #FBFFFF;
    min-height: 100vh; /* Ensure body takes full height */
    overflow-x: hidden; /* Prevent horizontal scroll */
    display: flex;
    flex-direction: column; /* Allows for flexible content layout */
    min-height: 100%;
}
       
        .main{
     /* Set margin equal to the initial width of the sidebar */
    padding: 20px;
    transition: margin-left 0.4s ease;
    

    display: flex;
    align-items: center;
    justify-content: center;
    background-color: #131419;
    box-shadow: 8px 8px 15px #0e0f13, -8px -8px 15px #17181d;
    border-radius: 20px;
    margin: 20px;
   

}

        h1 {
            color: #fff;
        }
        h2 {
            margin-top: 30px;
            color: #fff;
        }
        form {
    display: flex;
    flex-direction: column; /* Stack textarea and button */
    align-items: center; /* Center form items */
    width: 100%;
    max-width: 600px; /* Ensure it fits within the main content area */
    margin-top: 20px; /* Space from the conversation */
}
        textarea {
    width: 100%;
    height: 100px;
    padding: 10px;
    border: 1px solid #ccc;
    border-radius: 5px;
    margin-top: 10px;
    resize: none;
    font-size: 16px;
    box-shadow: inset 0 1px 3px rgba(0, 0, 0, 0.1);
}

button {
    background-color: #007bff;
    color: white;
    border: none;
    padding: 10px 15px;
    border-radius: 5px;
    cursor: pointer;
    margin-top: 10px;
    transition: background-color 0.3s;
}
        button:hover {
            background-color: #0056b3;
        }
        .conversation {
    width: 100%;
    max-width: 600px;
    margin-top: 20px;
    background: #ffffff;
    padding: 20px;
    border-radius: 8px;
    box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
    display: flex;
    flex-direction: column; /* Align messages vertically */
    align-items: center; /* Center the messages */
    overflow-y: auto; /* Allow scrolling if messages exceed container height */
    max-height: 400px; /* Set a maximum height for the conversation area */
}

.message {
    padding: 10px;
    margin: 5px 0;
    border-radius: 5px;
    position: relative;
    width: fit-content; /* Adjust width to content */
    max-width: 80%; /* Limit maximum width */
    align-self: center; /* Center each message */
    word-wrap: break-word; /* Ensure long words break to the next line */
}


        .sent {
            background-color: #e1ffc7; /* Light green for sent messages */
            text-align: right;
            align-self: flex-end;
        }
        .received {
            background-color: #f0f0f0; /* Light gray for received messages */
            text-align: left;
            align-self: flex-start;
        }
        .unread {
            font-weight: bold;
        }
        small {
            display: block;
            font-size: 0.8em;
            color: #888;
            margin-top: 5px;
        }
        ul {
            list-style-type: none;
            padding: 0;
            margin: 0;
            width: 100%;
        }


        .sidebar {
position: fixed;
top: 16%;
bottom: 32%;
left: 5px;
height: 80%;
width: 85px;
display: flex;
overflow-x: hidden;
flex-direction: column;
background: #161a2d;
padding: 25px 20px;
transition: all 0.4s ease;
z-index: 1000; /* Ensure sidebar stays on top */
border-radius: 30%;
}

.sidebar:hover {
width: 200px;
}

.sidebar .sidebar-header {
display: flex;
align-items: center;
}

.sidebar .sidebar-header img {
width: 42px;
border-radius: 50%;
}

.sidebar .sidebar-header h2 {
color: #fff;
font-size: 1.25rem;
font-weight: 600;
white-space: nowrap;
margin-left: 23px;
}

.sidebar-links h4 {
color: #fff;
font-weight: 500;
white-space: nowrap;
margin: 10px 0;
position: relative;
}

.sidebar-links h4 span {
opacity: 0;
}

.sidebar:hover .sidebar-links h4 span {
opacity: 1;
}

.sidebar-links .menu-separator {
position: absolute;
left: 0;
top: 50%;
width: 100%;
height: 1px;
transform: scaleX(1);
transform: translateY(-50%);
background: #4f52ba;
transform-origin: right;
transition-delay: 0.2s;
}

.sidebar:hover .sidebar-links .menu-separator {
transition-delay: 0s;
transform: scaleX(0);
}

.sidebar-links {
list-style: none;
margin-top: 20px;
height: 80%;
overflow-y: auto;
scrollbar-width: none;
}

.sidebar-links::-webkit-scrollbar {
display: none;
}

.sidebar-links li a {
display: flex;
align-items: center;
gap: 0 20px;
color: #fff;
font-weight: 500;
white-space: nowrap;
padding: 15px 10px;
text-decoration: none;
transition: 0.2s ease;
}

.sidebar-links li a:hover {
color: #161a2d;
background: #fff;
border-radius: 4px;
}

.user-account {
margin-top: 5%;

padding: 12px 10px;
margin-left: -10px;
}

.user-profile {
display: flex;
align-items: center;
color: #161a2d;

}

.user-profile img {
width: 42px;
border-radius: 50%;
border: 2px solid #fff;
}

.user-profile h3 {
font-size: 1rem;
font-weight: 600;
}

.user-profile span {
font-size: 0.775rem;
font-weight: 600;
}

.user-detail {
margin-left: 23px;
white-space: nowrap;

}

.sidebar:hover .user-account {
background: #fff;
border-radius: 4px;
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

.messagecontainer{
    align-items: center;
    margin-left: 30%;
    color:#000000;
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


    <aside class="sidebar">
   
    <ul class="sidebar-links">
      <h4>
        <span>Main Menu</span>
        <div class="menu-separator"></div>
      </h4>
      <li>
        <a href="customercompany.php">
          <span class="material-symbols-outlined"> dashboard </span>Dashboard</a>
      </li>

      <h4>
        <span>General</span>
        <div class="menu-separator"></div>
      </h4>
      <li>
        <a href="upload.php"><span class="material-symbols-outlined"> folder </span>Projects</a>
      </li>
      <li>
        <a href="#"><span class="material-symbols-outlined"> groups </span>Refferals</a>
      </li>
      <li>
        <a href="changepassword.php"><span class="material-symbols-outlined"> move_up </span>Password</a>
      </li>
      <li>
        <a href="#"><span class="material-symbols-outlined"> flag </span>All Invoices</a>
      </li>
      <li>
        <a href="user_messages.php"><span class="material-symbols-outlined">
            notifications_active </span>Notifications</a>
      </li>
      <h4>
        <span>Account</span>
        <div class="menu-separator"></div>
      </h4>
      <li>
        <a href="profile.php"><span class="material-symbols-outlined"> account_circle </span>Profile</a>
      </li>
      
      <li>
        <a href="#"><span class="material-symbols-outlined"> logout </span>Logout</a>
  
      </li>
    </ul>
<!-- Logout Form -->
<form id="logout-form" method="POST" action="#" style="display: none;">
    <input type="hidden" name="action" value="logout">
</form>


<div class="user-account">
        <div class="user-profile">
        <?php if ($profile_picture): ?>
        <img src="<?= htmlspecialchars($profile_picture) ?>" alt="Profile Picture" class="profile-picture" width="100"><br>
        <!-- The filename display line has been removed -->
        <?php endif; ?>

            <div class="user-detail">
                <h3><?= htmlspecialchars($_SESSION['user']['email']) ?></h3>
                <span>Email</span>
            </div>
        </div>
    </div>

  </aside>


<div class="messagecontainer">
    
<h1>Send Message to Admin</h1>
    <h2>Your Conversations</h2>
    <div class="conversation">
        <ul id="message-list">
            <?php foreach ($messages as $message): ?>
                <li class="message <?php echo $message['sender_email'] === $user_email ? 'sent' : 'received'; ?>">
                    <strong><?php echo htmlspecialchars($message['sender_email']); ?></strong>: <?php echo htmlspecialchars($message['message']); ?>
                    <span><?php echo $message['is_read'] ? ' (Read)' : ' (Unread)'; ?></span>
                    <small><?php echo $message['created_at']; ?></small>
                </li>
            <?php endforeach; ?>
        </ul>
    </div>
    <form method="POST">
        <textarea name="message" placeholder="Type your message..." required></textarea>
        <button type="submit">Send Message</button>
    </form>



</div>
   



    <script>
        // Function to fetch messages
        function fetchMessages() {
            $.ajax({
                url: 'fetch_messages.php',
                method: 'GET',
                success: function(data) {
                    $('#message-list').empty(); // Clear current messages
                    // Add new messages at the bottom
                    data.forEach(function(message) {
                        $('#message-list').append(`
                            <li class="message ${message.sender_email === '<?php echo $user_email; ?>' ? 'sent' : 'received'}">
                                <strong>${message.sender_email}</strong>: ${message.message}
                                <span>${message.is_read ? ' (Read)' : ' (Unread)'}</span>
                                <small>${message.created_at}</small>
                            </li>
                        `);
                    });
                    // Scroll to the bottom of the message list
                    $('.conversation').scrollTop($('.conversation')[0].scrollHeight);
                }
            });
        }

        // Fetch messages every 2 seconds
        setInterval(fetchMessages, 2000);

        // Initially fetch messages
        fetchMessages();
    </script>
</body>
</html>
