<?php
session_start();

// Database configuration
$host = "localhost";
$user = "root";
$pass = "";
$dbname = "auth_demo";

// Database connection
$conn = new mysqli($host, $user, $pass, $dbname);
if ($conn->connect_error) {
  die("Database connection failed: " . $conn->connect_error);
}

// Function to output <head> section
function get_head($page_title = "FindMyCareer")
{
  ?>
  <!DOCTYPE html>
  <html lang="en">

  <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="description" content="find my carrier - your platform for career opportunities and profile management">
    <meta name="robots" content="index, follow">
    <meta name="author" content="sumeet hibare">
    <title><?php echo htmlspecialchars($page_title); ?></title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
      @apply font-sans;
      @apply tracking-tight;

      .scrolly::-webkit-scrollbar {
        display: none;
      }
      .scrolly {
        -ms-overflow-style: none;
        scrollbar-width: none;
      }
    </style>
  </head>
  <?php
}

// Username validation
if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['check_username'])) {
  $username = trim($_GET['check_username']);
  $stmt = $conn->prepare("SELECT id FROM users WHERE username = ?");
  $stmt->bind_param("s", $username);
  $stmt->execute();
  $stmt->store_result();
  echo $stmt->num_rows > 0 ? 'taken' : 'available';
  $stmt->close();
  exit;
}

// Auth check (used in dashboard pages)
function protect()
{
  global $conn;

  if (!isset($_SESSION['username']) || !isset($_SESSION['token'])) {
    header("Location: ../login.php");
    exit;
  }

  $stmt = $conn->prepare("SELECT token FROM users WHERE username = ?");
  $stmt->bind_param("s", $_SESSION['username']);
  $stmt->execute();
  $res = $stmt->get_result();

  if ($res->num_rows !== 1 || $res->fetch_assoc()['token'] !== $_SESSION['token']) {
    session_destroy();
    header("Location: ../login.php");
    exit;
  }
}
?>

