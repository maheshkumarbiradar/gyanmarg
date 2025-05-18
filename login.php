<?php
require_once "config/db.php";

function user_exists($conn, $username)
{
  $stmt = $conn->prepare("SELECT id FROM users WHERE username = ?");
  $stmt->bind_param("s", $username);
  $stmt->execute();
  return $stmt->get_result()->num_rows > 0;
}

function email_exists($conn, $email)
{
  $stmt = $conn->prepare("SELECT id FROM users WHERE email = ?");
  $stmt->bind_param("s", $email);
  $stmt->execute();
  return $stmt->get_result()->num_rows > 0;
}

function validate_password($password)
{
  return strlen($password) >= 8 && preg_match('/[A-Z]/', $password) && preg_match('/\d/', $password);
}

function calculate_age($dob)
{
  return (new DateTime())->diff(new DateTime($dob))->y;
}

$error = [];
$step = $_POST['step'] ?? 'login';

$username = $_POST['username'] ?? '';
$password = $_POST['password'] ?? '';
$email = $_POST['email'] ?? '';
$dob = $_POST['dob'] ?? '';
$location = $_POST['location'] ?? '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  if ($step === 'login') {
    $stmt = $conn->prepare("SELECT * FROM users WHERE username = ?");
    $stmt->bind_param("s", $username);
    $stmt->execute();
    $res = $stmt->get_result();

    if ($res->num_rows === 1) {
      $user = $res->fetch_assoc();
      if (password_verify($password, $user['password'])) {
        $_SESSION['username'] = $username;
        $_SESSION['token'] = bin2hex(random_bytes(32));
        $stmt = $conn->prepare("UPDATE users SET token = ? WHERE username = ?");
        $stmt->bind_param("ss", $_SESSION['token'], $username);
        $stmt->execute();
        header("Location: user/dashboard.php");
        exit;
      } else {
        $error[] = "Incorrect password.";
      }
    } else {
      $error[] = "User not found. Please sign up.";
    }
  }

  if ($step === 'signup') {
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
      $error[] = "Invalid email format.";
    } elseif (email_exists($conn, $email)) {
      $error[] = "Email already exists.";
    }

    if (!validate_password($password)) {
      $error[] = "Password must be at least 8 characters long, include one uppercase letter and a number.";
    }

    if (calculate_age($dob) < 15) {
      $error[] = "You must be at least 15 years old.";
    }

    if (user_exists($conn, $username)) {
      $error[] = "Username already taken.";
    }

    if (empty($error)) {
      $hash = password_hash($password, PASSWORD_DEFAULT);
      $token = bin2hex(random_bytes(32));
      $stmt = $conn->prepare("INSERT INTO users (username, password, email, dob, location, token) VALUES (?, ?, ?, ?, ?, ?)");
      $stmt->bind_param("ssssss", $username, $hash, $email, $dob, $location, $token);
      $stmt->execute();
      $_SESSION['username'] = $username;
      $_SESSION['token'] = $token;
      header("Location: user/dashboard.php");
      exit;
    }
  }
}
?>

<!DOCTYPE html>
<html lang="en">

<head>
  <meta charset="UTF-8" />
  <title>Login / Signup</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <script src="https://cdn.tailwindcss.com"></script>
  <style>
    .hidden-form {
      max-height: 0;
      opacity: 0;
      overflow: hidden;
      transition: max-height 0.5s ease, opacity 0.5s ease;
    }

    .visible-form {
      max-height: 1000px;
      opacity: 1;
      overflow: visible;
      transition: max-height 0.5s ease, opacity 0.5s ease;
    }
  </style>
</head>

<body class="flex justify-center items-center min-h-screen bg-gray-100">
  <div class="bg-white shadow-md rounded p-6 w-full max-w-md">
    <h2 class="text-2xl font-bold text-center mb-6">Welcome</h2>

    <?php if ($error): ?>
      <div class="bg-red-100 text-red-700 p-3 rounded mb-4">
        <?php foreach ($error as $e)
          echo "<p>$e</p>"; ?>
      </div>
    <?php endif; ?>

    <div id="login-form" class="<?= ($step === 'login') ? 'visible-form' : 'hidden-form' ?>">
      <form method="POST" class="space-y-4" id="loginForm">
        <input type="hidden" name="step" value="login" />
        <input type="text" name="username" id="login-username" required placeholder="Username"
          value="<?= htmlspecialchars($username) ?>" class="w-full p-2 border rounded" />
        <input type="password" name="password" id="login-password" required placeholder="Password"
          class="w-full p-2 border rounded" />
        <div class="flex items-center space-x-2">
          <input type="checkbox" id="toggleLoginPass" />
          <label for="toggleLoginPass" class="text-sm select-none cursor-pointer">Show Password</label>
        </div>
        <button type="submit" class="w-full bg-blue-600 hover:bg-blue-700 text-white py-2 rounded">Login</button>
        <p class="text-center mt-4 text-sm">Don't have an account? <button type="button" id="showSignup"
            class="text-blue-600 hover:underline">Sign Up</button></p>
      </form>
    </div>

    <div id="signup-form" class="<?= ($step === 'signup') ? 'visible-form' : 'hidden-form' ?>">
      <form method="POST" class="space-y-4" id="signupForm" novalidate>
        <input type="hidden" name="step" value="signup" />
        <input type="text" name="username" id="signup-username" required placeholder="Username"
          value="<?= htmlspecialchars($username) ?>" class="w-full p-2 border rounded" />
        <small id="username-msg" class="text-sm text-red-600"></small>

        <input type="password" name="password" id="signup-password" required placeholder="Password"
          class="w-full p-2 border rounded" />
        <small id="password-msg" class="text-sm text-red-600"></small>

        <div class="flex items-center space-x-2">
          <input type="checkbox" id="toggleSignupPass" />
          <label for="toggleSignupPass" class="text-sm select-none cursor-pointer">Show Password</label>
        </div>

        <input type="email" name="email" id="signup-email" required placeholder="Email"
          value="<?= htmlspecialchars($email) ?>" class="w-full p-2 border rounded" />
        <small id="email-msg" class="text-sm text-red-600"></small>

        <input type="date" name="dob" id="signup-dob" required value="<?= htmlspecialchars($dob) ?>"
          class="w-full p-2 border rounded" />
        <small id="dob-msg" class="text-sm text-red-600"></small>

        <input type="text" name="location" id="signup-location" placeholder="Location"
          value="<?= htmlspecialchars($location) ?>" class="w-full p-2 border rounded" />

        <button type="submit" id="signup-submit" disabled
          class="w-full bg-blue-600 hover:bg-blue-700 text-white py-2 rounded opacity-50 cursor-not-allowed">Create
          Account</button>
        <p class="text-center mt-4 text-sm">Already have an account? <button type="button" id="showLogin"
            class="text-blue-600 hover:underline">Login</button></p>
      </form>
    </div>
  </div>

  <script>
    // Show/hide password toggles
    document.getElementById('toggleLoginPass').addEventListener('change', function () {
      const pass = document.getElementById('login-password');
      pass.type = this.checked ? 'text' : 'password';
    });

    document.getElementById('toggleSignupPass').addEventListener('change', function () {
      const pass = document.getElementById('signup-password');
      pass.type = this.checked ? 'text' : 'password';
    });

    // Toggle forms with animation
    const loginForm = document.getElementById('login-form');
    const signupForm = document.getElementById('signup-form');
    const showSignupBtn = document.getElementById('showSignup');
    const showLoginBtn = document.getElementById('showLogin');

    showSignupBtn.addEventListener('click', () => {
      loginForm.classList.replace('visible-form', 'hidden-form');
      signupForm.classList.replace('hidden-form', 'visible-form');
      clearSignupMessagesAndState();
    });

    showLoginBtn.addEventListener('click', () => {
      signupForm.classList.replace('visible-form', 'hidden-form');
      loginForm.classList.replace('hidden-form', 'visible-form');
    });

    // Signup form live validation - only after user inputs in a field
    const signupFields = ['username', 'email', 'password', 'dob'];
    const touched = { username: false, email: false, password: false, dob: false };

    signupFields.forEach(id => {
      const input = document.getElementById('signup-' + id);
      input.addEventListener('input', () => {
        touched[id] = true;
        validateField(id);
        validateForm();
      });
    });

    function validateField(field) {
      const val = document.getElementById('signup-' + field).value.trim();
      const msgElem = document.getElementById(field + '-msg');

      if (val === '') {
        msgElem.textContent = '';
        return false;
      }

      if (field === 'username') {
        msgElem.textContent = val.length >= 3 ? '' : 'Username must be at least 3 characters.';
        return val.length >= 3;
      }
      if (field === 'email') {
        const emailRegex = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;
        msgElem.textContent = emailRegex.test(val) ? '' : 'Invalid email address.';
        return emailRegex.test(val);
      }
      if (field === 'password') {
        const passValid = val.length >= 8 && /[A-Z]/.test(val) && /\d/.test(val);
        msgElem.textContent = passValid ? '' : 'Password must be 8+ chars, with uppercase and number.';
        return passValid;
      }
      if (field === 'dob') {
        const age = calculateAge(val);
        msgElem.textContent = age >= 15 ? '' : 'You must be at least 15 years old.';
        return age >= 15;
      }
      return true;
    }
    function calculateAge(dob) {
      if (!dob) return 0;
      const diff = Date.now() - new Date(dob).getTime();
      const ageDt = new Date(diff);
      return Math.abs(ageDt.getUTCFullYear() - 1970);
    }

    function validateForm() {
      const allValid = signupFields.every(field => touched[field] && validateField(field));
      const allFilled = signupFields.every(field => document.getElementById('signup-' + field).value.trim() !== '');
      const submitBtn = document.getElementById('signup-submit');

      submitBtn.disabled = !(allValid && allFilled);
      submitBtn.classList.toggle('opacity-50', submitBtn.disabled);
      submitBtn.classList.toggle('cursor-not-allowed', submitBtn.disabled);
    }

    function clearSignupMessagesAndState() {
      signupFields.forEach(f => {
        document.getElementById(f + '-msg').textContent = '';
        touched[f] = false;
      });
      document.getElementById('signup-submit').disabled = true;
      document.getElementById('signup-submit').classList.add('opacity-50', 'cursor-not-allowed');
    }
  </script>
</body>

</html>
