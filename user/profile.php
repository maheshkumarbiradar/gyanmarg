<?php
require_once "../config/db.php";
protect();
$username = $_SESSION['username'];
$stmt = $conn->prepare("SELECT email, location, dob, profile_pic FROM users WHERE username=?");
$stmt->bind_param("s", $username);
$stmt->execute();
$user = $stmt->get_result()->fetch_assoc();
?>

<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Profile</title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-100 p-6 pb-20">

<div class="max-w-xl mx-auto bg-white rounded shadow p-6">
  <div class="flex items-center space-x-4 mb-6">
    <img src="<?= $user['profile_pic'] ?? 'https://via.placeholder.com/100' ?>" class="w-20 h-20 rounded-full">
    <div>
      <h2 class="text-xl font-bold"><?= htmlspecialchars($username) ?></h2>
      <p class="text-sm text-gray-500"><?= htmlspecialchars($user['email']) ?></p>
    </div>
  </div>
  <button onclick="toggleModal('updateModal')" class="bg-blue-600 text-white px-4 py-2 rounded">Edit Profile</button>
  <button onclick="toggleModal('passwordModal')" class="ml-2 bg-gray-600 text-white px-4 py-2 rounded">Change Password</button>
</div>

<?php include("includes/bottom.php"); ?>

<!-- Update Profile Modal -->
<div id="updateModal" class="fixed inset-0 bg-black bg-opacity-30 hidden justify-center items-center z-50">
  <div class="bg-white p-6 rounded w-full max-w-md space-y-4">
    <h2 class="text-xl font-bold">Update Profile</h2>
    <form method="POST" enctype="multipart/form-data" action="profile_update.php">
      <input type="email" name="email" value="<?= htmlspecialchars($user['email']) ?>" class="w-full border p-2 rounded" required>
      <input type="text" name="location" value="<?= htmlspecialchars($user['location']) ?>" class="w-full border p-2 rounded mt-2">
      <input type="date" name="dob" value="<?= $user['dob'] ?>" class="w-full border p-2 rounded mt-2">
      <input type="file" name="profile_pic" class="mt-2">
      <div class="mt-4 flex justify-end">
        <button type="submit" class="bg-blue-600 text-white px-4 py-2 rounded">Save</button>
        <button type="button" onclick="toggleModal('updateModal')" class="ml-2">Cancel</button>
      </div>
    </form>
  </div>
</div>

<!-- Change Password Modal -->
<div id="passwordModal" class="fixed inset-0 bg-black bg-opacity-30 hidden justify-center items-center z-50">
  <div class="bg-white p-6 rounded w-full max-w-md space-y-4">
    <h2 class="text-xl font-bold">Change Password</h2>
    <form method="POST" action="password_update.php">
      <input type="password" name="old_password" placeholder="Current Password" class="w-full border p-2 rounded" required>
      <input type="password" name="new_password" placeholder="New Password" class="w-full border p-2 rounded mt-2" required>
      <div class="mt-4 flex justify-end">
        <button type="submit" class="bg-green-600 text-white px-4 py-2 rounded">Change</button>
        <button type="button" onclick="toggleModal('passwordModal')" class="ml-2">Cancel</button>
      </div>
    </form>
  </div>
</div>

<script>
function toggleModal(id) {
  const modal = document.getElementById(id);
  modal.classList.toggle("hidden");
  modal.classList.toggle("flex");
}
</script>

</body>
</html>
