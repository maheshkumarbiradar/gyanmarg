<?php
require_once "../config/db.php";
protect();
$username = $_SESSION['username'] ?? '';
?>

<!DOCTYPE html>
<html lang="en">
<?php get_head("Dashboard - Find My Career"); ?>

<body class="min-h-screen flex flex-col bg-white text-gray-800">

  <div class="flex flex-col md:flex-row w-full">
    <!-- Sidebar -->
    <?php include("./includes/sidebar.php"); ?>

    <!-- Main Content -->
    <main class="flex-1 p-4 md:p-6 w-full overflow-y-auto">
      <!-- Welcome Section -->
      <section class="mb-6 ">
        <h2 class="text-3xl text-gray-800">Home</h2>
        <p class="text-gray-600 text-sm mt-1"> Your account is active and secure. Explore your career opportunities with
          Find My Career.</p>
      </section>

      <!-- Dashboard Grid -->
      <section class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-6 gap-4 md:gap-6">

        <!-- Card Component -->
        <?php
        $cards = [
          [
            "title" => "Profile Progress",
            "description" => "Completed 8 lessons this month.",
            "extra" => '<div class="mt-4 w-full bg-gray-300 rounded-full h-2.5">
                          <div class="bg-green-400 h-2.5 rounded-full" style="width: 80%;"></div>
                        </div>
                        <div class="absolute top-4 right-4 text-green-400 text-xs font-bold uppercase">80%</div>',
            "color" => "from-green-100/20",
            "span" => "lg:col-span-2"
          ],
          [
            "title" => "Profile Overview",
            "description" => "View and update your profile details to enhance your career matches.",
            "extra" => '<a href="settings.php" class="mt-4 inline-block bg-blue-400 text-white px-4 py-2 rounded-full hover:bg-blue-700 transition duration-200 text-sm">Edit Profile</a>',
            "color" => "from-blue-100/20",
            "span" => "lg:col-span-2"
          ],
          [
            "title" => "Career Resources",
            "description" => "Access tools and resources to boost your career journey.",
            "extra" => '<a href="#" class="mt-4 inline-block bg-green-400 text-white px-4 py-2 rounded-lg hover:bg-green-700 transition duration-200 text-sm">Explore</a>',
            "color" => "from-green-100/20",
            "span" => "lg:col-span-2"
          ],
          [
            "title" => "Job Applications",
            "description" => "Track your recent job applications and their status.",
            "extra" => '<div class="mt-4 flex space-x-4">
                          <span class="inline-flex items-center gap-1 text-sm font-medium text-gray-700 bg-gray-100 rounded-full px-3 py-1">✅ 5 Active</span>
                          <span class="inline-flex items-center gap-1 text-sm font-medium text-gray-500 bg-gray-100 rounded-full px-3 py-1">🕒 2 Pending</span>
                        </div>',
            "color" => "from-purple-100/20",
            "span" => "sm:col-span-2 lg:col-span-6"
          ],
        ];

        foreach ($cards as $card): ?>
          <div
            class="col-span-1 <?= $card['span']; ?> group relative bg-zinc-100 backdrop-blur-lg rounded-lg p-6 transition-all duration-300 overflow-hidden hover:bg-white/90">
            <div
              class="absolute inset-0 bg-gradient-to-tr <?= $card['color']; ?> to-transparent opacity-0 group-hover:opacity-100 transition duration-300 rounded-lg pointer-events-none">
            </div>
            <h2 class="text-xl font-semibold"><?= $card['title']; ?></h2>
            <p class="mt-2 text-sm text-gray-400"><?= $card['description']; ?></p>
            <?= $card['extra']; ?>
          </div>
        <?php endforeach; ?>

      </section>
    </main>
  </div>

  <?php include("includes/bottom.php"); ?>
</body>

<style>
  html {
    font-family: -apple-system, BlinkMacSystemFont, "San Francisco", "Helvetica Neue", Helvetica, Arial, sans-serif;
  }
</style>

</html>
