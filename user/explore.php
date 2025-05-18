<?php
require_once "../config/db.php";
protect();
$username = $_SESSION['username'] ?? '';

// Fetch current user's profile data
$user_query = "SELECT * FROM users WHERE username = ?";
$user_stmt = $conn->prepare($user_query);
$user_stmt->bind_param('s', $username);
$user_stmt->execute();
$user = $user_stmt->get_result()->fetch_assoc();
$user_stmt->close();

// Initialize user data with defaults if not set
$user_course = $user['course'] ?? '';
$user_stream = $user['stream'] ?? '';
$user_branch = $user['branch'] ?? '';
$user_location = $user['location'] ?? '';
$user_year = $user['year_of_study'] ?? '';

// Fetch filter inputs
$search = $_GET['search'] ?? '';
$location = $_GET['location'] ?? '';
$job_type = $_GET['job_type'] ?? '';
$skills = $_GET['skills'] ?? '';
$experience = $_GET['experience'] ?? '';
$sort = $_GET['sort'] ?? 'recent';
$recommended = isset($_GET['recommended']) ? (bool)$_GET['recommended'] : true;
?>

<!DOCTYPE html>
<html lang="en">
<?php get_head("Explore Jobs - Find My Career"); ?>

<head>
  <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
  <script>
  $(document).ready(function() {
    // Function to load jobs with current filters
    function loadJobs() {
      const filters = {
        search: $('#search').val(),
        location: $('#location').val(),
        job_type: $('#job_type').val(),
        skills: $('#skills').val(),
        experience: $('#experience').val(),
        sort: $('#sort').val(),
        recommended: $('#recommended').is(':checked')
      };

      $.ajax({
        url: 'fetch_jobs.php',
        type: 'GET',
        data: filters,
        success: function(data) {
          $('#job-container').html(data);
        },
        error: function() {
          $('#job-container').html('<p class="text-gray-600 col-span-full text-center">Error loading jobs. Please try again.</p>');
        }
      });
    }

    // Load initial jobs
    loadJobs();

    // Apply real-time filtering
    $('input, select').on('input change', function() {
      loadJobs();
    });
  });
  </script>
</head>

<body class="min-h-screen flex flex-col bg-gray-50 text-gray-800">
  <div class="flex flex-col md:flex-row w-full">
    <!-- Sidebar -->
    <?php include("./includes/sidebar.php"); ?>

    <!-- Main Content -->
    <main class="flex-1 p-4 md:p-6 w-full overflow-y-auto">
      <!-- Welcome Section -->
      <section class="mb-6">
        <h2 class="text-3xl text-gray-800">Explore Jobs for You</h2>
        <p class="text-gray-600 text-sm mt-1">
          <?php if (!empty($user_course) || !empty($user_stream)): ?>
            Showing jobs relevant for <?= htmlspecialchars($user_course) ?> students in <?= htmlspecialchars($user_stream) ?>.
          <?php else: ?>
            Discover entry-level jobs and internships perfect for students like you!
          <?php endif; ?>
        </p>
      </section>

      <!-- Filters Section -->
      <section class="mb-6 bg-white p-4 rounded-lg shadow-sm">
        <form id="filter-form" class="flex flex-col md:flex-row gap-4">
          <input type="text" id="search" name="search" value="<?= htmlspecialchars($search) ?>" placeholder="Search jobs, companies, or keywords..." class="p-2 border rounded-md w-full md:w-1/4 focus:ring-2 focus:ring-blue-500">
          <input type="text" id="location" name="location" value="<?= htmlspecialchars($location) ?>" placeholder="Location (e.g., Bangalore, Remote)" class="p-2 border rounded-md w-full md:w-1/5 focus:ring-2 focus:ring-blue-500">
          <select id="job_type" name="job_type" class="p-2 border rounded-md w-full md:w-1/5 focus:ring-2 focus:ring-blue-500">
            <option value="">All Job Types</option>
            <option value="full-time" <?= $job_type === 'full-time' ? 'selected' : '' ?>>Full-Time</option>
            <option value="part-time" <?= $job_type === 'part-time' ? 'selected' : '' ?>>Part-Time</option>
            <option value="internship" <?= $job_type === 'internship' ? 'selected' : '' ?>>Internship</option>
            <option value="freelance" <?= $job_type === 'freelance' ? 'selected' : '' ?>>Freelance</option>
          </select>
          <input type="text" id="skills" name="skills" value="<?= htmlspecialchars($skills) ?>" placeholder="Skills (e.g., HTML, Writing)" class="p-2 border rounded-md w-full md:w-1/5 focus:ring-2 focus:ring-blue-500">
          <select id="experience" name="experience" class="p-2 border rounded-md w-full md:w-1/5 focus:ring-2 focus:ring-blue-500">
            <option value="">All Experience Levels</option>
            <option value="None" <?= $experience === 'None' ? 'selected' : '' ?>>No Experience</option>
            <option value="0-1 year" <?= $experience === '0-1 year' ? 'selected' : '' ?>>0-1 Year</option>
          </select>
          <select id="sort" name="sort" class="p-2 border rounded-md w-full md:w-1/5 focus:ring-2 focus:ring-blue-500">
            <option value="recent" <?= $sort === 'recent' ? 'selected' : '' ?>>Most Recent</option>
            <option value="salary" <?= $sort === 'salary' ? 'selected' : '' ?>>Highest Salary</option>
          </select>
          <div class="flex items-center">
            <input type="checkbox" id="recommended" name="recommended" <?= $recommended ? 'checked' : '' ?> class="mr-2">
            <label for="recommended" class="text-sm">Show recommended</label>
          </div>
        </form>
      </section>

      <!-- Personalized Recommendation Note -->
      <div id="recommendation-note" class="mb-4 p-3 bg-blue-50 text-blue-800 rounded-lg text-sm" style="display: <?= $recommended ? 'block' : 'none' ?>;">
        <strong>Personalized Recommendations:</strong> These jobs are selected based on your profile (<?= htmlspecialchars($user_course) ?>, <?= htmlspecialchars($user_stream) ?>, and location preferences).
      </div>

      <!-- Job Cards Container -->
      <section id="job-container" class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <!-- Jobs will be loaded here via AJAX -->
      </section>
    </main>
  </div>

  <?php include("includes/bottom.php"); ?>
</body>
</html>
