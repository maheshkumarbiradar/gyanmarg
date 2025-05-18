<?php
require_once "../config/db.php";
protect();
$username = $_SESSION['username'] ?? '';

// Fetch filter inputs
$category = $_GET['category'] ?? '';
$difficulty = $_GET['difficulty'] ?? '';

// Build query for quizzes
$query = "SELECT * FROM quizzes WHERE 1=1";
$params = [];

if ($category) {
  $query .= " AND category = ?";
  $params[] = $category;
}
if ($difficulty) {
  $query .= " AND difficulty = ?";
  $params[] = $difficulty;
}
$query .= " ORDER BY RAND() LIMIT 16"; // Randomize, limit to 16 for variety

$stmt = $conn->prepare($query);
if (!$stmt) {
  die("Query failed: " . $conn->error);
}
if ($params) {
  $types = str_repeat('s', count($params));
  $stmt->bind_param($types, ...$params);
}
$stmt->execute();
$questions = $stmt->get_result()->fetch_all(MYSQLI_ASSOC);
$stmt->close();

// Handle form submission
$score = null;
$results = [];
$answers = $_POST['answers'] ?? [];
if ($_SERVER['REQUEST_METHOD'] === 'POST' && !empty($answers)) {
  $score = 0;
  foreach ($questions as $question) {
    $is_correct = isset($answers[$question['id']]) && $answers[$question['id']] === $question['correct_option'];
    if ($is_correct) {
      $score++;
    }
    $results[$question['id']] = [
      'is_correct' => $is_correct,
      'selected' => $answers[$question['id']] ?? null,
      'correct' => $question['correct_option'],
      'explanation' => $question['explanation']
    ];
  }
  // Save progress (simplified, could use a user_progress table)
  $stmt = $conn->prepare("INSERT INTO user_progress (username, quiz_score, total_questions, quiz_date) VALUES (?, ?, ?, NOW())");
  $stmt->bind_param("sii", $username, $score, count($questions));
  $stmt->execute();
  $stmt->close();
}

// Fetch progress
$stmt = $conn->prepare("SELECT AVG(quiz_score / total_questions * 100) as avg_score, COUNT(*) as quizzes_taken FROM user_progress WHERE username = ?");
$stmt->bind_param("s", $username);
$stmt->execute();
$progress = $stmt->get_result()->fetch_assoc();
$stmt->close();

// Learning resources
$resources = [
  ['title' => 'Learn HTML & CSS', 'url' => 'https://www.w3schools.com/html/', 'desc' => 'Free tutorials for web development beginners.'],
  ['title' => 'JavaScript Basics', 'url' => 'https://www.freecodecamp.org/learn/javascript-algorithms-and-data-structures/', 'desc' => 'Interactive JavaScript course for beginners.'],
  ['title' => 'Canva Design School', 'url' => 'https://www.canva.com/learn/design/', 'desc' => 'Learn graphic design with Canva’s free guides.'],
  ['title' => 'SEO for Beginners', 'url' => 'https://moz.com/beginners-guide-to-seo', 'desc' => 'Understand SEO to boost content visibility.'],
  ['title' => 'Video Editing Tips', 'url' => 'https://www.adobe.com/in/creativecloud/video/discover/video-editing.html', 'desc' => 'Master video editing with Adobe’s tutorials.']
];
?>

<!DOCTYPE html>
<html lang="en">
<?php get_head("Learning Center - Find My Career"); ?>

<body class="min-h-screen flex flex-col bg-gray-50 text-gray-800">
  <div class="flex flex-col md:flex-row w-full">
    <!-- Sidebar -->
    <?php include("./includes/sidebar.php"); ?>

    <!-- Main Content -->
    <main class="flex-1 p-4 md:p-6 w-full overflow-y-auto">
      <!-- Welcome Section -->
      <section class="mb-6">
        <h2 class="text-3xl text-gray-800">Learning Center</h2>
        <p class="text-gray-600 text-sm mt-1">Boost your skills with quizzes and resources tailored for you!</p>
      </section>

      <!-- Progress Section -->
      <section class="mb-6 bg-white p-4 rounded-lg shadow-sm">
        <h3 class="text-xl text-gray-800">Your Progress</h3>
        <p class="text-gray-600 text-sm mt-1">
          Average Score: <?= $progress['avg_score'] ? round($progress['avg_score'], 1) . '%' : 'Not started' ?>
          | Quizzes Taken: <?= $progress['quizzes_taken'] ?>
        </p>
      </section>

      <!-- Filters Section -->
      <section class="mb-6 bg-white p-4 rounded-lg shadow-sm">
        <form class="flex flex-col md:flex-row gap-4" method="GET">
          <select name="category" class="p-2 border rounded-md w-full md:w-1/3 focus:ring-2 focus:ring-blue-500">
            <option value="">All Categories</option>
            <option value="Web Development" <?= $category === 'Web Development' ? 'selected' : '' ?>>Web Development
            </option>
            <option value="IT Basics" <?= $category === 'IT Basics' ? 'selected' : '' ?>>IT Basics</option>
            <option value="Graphic Design" <?= $category === 'Graphic Design' ? 'selected' : '' ?>>Graphic Design</option>
            <option value="Content Writing" <?= $category === 'Content Writing' ? 'selected' : '' ?>>Content Writing
            </option>
            <option value="Digital Marketing" <?= $category === 'Digital Marketing' ? 'selected' : '' ?>>Digital Marketing
            </option>
            <option value="Video Editing" <?= $category === 'Video Editing' ? 'selected' : '' ?>>Video Editing</option>
          </select>
          <select name="difficulty" class="p-2 border rounded-md w-full md:w-1/3 focus:ring-2 focus:ring-blue-500">
            <option value="">All Difficulties</option>
            <option value="beginner" <?= $difficulty === 'beginner' ? 'selected' : '' ?>>Beginner</option>
            <option value="intermediate" <?= $difficulty === 'intermediate' ? 'selected' : '' ?>>Intermediate</option>
          </select>
          <button type="submit"
            class="p-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 transition w-full md:w-auto">Filter
            Quizzes</button>
        </form>
      </section>

      <!-- Quiz Section -->
      <section class="mb-6">
        <?php if ($score !== null): ?>
          <div class="mb-4 p-4 bg-green-100 text-green-800 rounded-lg">
            <p class="font-semibold">Your Score: <?= $score ?> / <?= count($questions) ?>
              (<?= round($score / count($questions) * 100, 1) ?>%)</p>
            <p class="text-sm mt-1">Great job! Review your answers below.</p>
          </div>
        <?php endif; ?>

        <form method="POST" class="space-y-6">
          <?php foreach ($questions as $index => $question): ?>
            <div class="p-4 border rounded-lg bg-white shadow-sm hover:shadow-md transition">
              <p class="font-semibold text-gray-800"><?= ($index + 1) . '. ' . htmlspecialchars($question['question']) ?>
              </p>
              <p class="text-gray-500 text-sm mt-1">Category: <?= htmlspecialchars($question['category']) ?> | Difficulty:
                <?= ucfirst($question['difficulty']) ?></p>
              <div class="mt-2 space-y-2">
                <?php foreach (['A' => 'option_a', 'B' => 'option_b', 'C' => 'option_c', 'D' => 'option_d'] as $key => $option): ?>
                  <label class="flex items-center">
                    <input type="radio" name="answers[<?= $question['id'] ?>]" value="<?= $key ?>"
                      class="mr-2 focus:ring-blue-500" required>
                    <?= htmlspecialchars($question[$option]) ?>
                  </label>
                <?php endforeach; ?>
              </div>
              <?php if (isset($results[$question['id']])): ?>
                <div
                  class="mt-2 p-2 rounded <?= $results[$question['id']]['is_correct'] ? 'bg-green-50 text-green-800' : 'bg-red-50 text-red-800' ?>">
                  <p class="text-sm font-medium">
                    <?= $results[$question['id']]['is_correct'] ? 'Correct!' : 'Incorrect. Your answer: ' . $results[$question['id']]['selected'] . ', Correct: ' . $results[$question['id']]['correct'] ?>
                  </p>
                  <p class="text-sm"><?= htmlspecialchars($results[$question['id']]['explanation']) ?></p>
                </div>
              <?php endif; ?>
            </div>
          <?php endforeach; ?>
          <?php if (!empty($questions)): ?>
            <button type="submit" class="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 transition">Submit
              Answers</button>
          <?php else: ?>
            <p class="text-gray-600">No quizzes found. Try adjusting your filters!</p>
          <?php endif; ?>
        </form>
      </section>

      <!-- Resources Section -->
      <section class="mb-6">
        <h3 class="text-xl font-semibold text-gray-800">Recommended Learning Resources</h3>
        <p class="text-gray-600 text-sm mt-1">Explore these free resources to build your skills.</p>
        <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 mt-4">
          <?php foreach ($resources as $resource): ?>
            <div class="p-4 border rounded-lg bg-white shadow-sm hover:shadow-md transition">
              <h4 class="font-semibold text-gray-800"><?= htmlspecialchars($resource['title']) ?></h4>
              <p class="text-gray-600 text-sm mt-1"><?= htmlspecialchars($resource['desc']) ?></p>
              <a href="<?= htmlspecialchars($resource['url']) ?>" target="_blank"
                class="mt-2 inline-block text-blue-600 hover:underline">Start Learning</a>
            </div>
          <?php endforeach; ?>
        </div>
      </section>
    </main>
  </div>

  <?php include("includes/bottom.php"); ?>
</body>

<style>
  html {
    font-family: -apple-system, BlinkMacSystemFont, "San Francisco", "Helvetica Neue", Helvetica, Arial, sans-serif;
  }

  /* Hide scrollbars */
  ::-webkit-scrollbar {
    display: none;
  }

  main {
    -ms-overflow-style: none;
    scrollbar-width: none;
  }

  /* Input focus effects */
  input:focus,
  select:focus {
    outline: none;
    transition: all 0.2s ease-in-out;
  }
</style>

</html>
