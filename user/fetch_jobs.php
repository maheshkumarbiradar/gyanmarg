<?php
require_once "../config/db.php";

// Fetch filter inputs
$search = $_GET['search'] ?? '';
$location = $_GET['location'] ?? '';
$job_type = $_GET['job_type'] ?? '';
$skills = $_GET['skills'] ?? '';
$experience = $_GET['experience'] ?? '';
$sort = $_GET['sort'] ?? 'recent';
$recommended = isset($_GET['recommended']) ? (bool)$_GET['recommended'] : true;

// Get user data if available
$user = [];
if (isset($_SESSION['username'])) {
    $user_query = "SELECT * FROM users WHERE username = ?";
    $user_stmt = $conn->prepare($user_query);
    $user_stmt->bind_param('s', $_SESSION['username']);
    $user_stmt->execute();
    $user = $user_stmt->get_result()->fetch_assoc();
    $user_stmt->close();
}

$user_course = $user['course'] ?? '';
$user_branch = $user['branch'] ?? '';
$user_location = $user['location'] ?? '';
$user_year = $user['year_of_study'] ?? '';
$user_stream = $user['stream'] ?? '';

// Base query with recommendation logic
$query = "SELECT j.*,
          CASE
            WHEN j.education LIKE ? THEN 5
            WHEN j.skills LIKE ? THEN 4
            WHEN j.location LIKE ? THEN 3
            WHEN j.type = 'internship' AND (j.education LIKE ? OR j.education LIKE ?) THEN 2
            ELSE 1
          END AS relevance_score
          FROM jobs j WHERE 1=1";

$params = [
    "%$user_course%",
    "%$user_branch%",
    "%$user_location%",
    "%$user_year%",
    "%$user_stream%"
];

// Additional filters
if ($search) {
    $query .= " AND (j.title LIKE ? OR j.company LIKE ? OR j.description LIKE ?)";
    array_push($params, "%$search%", "%$search%", "%$search%");
}
if ($location) {
    $query .= " AND j.location LIKE ?";
    $params[] = "%$location%";
}
if ($job_type) {
    $query .= " AND j.type = ?";
    $params[] = $job_type;
}
if ($skills) {
    $query .= " AND j.skills LIKE ?";
    $params[] = "%$skills%";
}
if ($experience) {
    $query .= " AND j.experience = ?";
    $params[] = $experience;
}

// Sorting
if ($recommended) {
    $query .= " ORDER BY relevance_score DESC, ";
} else {
    $query .= " ORDER BY ";
}

if ($sort === 'recent') {
    $query .= "j.posted_date DESC";
} elseif ($sort === 'salary') {
    $query .= "j.salary DESC";
}

// Execute query
$stmt = $conn->prepare($query);
if ($params) {
    $types = str_repeat('s', count($params));
    $stmt->bind_param($types, ...$params);
}
$stmt->execute();
$jobs = $stmt->get_result()->fetch_all(MYSQLI_ASSOC);
$stmt->close();

// Output job cards
if (empty($jobs)) {
    echo '<p class="text-gray-600 col-span-full text-center">No jobs found. Try adjusting your filters or check back later!</p>';
} else {
    foreach ($jobs as $job) {
        echo '<div class="border rounded-lg p-4 bg-white shadow-sm hover:shadow-lg transition transform hover:-translate-y-1">';
        if ($recommended && ($job['relevance_score'] >= 4)) {
            echo '<div class="absolute top-2 right-2 bg-green-100 text-green-800 text-xs px-2 py-1 rounded-full">Recommended</div>';
        }
        echo '<h3 class="text-lg font-semibold text-gray-800">' . htmlspecialchars($job['title']) . '</h3>';
        echo '<p class="text-gray-600 text-sm">' . htmlspecialchars($job['company']) . '</p>';
        echo '<div class="text-gray-500 text-sm mt-2 space-y-1">';
        echo '<p><span class="font-medium">Location:</span> ' . htmlspecialchars($job['location']) . '</p>';
        echo '<p><span class="font-medium">Type:</span> ' . htmlspecialchars(ucfirst($job['type'])) . '</p>';
        echo '<p><span class="font-medium">Salary:</span> ' . ($job['salary'] ? '₹' . number_format($job['salary']) : 'Not disclosed') . '</p>';
        echo '<p><span class="font-medium">Skills:</span> ' . htmlspecialchars($job['skills']) . '</p>';
        echo '<p><span class="font-medium">Education:</span> ' . htmlspecialchars($job['education']) . '</p>';
        echo '<p><span class="font-medium">Experience:</span> ' . htmlspecialchars($job['experience']) . '</p>';
        echo '</div>';
        echo '<p class="text-gray-400 text-xs mt-2">Posted: ' . date('M d, Y', strtotime($job['posted_date'])) . '</p>';
        echo '<p class="text-gray-600 text-sm mt-2 line-clamp-2">' . htmlspecialchars($job['description']) . '</p>';
        echo '<a href="job-details.php?id=' . $job['id'] . '" class="mt-3 inline-block text-blue-600 hover:underline font-medium">View Details</a>';
        echo '</div>';
    }
}
?>
