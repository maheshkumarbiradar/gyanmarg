<?php
require_once "../config/db.php";
protect();

$username = $_SESSION['username'] ?? '';

$stmt = $conn->prepare("SELECT username, profile_pic FROM users WHERE username = ?");
$stmt->bind_param("s", $username);
$stmt->execute();
$user = $stmt->get_result()->fetch_assoc();
$stmt->close();

$menus = [
  [
    'label' => 'Home',
    'url' => 'dashboard.php',
    'icon' => '<svg class="w-5 h-5 mr-3 group-hover:scale-110 group-hover:-rotate-12 hover:duration-300 duration-200" fill="none" stroke="currentColor" stroke-width="1.8" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M3 12l2-2 7-7 7 7 2 2M5 10v10a1 1 0 001 1h3m10-11v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1"/></svg>',
  ],
  [
    'label' => 'Explore Jobs',
    'url' => 'explore.php',
    'icon' => '<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" class="w-5 h-5 mr-3 group-hover:scale-110 group-hover:-rotate-12 hover:duration-300 duration-200">
  <path stroke-linecap="round" stroke-linejoin="round" d="M20.25 14.15v4.25c0 1.094-.787 2.036-1.872 2.18-2.087.277-4.216.42-6.378.42s-4.291-.143-6.378-.42c-1.085-.144-1.872-1.086-1.872-2.18v-4.25m16.5 0a2.18 2.18 0 0 0 .75-1.661V8.706c0-1.081-.768-2.015-1.837-2.175a48.114 48.114 0 0 0-3.413-.387m4.5 8.006c-.194.165-.42.295-.673.38A23.978 23.978 0 0 1 12 15.75c-2.648 0-5.195-.429-7.577-1.22a2.016 2.016 0 0 1-.673-.38m0 0A2.18 2.18 0 0 1 3 12.489V8.706c0-1.081.768-2.015 1.837-2.175a48.111 48.111 0 0 1 3.413-.387m7.5 0V5.25A2.25 2.25 0 0 0 13.5 3h-3a2.25 2.25 0 0 0-2.25 2.25v.894m7.5 0a48.667 48.667 0 0 0-7.5 0M12 12.75h.008v.008H12v-.008Z" />
</svg>
',
  ],
  [
    'label' => 'Learning Center',
    'url' => 'learn.php',
    'icon' => '<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" class="w-5 h-5 mr-3 group-hover:scale-110 group-hover:-rotate-12 hover:duration-300 duration-200">
  <path stroke-linecap="round" stroke-linejoin="round" d="M4.26 10.147a60.438 60.438 0 0 0-.491 6.347A48.62 48.62 0 0 1 12 20.904a48.62 48.62 0 0 1 8.232-4.41 60.46 60.46 0 0 0-.491-6.347m-15.482 0a50.636 50.636 0 0 0-2.658-.813A59.906 59.906 0 0 1 12 3.493a59.903 59.903 0 0 1 10.399 5.84c-.896.248-1.783.52-2.658.814m-15.482 0A50.717 50.717 0 0 1 12 13.489a50.702 50.702 0 0 1 7.74-3.342M6.75 15a.75.75 0 1 0 0-1.5.75.75 0 0 0 0 1.5Zm0 0v-3.675A55.378 55.378 0 0 1 12 8.443m-7.007 11.55A5.981 5.981 0 0 0 6.75 15.75v-1.5" />
</svg>
',
  ],
  [
    'label' => 'Talk to AI',
    'url' => 'vca.html',
    'icon' => '<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor"  class="w-5 h-5 mr-3 group-hover:scale-110 group-hover:-rotate-12 hover:duration-300 duration-200">
  <path stroke-linecap="round" stroke-linejoin="round" d="M8.625 12a.375.375 0 1 1-.75 0 .375.375 0 0 1 .75 0Zm0 0H8.25m4.125 0a.375.375 0 1 1-.75 0 .375.375 0 0 1 .75 0Zm0 0H12m4.125 0a.375.375 0 1 1-.75 0 .375.375 0 0 1 .75 0Zm0 0h-.375M21 12c0 4.556-4.03 8.25-9 8.25a9.764 9.764 0 0 1-2.555-.337A5.972 5.972 0 0 1 5.41 20.97a5.969 5.969 0 0 1-.474-.065 4.48 4.48 0 0 0 .978-2.025c.09-.457-.133-.901-.467-1.226C3.93 16.178 3 14.189 3 12c0-4.556 4.03-8.25 9-8.25s9 3.694 9 8.25Z" />
</svg>
',
  ],
  [
    'label' => 'Chat With AI',
    'url' => 'https://9000-firebase-studio-1747335856452.cluster-73qgvk7hjjadkrjeyexca5ivva.cloudworkstations.dev',
    'icon' => '<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor"  class="w-5 h-5 mr-3 group-hover:scale-110 group-hover:-rotate-12 hover:duration-300 duration-200">
  <path stroke-linecap="round" stroke-linejoin="round" d="M8.625 12a.375.375 0 1 1-.75 0 .375.375 0 0 1 .75 0Zm0 0H8.25m4.125 0a.375.375 0 1 1-.75 0 .375.375 0 0 1 .75 0Zm0 0H12m4.125 0a.375.375 0 1 1-.75 0 .375.375 0 0 1 .75 0Zm0 0h-.375M21 12c0 4.556-4.03 8.25-9 8.25a9.764 9.764 0 0 1-2.555-.337A5.972 5.972 0 0 1 5.41 20.97a5.969 5.969 0 0 1-.474-.065 4.48 4.48 0 0 0 .978-2.025c.09-.457-.133-.901-.467-1.226C3.93 16.178 3 14.189 3 12c0-4.556 4.03-8.25 9-8.25s9 3.694 9 8.25Z" />
</svg>
',
  ],
  [
    'label' => 'Settings',
    'url' => 'settings.php',
    'icon' => '<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor"  class="w-5 h-5 mr-3 group-hover:scale-110 group-hover:-rotate-90 hover:duration-300 duration-200">
  <path stroke-linecap="round" stroke-linejoin="round" d="M4.5 12a7.5 7.5 0 0 0 15 0m-15 0a7.5 7.5 0 1 1 15 0m-15 0H3m16.5 0H21m-1.5 0H12m-8.457 3.077 1.41-.513m14.095-5.13 1.41-.513M5.106 17.785l1.15-.964m11.49-9.642 1.149-.964M7.501 19.795l.75-1.3m7.5-12.99.75-1.3m-6.063 16.658.26-1.477m2.605-14.772.26-1.477m0 17.726-.26-1.477M10.698 4.614l-.26-1.477M16.5 19.794l-.75-1.299M7.5 4.205 12 12m6.894 5.785-1.149-.964M6.256 7.178l-1.15-.964m15.352 8.864-1.41-.513M4.954 9.435l-1.41-.514M12.002 12l-3.75 6.495" />
</svg>
',
  ],
];
$current_page = basename($_SERVER['PHP_SELF']);
?>
<aside
  class="w-full md:w-72 bg-white/40 backdrop-blur-xl text-gray-900 lg:flex flex-col md:p-6 md:min-h-screen md:sticky md:top-0 rounded-none transition-all duration-300 sidebar relative hidden">
  <div
    class="flex items-center justify-between md:flex-col md:items-start p-4 gap-2 md:gap-4 md:mb-8 bg-white/50 backdrop-blur-md">
    <div class="flex flex-col md:mt-2 lg:mt-4 md:order-2 order-1 z-10">
      <div class="text-sm font-medium tracking-tight text-zinc-950">namaste,</div>
      <div class="text-4xl font-medium text-gray-900 tracking-tight leading-8">
        <?php echo htmlspecialchars($user['username']); ?>
      </div>
    </div>
    <div class="group relative md:order-1 order-2 z-10">
      <img
        src="<?php echo $user['profile_pic'] ? 'data:image/jpeg;base64,' . base64_encode($user['profile_pic']) : 'https://via.placeholder.com/64'; ?>"
        alt="User profile picture" title="<?php echo htmlspecialchars($user['name'] ?? ''); ?>"
        class="aspect-square w-14 h-14 md:w-16 md:h-16 lg:w-48 lg:h-48 rounded-full object-cover object-center transition duration-300 hover:opacity-90 hover:scale-105 border border-zinc-300 shadow-sm hidden md:block" />
    </div>
  </div>

  <!-- Navigation -->
  <nav class="lg:flex flex-col gap-1 mt-4 hidden">
    <?php foreach ($menus as $menu): ?>
      <a href="<?php echo htmlspecialchars($menu['url']); ?>"
        class="group flex items-center px-4 py-2.5 rounded-full text-gray-800 hover:bg-zinc-200/40 transition-all duration-200 <?php echo $current_page === $menu['url'] ? 'bg-zinc-200/80 text-blue-600 font-medium' : ''; ?>">
        <?php echo $menu['icon']; ?>
        <span class="text-[15px]"><?php echo htmlspecialchars($menu['label']); ?></span>
      </a>
    <?php endforeach; ?>
    <!-- Sign Out -->
    <a href="logout.php"
      class="flex items-center px-4 py-2.5 rounded-xl text-gray-700 hover:bg-zinc-200 transition duration-150 group">
      <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor"
        class="w-5 h-5 mr-3 group-hover:scale-110 group-hover:-rotate-12 hover:duration-300 duration-200">
        <path stroke-linecap="round" stroke-linejoin="round"
          d="M16.5 10.5V6.75a4.5 4.5 0 1 0-9 0v3.75m-.75 11.25h10.5a2.25 2.25 0 0 0 2.25-2.25v-6.75a2.25 2.25 0 0 0-2.25-2.25H6.75a2.25 2.25 0 0 0-2.25 2.25v6.75a2.25 2.25 0 0 0 2.25 2.25Z" />
      </svg>
      <span class="text-[15px]">Sign Out</span>
    </a>
  </nav>
</aside>

<style>
  .sidebar {
    transition: opacity 0.3s ease-in-out, transform 0.3s ease-in-out;
  }

  @media (prefers-reduced-motion: reduce) {
    .sidebar {
      transition: none;
    }
  }

  @media (max-width: 767px) {
    .sidebar {
      background-image: url('<?php echo $user['profile_pic'] ? 'data:image/jpeg;base64,' . base64_encode($user['profile_pic']) : 'https://via.placeholder.com/64'; ?>');
      background-size: cover;
      background-position: center;
      background-repeat: no-repeat;
      background-color: rgba(255, 255, 255, 0.3);
      backdrop-filter: blur(8px);
    }
  }

  html {
    font-family: -apple-system, BlinkMacSystemFont, "San Francisco", "Helvetica Neue", Helvetica, Arial, sans-serif;
  }
</style>
