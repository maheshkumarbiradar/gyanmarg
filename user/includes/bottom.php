<?php
require_once "../config/db.php";
$currentPage = basename($_SERVER['PHP_SELF']);

// Fetch active nav items
$stmt = $conn->prepare("SELECT title, url, icon_svg FROM nav_items WHERE is_active = 1 ORDER BY order_num");
$stmt->execute();
$nav_items = $stmt->get_result()->fetch_all(MYSQLI_ASSOC);
$stmt->close();
?>

<nav class="fixed bottom-0 left-0 w-full bg-white/80 backdrop-blur-md border-t border-zinc-200 shadow-[0_-1px_6px_rgba(0,0,0,0.05)] flex justify-evenly py-2.5 md:hidden z-50">
    <?php foreach ($nav_items as $item): ?>
        <a href="<?= htmlspecialchars($item['url']) ?>"
           class="flex flex-col items-center px-4 py-1.5 rounded-xl transition-all duration-200 ease-in-out <?= $currentPage === $item['url'] ? 'text-blue-600 bg-blue-50/60' : 'text-zinc-600 hover:bg-zinc-100/50' ?>">
            <?= $item['icon_svg'] ?>
            <span class="text-[11px] font-medium"><?= htmlspecialchars($item['title']) ?></span>
        </a>
    <?php endforeach; ?>
</nav>
