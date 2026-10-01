<?php

declare(strict_types=1);

/**
 * Automated packaging script for the WordPress plugin.
 * Copies PHP engine classes, JS assets, and creates an installation-ready ZIP archive.
 *
 * Usage:
 *   php src/php/WordPress/package.php
 */

if (!extension_loaded('zip')) {
    fwrite(STDERR, "Erreur : L'extension PHP 'zip' est requise pour créer l'archive.\n");
    exit(1);
}

$rootDir = dirname(__DIR__, 3);
$phpSrcDir = $rootDir . '/src/php';
$jsSrcDir = $rootDir . '/src/js';
$wpDir = $phpSrcDir . '/WordPress';
$distDir = $rootDir . '/public';
$pluginSlug = 'anonympins-bot-mitigation-pow';
$buildDir = $distDir . '/' . $pluginSlug;
$zipFile = $distDir . '/' . $pluginSlug . '.zip';

echo "==> Packaging WordPress plugin...\n";

// 1. Clean previous build directory
if (is_dir($buildDir)) {
    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($buildDir, FilesystemIterator::SKIP_DOTS),
        RecursiveIteratorIterator::CHILD_FIRST
    );
    foreach ($iterator as $item) {
        $item->isDir() ? rmdir($item->getPathname()) : unlink($item->getPathname());
    }
    rmdir($buildDir);
}
if (file_exists($zipFile)) {
    unlink($zipFile);
}

@mkdir($buildDir . '/src', 0777, true);
@mkdir($buildDir . '/assets', 0777, true);
@mkdir($buildDir . '/languages', 0777, true);
@mkdir($buildDir . '/config', 0777, true);

// 2. Copy main WordPress plugin files
copy($wpDir . '/anonympins-bot-mitigation-pow.php', $buildDir . '/anonympins-bot-mitigation-pow.php');
copy($wpDir . '/WpDbStore.php', $buildDir . '/WpDbStore.php');
if (file_exists($wpDir . '/readme.txt')) {
    copy($wpDir . '/readme.txt', $buildDir . '/readme.txt');
}

// 2.b Compile and copy language files (PO -> MO)
$languagesDir = $wpDir . '/languages';
if (is_dir($languagesDir)) {
    $poFiles = glob($languagesDir . '/*.po') ?: [];
    foreach ($poFiles as $poFile) {
        $filename = basename($poFile);
        copy($poFile, $buildDir . '/languages/' . $filename);

        $moFile = preg_replace('/\.po$/', '.mo', $poFile);
        // Compile PO to binary MO if missing or outdated
        if (!file_exists($moFile) || filemtime($poFile) > filemtime($moFile)) {
            compilePoToMo($poFile, $moFile);
        }
        if (file_exists($moFile)) {
            copy($moFile, $buildDir . '/languages/' . basename($moFile));
        }
    }
}

/**
 * Minimal native PHP PO -> binary gettext MO compiler
 */
function compilePoToMo(string $poPath, string $moPath): void {
    $content = (string)file_get_contents($poPath);
    $pattern = '/msgid\s+("(?:[^"\\\\]|\\\\.)*")\s+msgstr\s+("(?:[^"\\\\]|\\\\.)*")/s';
    if (!preg_match_all($pattern, $content, $matches, PREG_SET_ORDER)) {
        return;
    }
    $entries = [];
    foreach ($matches as $m) {
        $orig = stripcslashes(substr($m[1], 1, -1));
        $trans = stripcslashes(substr($m[2], 1, -1));
        if ($orig !== '' && $trans !== '') {
            $entries[$orig] = $trans;
        }
    }
    ksort($entries);
    $count = count($entries);
    $originalsTable = '';
    $translationsTable = '';
    $origOffsets = [];
    $transOffsets = [];
    $headerLength = 28 + ($count * 8) * 2;
    $currentOffset = $headerLength;
    foreach ($entries as $orig => $trans) {
        $origOffsets[] = ['len' => strlen($orig), 'off' => $currentOffset];
        $currentOffset += strlen($orig) + 1;
    }
    foreach ($entries as $orig => $trans) {
        $transOffsets[] = ['len' => strlen($trans), 'off' => $currentOffset];
        $currentOffset += strlen($trans) + 1;
    }
    $binary = pack('V7', 0x950412de, 0, $count, 28, 28 + ($count * 8), 0, 0);
    foreach ($origOffsets as $o) { $binary .= pack('V2', $o['len'], $o['off']); }
    foreach ($transOffsets as $t) { $binary .= pack('V2', $t['len'], $t['off']); }
    foreach ($entries as $orig => $trans) { $binary .= $orig . "\0"; }
    foreach ($entries as $orig => $trans) { $binary .= $trans . "\0"; }
    file_put_contents($moPath, $binary);
}

// 3. Copy required client assets (PoW solver and client bundle without external CDN)
$solverSource = $jsSrcDir . '/pow.solver.inline.js';
if (file_exists($solverSource)) {
    $solverContent = (string)file_get_contents($solverSource);
    // Neutralize remote CDN scripts prohibited by WordPress.org guidelines
    $solverContent = str_replace(
        ["'https://cdn.jsdelivr.net/npm/onnxruntime-web/dist/ort.min.js'", "'https://cdn.jsdelivr.net/npm/@tensorflow/tfjs/dist/tf.min.js'"],
        ["''", "''"],
        $solverContent
    );
    file_put_contents($buildDir . '/assets/pow.solver.inline.js', $solverContent);
}
$clientSource = file_exists($jsSrcDir . '/fingerprint.client.obfuscated.js')
    ? $jsSrcDir . '/fingerprint.client.obfuscated.js'
    : $jsSrcDir . '/fingerprint.client.js';
if (file_exists($clientSource)) {
    copy($clientSource, $buildDir . '/assets/fingerprint.client.js');
}

// 3.b Copy problem/bot configuration assets
$configSourceDir = $rootDir . '/config';
if (is_dir($configSourceDir)) {
    $configFiles = glob($configSourceDir . '/*.json') ?: [];
    foreach ($configFiles as $cfgFile) {
        copy($cfgFile, $buildDir . '/config/' . basename($cfgFile));
    }
}

// 4. Recursively copy PHP library (src/php -> build/src), excluding dev folders
$excludeDirs = ['WordPress', 'Tests', 'bin'];
$phpIterator = new RecursiveIteratorIterator(
    new RecursiveDirectoryIterator($phpSrcDir, FilesystemIterator::SKIP_DOTS),
    RecursiveIteratorIterator::SELF_FIRST
);

foreach ($phpIterator as $item) {
    $relativePath = substr($item->getPathname(), strlen($phpSrcDir) + 1);
    $topDir = explode(DIRECTORY_SEPARATOR, str_replace('/', DIRECTORY_SEPARATOR, $relativePath))[0];

    if (in_array($topDir, $excludeDirs, true)) {
        continue;
    }

    $destPath = $buildDir . '/src/' . $relativePath;
    if ($item->isDir()) {
        if (!is_dir($destPath)) {
            mkdir($destPath, 0777, true);
        }
    } else {
        copy($item->getPathname(), $destPath);
    }
}

echo "==> Files copied to {$buildDir}\n";

// 5. Create ZIP archive
$zip = new ZipArchive();
if ($zip->open($zipFile, ZipArchive::CREATE | ZipArchive::OVERWRITE) !== true) {
    fwrite(STDERR, "Erreur : Impossible de créer le fichier {$zipFile}\n");
    exit(1);
}

$distIterator = new RecursiveIteratorIterator(
    new RecursiveDirectoryIterator($buildDir, FilesystemIterator::SKIP_DOTS),
    RecursiveIteratorIterator::LEAVES_ONLY
);

foreach ($distIterator as $file) {
    if (!$file->isDir()) {
        $filePath = $file->getPathname();
        // Preserve plugin root directory prefix in archive: anonympins-bot-mitigation-pow/...
        $relativePath = $pluginSlug . '/' . substr($filePath, strlen($buildDir) + 1);
        $zip->addFile($filePath, str_replace('\\', '/', $relativePath));
    }
}
function removeDirectory(string $dir): void
{
    if (!is_dir($dir)) {
        return;
    }
    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS),
        RecursiveIteratorIterator::CHILD_FIRST
    );
    foreach ($iterator as $item) {
        $item->isDir() ? rmdir($item->getPathname()) : unlink($item->getPathname());
    }
    rmdir($dir);
}
$zip->close();
removeDirectory($buildDir);
$sizeKb = round(filesize($zipFile) / 1024, 2);
echo "==> ZIP archive generated successfully:\n";
echo "    File: {$zipFile} ({$sizeKb} KB)\n";
echo "    Ready to be installed via wp-admin or deployed to production.\n";