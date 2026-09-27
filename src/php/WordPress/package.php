<?php

declare(strict_types=1);

/**
 * Script d'empaquetage automatique du plugin WordPress.
 * Copie les classes du moteur PHP, les assets JS et génère un ZIP prêt à être installé.
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

echo "==> Début du packaging du plugin WordPress...\n";

// 1. Nettoyage du répertoire de build précédent
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

// 2. Copie des fichiers principaux du plugin WordPress
copy($wpDir . '/anonympins-bot-mitigation-pow.php', $buildDir . '/anonympins-bot-mitigation-pow.php');
copy($wpDir . '/WpDbStore.php', $buildDir . '/WpDbStore.php');
if (file_exists($wpDir . '/readme.txt')) {
    copy($wpDir . '/readme.txt', $buildDir . '/readme.txt');
}

// 2.b Compilation et copie des fichiers de langues (PO -> MO)
$languagesDir = $wpDir . '/languages';
if (is_dir($languagesDir)) {
    $poFiles = glob($languagesDir . '/*.po') ?: [];
    foreach ($poFiles as $poFile) {
        $filename = basename($poFile);
        copy($poFile, $buildDir . '/languages/' . $filename);

        $moFile = preg_replace('/\.po$/', '.mo', $poFile);
        // Compilation PO vers binaire MO si absent ou obsolète
        if (!file_exists($moFile) || filemtime($poFile) > filemtime($moFile)) {
            compilePoToMo($poFile, $moFile);
        }
        if (file_exists($moFile)) {
            copy($moFile, $buildDir . '/languages/' . basename($moFile));
        }
    }
}

/**
 * Compilateur minimal PO -> binaire gettext MO natif PHP
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

// 3. Copie des assets clients nécessaires (solveur PoW et bibliothèque client sans CDN externe)
$solverSource = $jsSrcDir . '/pow.solver.inline.js';
if (file_exists($solverSource)) {
    $solverContent = (string)file_get_contents($solverSource);
    // Neutralise les chargements distants CDN interdits par les règles WordPress.org
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

// 4. Copie récursive de la bibliothèque PHP (src/php -> build/src), en excluant les dossiers de dev
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

echo "==> Fichiers copiés dans {$buildDir}\n";

// 5. Création de l'archive ZIP
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
        // Préserve le préfixe du dossier racine dans le ZIP : fingerprint-anti-bot/...
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
echo "==> Archive ZIP générée avec succès :\n";
echo "    Fichier : {$zipFile} ({$sizeKb} Ko)\n";
echo "    Prêt à être installé via wp-admin ou déployé en production !\n";