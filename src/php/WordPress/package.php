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
$pluginSlug = 'fingerprint-wordpress';
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

/**
 * Compile un fichier .po gettext en binaire .mo compatible WordPress.
 */
function compilePoToMo(string $poFile, string $moFile): bool {
    if (!file_exists($poFile)) return false;
    $content = file_get_contents($poFile);
    if ($content === false) return false;

    $entries = [];
    $currentMsgId = null;
    $currentMsgStr = null;
    $lines = explode("\n", str_replace(["\r\n", "\r"], "\n", $content));
    $state = '';

    foreach ($lines as $line) {
        $line = trim($line);
        if ($line === '' || str_starts_with($line, '#')) continue;
        if (preg_match('/^msgid\s+"(.*)"$/', $line, $m)) {
            if ($currentMsgId !== null && $currentMsgStr !== null) {
                $entries[$currentMsgId] = $currentMsgStr;
            }
            $currentMsgId = stripcslashes($m[1]);
            $currentMsgStr = null;
            $state = 'msgid';
        } elseif (preg_match('/^msgstr\s+"(.*)"$/', $line, $m)) {
            $currentMsgStr = stripcslashes($m[1]);
            $state = 'msgstr';
        } elseif (preg_match('/^"(.*)"$/', $line, $m)) {
            if ($state === 'msgid') {
                $currentMsgId .= stripcslashes($m[1]);
            } elseif ($state === 'msgstr') {
                $currentMsgStr .= stripcslashes($m[1]);
            }
        }
    }
    if ($currentMsgId !== null && $currentMsgStr !== null) {
        $entries[$currentMsgId] = $currentMsgStr;
    }

    ksort($entries);
    $count = count($entries);
    $originals = '';
    $translations = '';
    $origTable = [];
    $transTable = [];

    $headerSize = 28;
    $tablesSize = $count * 8 * 2;
    $curOffset = $headerSize + $tablesSize;

    foreach ($entries as $orig => $trans) {
        $origLen = strlen($orig);
        $origTable[] = ['len' => $origLen, 'off' => $curOffset + strlen($originals)];
        $originals .= $orig . "\0";
    }

    $transOffset = $curOffset + strlen($originals);
    foreach ($entries as $orig => $trans) {
        $transLen = strlen($trans);
        $transTable[] = ['len' => $transLen, 'off' => $transOffset + strlen($translations)];
        $translations .= $trans . "\0";
    }

    $mo = pack('V*',
        0x950412de, // Magic Number
        0,          // Revision
        $count,     // Number of strings
        28,         // Offset of table with original string lengths and offsets
        28 + ($count * 8), // Offset of table with translation string lengths and offsets
        0, 0        // Hash table size and offset
    );

    foreach ($origTable as $t) {
        $mo .= pack('VV', $t['len'], $t['off']);
    }
    foreach ($transTable as $t) {
        $mo .= pack('VV', $t['len'], $t['off']);
    }
    $mo .= $originals . $translations;
    return file_put_contents($moFile, $mo) !== false;
}

// 2. Copie des fichiers principaux du plugin WordPress
copy($wpDir . '/fingerprint-wordpress.php', $buildDir . '/fingerprint-wordpress.php');
copy($wpDir . '/WpDbStore.php', $buildDir . '/WpDbStore.php');

// 3. Copie des assets clients nécessaires (solveur PoW)
$solverSource = $jsSrcDir . '/pow.solver.inline.js';
if (file_exists($solverSource)) {
    copy($solverSource, $buildDir . '/assets/pow.solver.inline.js');
}

// 4. Copie et compilation des fichiers de traduction i18n (FR / DE / EN)
$langSourceDir = $wpDir . '/languages';
if (is_dir($langSourceDir)) {
    foreach (glob($langSourceDir . '/*.po') as $poFile) {
        $baseName = basename($poFile);
        copy($poFile, $buildDir . '/languages/' . $baseName);
        $moTarget = $buildDir . '/languages/' . preg_replace('/\.po$/', '.mo', $baseName);
        compilePoToMo($poFile, $moTarget);
        compilePoToMo($poFile, $langSourceDir . '/' . preg_replace('/\.po$/', '.mo', $baseName));
    }
}

// 5. Copie récursive de la bibliothèque PHP (src/php -> build/src), en excluant les dossiers de dev
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
        // Préserve le préfixe du dossier racine dans le ZIP : fingerprint-wordpress/...
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