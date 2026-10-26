<?php
/**
 * php2shell-lab target app.
 *
 * Deliberately minimal: it exists only to route unauthenticated requests into the
 * two vulnerable core paths (multipart/rfc1867 parsing and request-global state),
 * NOT to add its own bugs. No user input is eval'd, unserialized, or written to
 * disk. The only "feature" is a controlled fatal-error endpoint used as the
 * CVE-2026-109619 producer.
 */

declare(strict_types=1);

header('Content-Type: text/plain; charset=utf-8');

$action = $_GET['action'] ?? 'info';

switch ($action) {
    case 'info':
        // Version + limits fingerprint for detect.py
        echo "php_version=" . PHP_VERSION . "\n";
        echo "sapi=" . php_sapi_name() . "\n";
        echo "memory_limit=" . ini_get('memory_limit') . "\n";
        echo "post_max_size=" . ini_get('post_max_size') . "\n";
        echo "upload_progress=" . ini_get('session.upload_progress.enabled') . "\n";
        echo "fatal_error_backtraces=" . (ini_get('fatal_error_backtraces') ?? 'n/a') . "\n";
        echo "worker_pid=" . getmypid() . "\n";
        break;

    case 'upload':
        // Session start makes session.upload_progress tracking active, which is
        // the state family used by the CVE-2026-109619 confirmed session path.
        session_start();

        if (empty($_FILES)) {
            echo "no_parts_parsed\n";
        } else {
            echo "parts=" . count($_FILES) . "\n";
            foreach (array_keys($_FILES) as $k) {
                echo "part=" . preg_replace('/[^A-Za-z0-9_\-]/', '', (string)$k) . "\n";
            }
        }
        echo "worker_pid=" . getmypid() . "\n";
        break;

    case 'fatal':
        // Producer for CVE-2026-109619: a fatal error with backtraces enabled
        // stores request-owned error state that (pre-patch) is not reset during
        // shutdown of the aborted request. The NEXT request served by the same
        // worker can consume the stale state before RINIT replaces it.
        session_start();
        // Undefined-function call = fatal error in PHP 8, with backtrace attached.
        trigger_exploit_fatal_error();
        break;

    default:
        http_response_code(404);
        echo "unknown action\n";
}
