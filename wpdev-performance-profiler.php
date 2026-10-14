<?php
/**
 * Plugin Name: WPDev Performance & Bottleneck Profiler (MU)
 * Description: Comprehensive, fail-open, zero-DB performance & bottleneck profiler for WordPress. Logs slow requests, lifecycle phase breakdowns, slow hooks & plugin/theme callbacks, slow & N+1 database queries, autoloaded options bloat, external HTTP API calls (including hung/timed-out requests), Object Cache/OPcache efficiency, and CPU/RAM/I/O metrics to rotated JSONL files.
 * Version:     2.0.0
 * Author:      WPDev Team
 * Requires PHP: 7.4
 *
 * Installation:
 * Copy this file to `wp-content/mu-plugins/wpdev-performance-profiler.php`.
 * All settings work out-of-the-box with sensible defaults and can be overridden in `wp-config.php`.
 *
 * @package WPDev\Performance
 */

declare(strict_types=1);

namespace WPDev\Performance;

defined('ABSPATH') || exit;

/*
 * =============================================================================
 * Configuration Constants (Override any of these in wp-config.php)
 * =============================================================================
 */

// Master enable/disable switch.
defined('WPDEV_PERF_ENABLED')                || define('WPDEV_PERF_ENABLED', true);

// Environment name ('production', 'staging', 'development', 'local'). Auto-detects WP_ENVIRONMENT_TYPE.
defined('WPDEV_PERF_ENVIRONMENT')            || define('WPDEV_PERF_ENVIRONMENT', defined('WP_ENVIRONMENT_TYPE') ? (string) WP_ENVIRONMENT_TYPE : 'production');

// Automatically define SAVEQUERIES if not already defined (defaults to true in local/development; false in staging/production unless trace header is sent).
defined('WPDEV_PERF_AUTO_SAVEQUERIES')       || define('WPDEV_PERF_AUTO_SAVEQUERIES', null);

// Sampling rate for normal/healthy requests (0.0 to 1.0; e.g., 0.05 = 5%). Slow or error requests ALWAYS log (100%).
defined('WPDEV_PERF_SAMPLE_RATE')            || define('WPDEV_PERF_SAMPLE_RATE', 0.05);

// Skip logging healthy admin-ajax heartbeat requests unless they trigger a slow/error threshold.
defined('WPDEV_PERF_SKIP_HEARTBEAT')         || define('WPDEV_PERF_SKIP_HEARTBEAT', true);

// Thresholds (in milliseconds / ratio / KB).
defined('WPDEV_PERF_SLOW_REQUEST_MS')        || define('WPDEV_PERF_SLOW_REQUEST_MS', 500.0);
defined('WPDEV_PERF_SLOW_QUERY_MS')          || define('WPDEV_PERF_SLOW_QUERY_MS', 50.0);
defined('WPDEV_PERF_SLOW_HTTP_MS')           || define('WPDEV_PERF_SLOW_HTTP_MS', 1000.0);
defined('WPDEV_PERF_SLOW_PHASE_MS')          || define('WPDEV_PERF_SLOW_PHASE_MS', 100.0);
defined('WPDEV_PERF_SLOW_HOOK_MS')           || define('WPDEV_PERF_SLOW_HOOK_MS', 10.0);
defined('WPDEV_PERF_MEMORY_WATERMARK_RATIO') || define('WPDEV_PERF_MEMORY_WATERMARK_RATIO', 0.80);
defined('WPDEV_PERF_N_PLUS_ONE_THRESHOLD')   || define('WPDEV_PERF_N_PLUS_ONE_THRESHOLD', 3);
defined('WPDEV_PERF_AUTOLOAD_WARN_KB')       || define('WPDEV_PERF_AUTOLOAD_WARN_KB', 800.0);

// Deep Hook & Interval Profiling via WordPress 'all' hook (true = always, false = only on manual trace requests).
defined('WPDEV_PERF_PROFILE_HOOKS')          || define('WPDEV_PERF_PROFILE_HOOKS', true);

// Include normalized SQL templates (literals replaced with '?') in logs for slow and N+1 queries.
defined('WPDEV_PERF_CAPTURE_SQL')            || define('WPDEV_PERF_CAPTURE_SQL', true);

// Per-record collection caps to bound memory and JSON line size.
defined('WPDEV_PERF_MAX_SLOW_QUERIES')       || define('WPDEV_PERF_MAX_SLOW_QUERIES', 20);
defined('WPDEV_PERF_MAX_DUPLICATE_QUERIES')  || define('WPDEV_PERF_MAX_DUPLICATE_QUERIES', 15);
defined('WPDEV_PERF_MAX_HTTP_CALLS')         || define('WPDEV_PERF_MAX_HTTP_CALLS', 15);
defined('WPDEV_PERF_MAX_SLOW_HOOKS')         || define('WPDEV_PERF_MAX_SLOW_HOOKS', 20);
defined('WPDEV_PERF_MAX_RECORD_BYTES')       || define('WPDEV_PERF_MAX_RECORD_BYTES', 98304); // 96 KB

// File storage, rotation, and retention settings (if empty, automatically uses an unguessable salted directory in wp-content).
defined('WPDEV_PERF_LOG_DIR')                || define('WPDEV_PERF_LOG_DIR', '');
defined('WPDEV_PERF_MAX_FILE_BYTES')         || define('WPDEV_PERF_MAX_FILE_BYTES', 52428800);   // 50 MB per file segment
defined('WPDEV_PERF_MAX_TOTAL_BYTES')        || define('WPDEV_PERF_MAX_TOTAL_BYTES', 524288000); // 500 MB total directory cap
defined('WPDEV_PERF_RETENTION_DAYS')         || define('WPDEV_PERF_RETENTION_DAYS', 7);
defined('WPDEV_PERF_MIN_FREE_BYTES')         || define('WPDEV_PERF_MIN_FREE_BYTES', 10485760);  // 10 MB minimum free disk space

// Optional manual developer trace header & secret.
defined('WPDEV_PERF_TRACE_HEADER')           || define('WPDEV_PERF_TRACE_HEADER', 'HTTP_X_WPDEV_TRACE');
defined('WPDEV_PERF_TRACE_SECRET')           || define('WPDEV_PERF_TRACE_SECRET', '');
defined('WPDEV_PERF_TRACE_IP_ALLOWLIST')     || define('WPDEV_PERF_TRACE_IP_ALLOWLIST', array());

// Optional custom key for HMAC query fingerprinting (automatically falls back to WP salts/ABSPATH hash).
defined('WPDEV_PERF_FINGERPRINT_KEY')        || define('WPDEV_PERF_FINGERPRINT_KEY', '');

// Host / Worker identifier.
defined('WPDEV_PERF_HOST_ID')                || define('WPDEV_PERF_HOST_ID', (function_exists('php_uname') && @php_uname('n')) ? (string) @php_uname('n') : 'wpdev-worker');

/**
 * Normalizes SQL queries into safe, literal-free templates and generates stable fingerprints.
 */
final class SqlNormalizer
{
    /**
     * Strip SQL comments and replace string/numeric/hex literals with '?' placeholders.
     */
    public static function normalize(string $sql): string
    {
        $sql = trim($sql);
        if ('' === $sql) {
            return '';
        }

        // Strip multi-line /* ... */ comments (except MySQL version comments /*! ... */).
        $sql = preg_replace('/\/\*(?!\!).*?\*\//s', ' ', $sql) ?? $sql;

        // Hexadecimal and bit literals (0x123abc, 0b101, X'1F').
        $sql = preg_replace('/\b0x[0-9a-fA-F]+\b/', '?', $sql) ?? $sql;
        $sql = preg_replace('/\b0b[01]+\b/', '?', $sql) ?? $sql;
        $sql = preg_replace("/\b[xX]'[0-9a-fA-F]*'/", '?', $sql) ?? $sql;

        // Single-quoted and double-quoted string literals (handling escaped quotes).
        $sql = preg_replace("/'[^'\\\\]*(?:\\\\.[^'\\\\]*)*'/", '?', $sql) ?? $sql;
        $sql = preg_replace('/"[^"\\\\]*(?:\\\\.[^"\\\\]*)*"/', '?', $sql) ?? $sql;

        // Standalone numbers (integers, decimals, scientific notation, negative numbers).
        $sql = preg_replace('/(?<![a-zA-Z0-9_$])-?\b\d+(?:\.\d+)?(?:e[+-]?\d+)?\b/i', '?', $sql) ?? $sql;

        // Collapse variable-length IN (?, ?, ...) lists into IN (?).
        $sql = preg_replace('/\bIN\s*\(\s*\?(?:\s*,\s*\?)*\s*\)/i', 'IN (?)', $sql) ?? $sql;

        // Collapse multi-row VALUES (?, ?), (?, ?) lists into VALUES (?).
        $sql = preg_replace('/\bVALUES\s*\(\s*\?(?:\s*,\s*\?)*\s*\)(?:\s*,\s*\(\s*\?(?:\s*,\s*\?)*\s*\))+/i', 'VALUES (?)', $sql) ?? $sql;

        // Collapse whitespace.
        $sql = preg_replace('/\s+/', ' ', $sql) ?? $sql;

        return trim($sql);
    }

    /**
     * Extract primary SQL verb (SELECT, INSERT, UPDATE, DELETE, SHOW, etc.).
     */
    public static function extract_verb(string $sql): string
    {
        $clean = ltrim($sql, " \t\n\r\0\x0B(");
        $clean = preg_replace('/^(?:\/\*.*?\*\/\s*)+/s', '', $clean) ?? $clean;
        if (preg_match('/^([A-Za-z]+)/', $clean, $m)) {
            return strtoupper($m[1]);
        }

        return 'OTHER';
    }

    /**
     * Generate a short HMAC-SHA256 fingerprint for a normalized SQL string.
     */
    public static function fingerprint(string $normalized_sql, string $key): string
    {
        if ('' === $normalized_sql) {
            return '';
        }
        $effective_key = '' !== $key ? $key : self::default_key();

        return 'qfp_' . substr(hash_hmac('sha256', $normalized_sql, $effective_key), 0, 16);
    }

    /**
     * Fallback key so N+1 fingerprinting always works even without manual wp-config setup.
     */
    private static function default_key(): string
    {
        if (defined('AUTH_KEY') && '' !== (string) AUTH_KEY) {
            return (string) AUTH_KEY;
        }
        if (defined('SECURE_AUTH_KEY') && '' !== (string) SECURE_AUTH_KEY) {
            return (string) SECURE_AUTH_KEY;
        }

        return 'wpdev-fp-' . (defined('ABSPATH') ? ABSPATH : __DIR__);
    }
}

/**
 * Memory limit parsing and RAM usage metrics.
 */
final class MemoryHelper
{
    public static function parse_limit_to_bytes(string $raw): int
    {
        $raw = strtolower(trim($raw));
        if ('-1' === $raw) {
            return -1; // Explicitly unlimited memory
        }
        if ('' === $raw) {
            return 0;
        }

        if (!preg_match('/^(\d+)\s*([kmgt])?(?:b|ib)?$/i', $raw, $m)) {
            return 0;
        }

        $value = (int) $m[1];
        switch (strtolower($m[2] ?? '')) {
            case 't':
                return $value * 1024 * 1024 * 1024 * 1024;
            case 'g':
                return $value * 1024 * 1024 * 1024;
            case 'm':
                return $value * 1024 * 1024;
            case 'k':
                return $value * 1024;
            default:
                return $value;
        }
    }

    /**
     * @param float|int $current_bytes
     * @param float|int $peak_real_bytes
     * @param float|int $peak_emalloc_bytes
     * @param float|int $limit_bytes
     * @return array<string, mixed>
     */
    public static function build_metrics($current_bytes, $peak_real_bytes, $peak_emalloc_bytes, $limit_bytes): array
    {
        $mb = static function ($bytes): float {
            return round((float) $bytes / 1048576.0, 2);
        };

        $is_unlimited = (-1 === (int) $limit_bytes);
        $wp_limit_bytes = defined('WP_MEMORY_LIMIT') ? self::parse_limit_to_bytes((string) WP_MEMORY_LIMIT) : 0;

        $effective_limit = 0.0;
        if ($is_unlimited) {
            $effective_limit = -1.0;
        } elseif ((float) $limit_bytes > 0.0) {
            $effective_limit = (float) $limit_bytes;
        } elseif ($wp_limit_bytes > 0) {
            $effective_limit = (float) $wp_limit_bytes;
        }

        $metrics = array(
            'current_mb'      => $mb($current_bytes),
            'peak_real_mb'    => $mb($peak_real_bytes),
            'peak_emalloc_mb' => $mb($peak_emalloc_bytes),
            'php_limit_mb'    => $is_unlimited ? -1.0 : ((float) $limit_bytes > 0.0 ? $mb($limit_bytes) : null),
            'wp_limit_mb'     => $wp_limit_bytes > 0 ? $mb($wp_limit_bytes) : null,
            'headroom_mb'     => null,
            'usage_ratio'     => null,
        );

        if ($effective_limit > 0.0) {
            $peak = max((float) $peak_real_bytes, (float) $peak_emalloc_bytes);
            $metrics['headroom_mb'] = round(max(0.0, $effective_limit - $peak) / 1048576.0, 2);
            $metrics['usage_ratio'] = round($peak / $effective_limit, 3);
        }

        return $metrics;
    }
}

/**
 * CPU user/system usage delta tracker via getrusage().
 */
final class CpuHelper
{
    /** @return array{utime: float, stime: float}|null */
    public static function snapshot(): ?array
    {
        if (!function_exists('getrusage')) {
            return null;
        }

        $usage = @getrusage();
        if (!is_array($usage)) {
            return null;
        }

        return array(
            'utime' => self::ru_value($usage, 'ru_utime', 'tv_sec') + (self::ru_value($usage, 'ru_utime', 'tv_usec') / 1000000.0),
            'stime' => self::ru_value($usage, 'ru_stime', 'tv_sec') + (self::ru_value($usage, 'ru_stime', 'tv_usec') / 1000000.0),
        );
    }

    private static function ru_value(array $usage, string $field, string $part): int
    {
        if (isset($usage[$field][$part]) && is_numeric($usage[$field][$part])) {
            return (int) $usage[$field][$part];
        }
        if (isset($usage[$field . '.' . $part]) && is_numeric($usage[$field . '.' . $part])) {
            return (int) $usage[$field . '.' . $part];
        }

        return 0;
    }

    /**
     * @param array{utime: float, stime: float}|null $start
     * @param array{utime: float, stime: float}|null $end
     * @return array{cpu_user_ms: float, cpu_system_ms: float, cpu_total_ms: float}|null
     */
    public static function delta_ms(?array $start, ?array $end): ?array
    {
        if (null === $start || null === $end) {
            return null;
        }

        $user_ms = round(max(0.0, ($end['utime'] - $start['utime'])) * 1000.0, 2);
        $sys_ms  = round(max(0.0, ($end['stime'] - $start['stime'])) * 1000.0, 2);

        return array(
            'cpu_user_ms'   => $user_ms,
            'cpu_system_ms' => $sys_ms,
            'cpu_total_ms'  => round($user_ms + $sys_ms, 2),
        );
    }
}

/**
 * Identifies the responsible plugin, MU-plugin, theme, or core component from file paths or call stacks.
 */
final class ComponentResolver
{
    /** @var array<string, array<int, string>> Cached hook callback sources */
    private static array $hook_callback_cache = array();

    /**
     * Extract component slug (e.g. "plugin:woocommerce", "theme:astra", "mu-plugin:...", "core") from a file path.
     */
    public static function from_path(string $file): string
    {
        if ('' === $file) {
            return 'unknown';
        }
        $normalized = str_replace('\\', '/', $file);

        // Dynamic detection using WP directory constants if defined.
        if (defined('WP_PLUGIN_DIR')) {
            $p_dir = str_replace('\\', '/', (string) WP_PLUGIN_DIR);
            if ('' !== $p_dir && 0 === strpos($normalized, $p_dir . '/')) {
                $rel = substr($normalized, strlen($p_dir) + 1);
                $parts = explode('/', $rel, 2);
                return 'plugin:' . strtolower($parts[0]);
            }
        }
        if (defined('WPMU_PLUGIN_DIR')) {
            $mu_dir = str_replace('\\', '/', (string) WPMU_PLUGIN_DIR);
            if ('' !== $mu_dir && 0 === strpos($normalized, $mu_dir . '/')) {
                $rel = substr($normalized, strlen($mu_dir) + 1);
                $parts = explode('/', $rel, 2);
                return 'mu-plugin:' . strtolower($parts[0]);
            }
        }

        // Standard wp-content and Bedrock/Roots app directory structure regex.
        if (preg_match('#/(?:wp-content|app)/plugins/([^/]+)#i', $normalized, $m)) {
            return 'plugin:' . strtolower($m[1]);
        }
        if (preg_match('#/(?:wp-content|app)/mu-plugins/([^/]+)#i', $normalized, $m)) {
            return 'mu-plugin:' . strtolower($m[1]);
        }
        if (preg_match('#/(?:wp-content|app)/themes/([^/]+)#i', $normalized, $m)) {
            return 'theme:' . strtolower($m[1]);
        }
        if (false !== strpos($normalized, '/wp-includes/') || false !== strpos($normalized, '/wp-admin/')) {
            return 'core';
        }

        return 'other:' . basename($normalized);
    }

    /**
     * Infer component from a $wpdb caller stack or debug_backtrace frames.
     */
    public static function from_caller_string(string $caller): string
    {
        if (preg_match('#wp-content/plugins/([a-zA-Z0-9._-]+)#i', $caller, $m)) {
            return 'plugin:' . strtolower($m[1]);
        }
        if (preg_match('#wp-content/themes/([a-zA-Z0-9._-]+)#i', $caller, $m)) {
            return 'theme:' . strtolower($m[1]);
        }
        if (preg_match('#wp-content/mu-plugins/([a-zA-Z0-9._-]+)#i', $caller, $m)) {
            return 'mu-plugin:' . strtolower($m[1]);
        }

        // Well-known namespace/class prefixes in caller stack when file paths aren't in $wpdb->queries[2].
        if (preg_match('/\b(WC_|Automattic\\\\WooCommerce|WooCommerce)/i', $caller)) {
            return 'plugin:woocommerce';
        }
        if (preg_match('/\b(Elementor\\\\|ElementorPro\\\\)/i', $caller)) {
            return 'plugin:elementor';
        }
        if (preg_match('/\b(WPSEO_|Yoast\\\\)/i', $caller)) {
            return 'plugin:wordpress-seo';
        }
        if (preg_match('/\b(RankMath\\\\)/i', $caller)) {
            return 'plugin:seo-by-rank-math';
        }
        if (preg_match('/\b(Rocket_|WP_Rocket\\\\)/i', $caller)) {
            return 'plugin:wp-rocket';
        }
        if (preg_match('/\b(WPCF7_|Flamingo_)/i', $caller)) {
            return 'plugin:contact-form-7';
        }
        if (preg_match('/\b(ACF|acf_)/', $caller)) {
            return 'plugin:advanced-custom-fields';
        }
        if (preg_match('/\b(LearnDash|LDLMS_)/i', $caller)) {
            return 'plugin:sfwd-lms';
        }
        if (preg_match('/\b(EDD_|Easy_Digital_Downloads)/i', $caller)) {
            return 'plugin:easy-digital-downloads';
        }
        if (preg_match('/\b(GFAPI|GFForms|RGFormsModel)/i', $caller)) {
            return 'plugin:gravityforms';
        }
        if (preg_match('/\b(WPML_|SitePress)/i', $caller)) {
            return 'plugin:sitepress-multilingual-cms';
        }
        if (preg_match('/\b(LiteSpeed\\\\)/i', $caller)) {
            return 'plugin:litespeed-cache';
        }
        if (preg_match('/\b(Wordfence|wfWAF|wfConfig)/i', $caller)) {
            return 'plugin:wordfence';
        }

        return 'core_or_theme';
    }

    /**
     * Inspect $wp_filter[$hook_name] using Reflection (only called at shutdown for top slow hooks)
     * to identify which plugins/themes have callbacks attached to a slow hook.
     *
     * @return array<int, string>
     */
    public static function resolve_hook_callbacks(string $hook_name, int $limit = 5): array
    {
        if (isset(self::$hook_callback_cache[$hook_name])) {
            return self::$hook_callback_cache[$hook_name];
        }

        global $wp_filter;
        if (!is_array($wp_filter) || !isset($wp_filter[$hook_name])) {
            return array();
        }

        $hook_obj = $wp_filter[$hook_name];
        $callbacks_by_priority = null;
        if (is_object($hook_obj) && isset($hook_obj->callbacks) && is_array($hook_obj->callbacks)) {
            $callbacks_by_priority = $hook_obj->callbacks;
        } elseif (is_array($hook_obj)) {
            $callbacks_by_priority = $hook_obj;
        }

        if (!is_array($callbacks_by_priority)) {
            return array();
        }

        $results = array();
        foreach ($callbacks_by_priority as $priority => $callbacks) {
            if (!is_array($callbacks)) {
                continue;
            }
            foreach ($callbacks as $cb_item) {
                if (count($results) >= $limit) {
                    break 2;
                }
                if (!is_array($cb_item) || !isset($cb_item['function'])) {
                    continue;
                }
                $fn = $cb_item['function'];
                $desc = self::describe_callable($fn, (int) $priority);
                if ('' !== $desc && false === strpos($desc, 'wpdev-performance-profiler')) {
                    $results[] = $desc;
                }
            }
        }

        self::$hook_callback_cache[$hook_name] = array_values(array_unique($results));

        return self::$hook_callback_cache[$hook_name];
    }

    /**
     * @param mixed $fn
     */
    private static function describe_callable($fn, int $priority): string
    {
        try {
            if (is_string($fn)) {
                if (false !== strpos($fn, '::')) {
                    list($class, $method) = explode('::', $fn, 2);
                    $ref = new \ReflectionMethod($class, $method);
                    $comp = self::from_path((string) $ref->getFileName());

                    return "{$comp} -> {$class}::{$method}@{$priority}";
                }
                if (function_exists($fn)) {
                    $ref = new \ReflectionFunction($fn);
                    $comp = self::from_path((string) $ref->getFileName());

                    return "{$comp} -> {$fn}@{$priority}";
                }

                return "{$fn}@{$priority}";
            }

            if (is_array($fn) && count($fn) === 2) {
                $obj_or_class = $fn[0];
                $method = (string) $fn[1];
                $class_name = is_object($obj_or_class) ? get_class($obj_or_class) : (string) $obj_or_class;
                if (class_exists($class_name) && method_exists($class_name, $method)) {
                    $ref = new \ReflectionMethod($class_name, $method);
                    $comp = self::from_path((string) $ref->getFileName());

                    return "{$comp} -> {$class_name}::{$method}@{$priority}";
                }

                return "{$class_name}::{$method}@{$priority}";
            }

            if ($fn instanceof \Closure) {
                $ref = new \ReflectionFunction($fn);
                $file = (string) $ref->getFileName();
                $line = (int) $ref->getStartLine();
                $comp = self::from_path($file);

                return "{$comp} -> Closure(" . basename($file) . ":{$line})@{$priority}";
            }

            if (is_object($fn) && method_exists($fn, '__invoke')) {
                $class_name = get_class($fn);
                $ref = new \ReflectionMethod($class_name, '__invoke');
                $comp = self::from_path((string) $ref->getFileName());

                return "{$comp} -> {$class_name}::__invoke@{$priority}";
            }
        } catch (\Throwable $e) {
            // Reflection may fail on internal/dynamic callables; fail open.
        }

        return '';
    }
}

/**
 * Main WPDev Performance & Bottleneck Profiler Engine.
 */
final class Profiler
{
    private const SCHEMA_VERSION = '2.0';
    private const LOGGER_VERSION = '2.0.0';

    private const MANDATORY_TRIGGERS = array(
        'slow_request',
        'slow_query',
        'n_plus_one_queries',
        'slow_http',
        'http_error',
        'http_unfinished',
        'slow_phase',
        'slow_hook',
        'memory_high',
        'autoload_bloat',
        'fatal',
        'error_5xx',
        'trace',
        'db_connection_error',
        'db_query_error',
    );

    /**
     * High-frequency WordPress hooks ignored during 'all' hook profiling so we never
     * incur CPU/RAM overhead on translation, escaping, or sanitization calls.
     *
     * @var array<string, bool>
     */
    private const NOISY_HOOKS = array(
        'gettext'                     => true,
        'gettext_with_context'        => true,
        'ngettext'                    => true,
        'ngettext_with_context'       => true,
        'override_load_textdomain'    => true,
        'load_textdomain'             => true,
        'load_textdomain_mofile'      => true,
        'esc_html'                    => true,
        'attribute_escape'            => true,
        'js_escape'                   => true,
        'clean_url'                   => true,
        'sanitize_key'                => true,
        'sanitize_title'              => true,
        'sanitize_text_field'         => true,
        'sanitize_html_class'         => true,
        'sanitize_user'              => true,
        'kses_allowed_protocols'      => true,
        'wp_kses_allowed_html'        => true,
        'map_meta_cap'                => true,
        'user_has_cap'                => true,
        'role_has_cap'                => true,
        'set_url_scheme'              => true,
        'home_url'                    => true,
        'site_url'                    => true,
        'plugins_url'                 => true,
        'content_url'                 => true,
        'includes_url'                => true,
        'script_loader_src'           => true,
        'style_loader_src'            => true,
        'filesystem_method'           => true,
        'all'                         => true,
        'shutdown'                    => true,
    );

    /** @var array<string, mixed> */
    private static array $config = array();

    private static string $environment = 'production';
    private static string $request_id = '';
    private static bool $is_trace = false;
    private static bool $shutdown_handled = false;

    private static float $boot_microtime = 0.0;
    private static float $boot_hrtime_ms = 0.0;
    private static float $bootstrap_ms = 0.0;

    /** @var array{utime: float, stime: float}|null */
    private static ?array $cpu_start = null;

    /**
     * Lifecycle milestones: milestone_name => array{ms: float, mem_bytes: int, queries: int}
     *
     * @var array<string, array{ms: float, mem_bytes: int, queries: int}>
     */
    private static array $milestones = array();

    /**
     * Rolling state for low-overhead 'all' hook interval profiling.
     */
    private static string $last_hook_name = '';
    private static float $last_hook_ms = 0.0;
    private static int $last_hook_mem = 0;
    private static int $last_hook_queries = 0;

    /**
     * Aggregated statistics per slow hook:
     * hook_name => array{calls: int, total_ms: float, max_ms: float, queries: int, mem_delta_kb: float}
     *
     * @var array<string, array{calls: int, total_ms: float, max_ms: float, queries: int, mem_delta_kb: float}>
     */
    private static array $hook_stats = array();

    /**
     * Top individual slow hook intervals (bounded to 30 entries in memory).
     *
     * @var array<int, array{start_hook: string, end_hook: string, ms: float, queries: int, mem_delta_kb: float}>
     */
    private static array $slow_intervals = array();

    /**
     * Active external HTTP calls stack (supports nested calls via LIFO matching).
     *
     * @var array<int, array{url: string, method: string, start_ms: float, caller: string}>
     */
    private static array $http_stack = array();

    /**
     * Completed HTTP calls (slow, error, or traced).
     *
     * @var array<int, array<string, mixed>>
     */
    private static array $http_calls = array();

    private static int $http_total_count = 0;
    private static int $http_slow_count = 0;
    private static int $http_error_count = 0;
    private static float $http_total_ms = 0.0;

    private static string $rest_route = '';
    private static int $response_status = 0;
    private static string $response_status_source = 'unknown';

    /** Cached log directory byte size (-1 = uninitialized). */
    private static int $log_dir_size = -1;

    /** Cache whether directory security guards (.htaccess, web.config, index.php) have been checked. */
    private static bool $guards_verified = false;

    /* ====================================================================== */
    /* Bootstrap & Initialization                                             */
    /* ====================================================================== */

    public static function bootstrap(): void
    {
        try {
            self::$boot_microtime = microtime(true);
            self::$boot_hrtime_ms = self::hrtime_ms();

            $request_time = isset($_SERVER['REQUEST_TIME_FLOAT']) ? (float) $_SERVER['REQUEST_TIME_FLOAT'] : 0.0;
            self::$config['bootstrap_base'] = $request_time > 0.0 ? $request_time : self::$boot_microtime;
            self::$bootstrap_ms = $request_time > 0.0
                ? round(max(0.0, (self::$boot_microtime - $request_time) * 1000.0), 2)
                : 0.0;

            self::resolve_config();
            if (!self::coerce_bool(self::$config['ENABLED'] ?? false)) {
                return;
            }

            self::$request_id = self::new_request_id();
            self::$is_trace   = self::is_trace_request();
            self::$cpu_start  = CpuHelper::snapshot();

            // Auto-enable SAVEQUERIES only if explicitly configured, running in local/development, or authorized trace.
            $auto_savequeries = self::$config['AUTO_SAVEQUERIES'] ?? null;
            if (null === $auto_savequeries) {
                $auto_savequeries = in_array(self::$environment, array('local', 'development'), true) || self::$is_trace;
            }
            if (self::coerce_bool($auto_savequeries) && !defined('SAVEQUERIES')) {
                define('SAVEQUERIES', true);
            }

            self::hook_milestones();
            self::hook_http();
            self::hook_rest();

            if (self::coerce_bool(self::$config['PROFILE_HOOKS'] ?? true) || self::$is_trace) {
                self::hook_interval_profiler();
            }

            if (function_exists('\add_action')) {
                \add_action('shutdown', array(self::class, 'handle_shutdown'), 9999);
            }
            register_shutdown_function(array(self::class, 'handle_shutdown'));
        } catch (\Throwable $e) {
            // Fail open: profiler must never break site execution.
        }
    }

    private static function resolve_config(): void
    {
        $raw_env = defined('WPDEV_PERF_ENVIRONMENT') ? (string) WPDEV_PERF_ENVIRONMENT : 'production';
        self::$environment = self::validate_environment($raw_env);
        $is_dev = in_array(self::$environment, array('local', 'development'), true);

        $keys = array(
            'ENABLED'                => true,
            'AUTO_SAVEQUERIES'       => $is_dev ? true : false,
            'SAMPLE_RATE'            => $is_dev ? 1.0 : 0.05,
            'SKIP_HEARTBEAT'         => true,
            'SLOW_REQUEST_MS'        => $is_dev ? 250.0 : 500.0,
            'SLOW_QUERY_MS'          => $is_dev ? 20.0 : 50.0,
            'SLOW_HTTP_MS'           => $is_dev ? 500.0 : 1000.0,
            'SLOW_PHASE_MS'          => $is_dev ? 50.0 : 100.0,
            'SLOW_HOOK_MS'           => $is_dev ? 5.0 : 10.0,
            'MEMORY_WATERMARK_RATIO' => 0.80,
            'N_PLUS_ONE_THRESHOLD'   => 3,
            'AUTOLOAD_WARN_KB'       => 800.0,
            'PROFILE_HOOKS'          => true,
            'CAPTURE_SQL'            => true,
            'MAX_SLOW_QUERIES'       => 20,
            'MAX_DUPLICATE_QUERIES'  => 15,
            'MAX_HTTP_CALLS'         => 15,
            'MAX_SLOW_HOOKS'         => 20,
            'MAX_RECORD_BYTES'       => 98304,
            'LOG_DIR'                => '',
            'MAX_FILE_BYTES'         => 52428800,
            'MAX_TOTAL_BYTES'        => 524288000,
            'RETENTION_DAYS'         => 7,
            'MIN_FREE_BYTES'         => 10485760,
            'TRACE_HEADER'           => 'HTTP_X_WPDEV_TRACE',
            'TRACE_SECRET'           => '',
            'TRACE_IP_ALLOWLIST'     => array(),
            'FINGERPRINT_KEY'        => '',
            'HOST_ID'                => 'wpdev-worker',
        );

        foreach ($keys as $key => $default) {
            $const_name = 'WPDEV_PERF_' . $key;
            self::$config[$key] = defined($const_name) ? constant($const_name) : $default;
        }

        if ('' === trim((string) (self::$config['LOG_DIR'] ?? ''))) {
            self::$config['LOG_DIR'] = self::default_log_dir();
        }
    }

    /**
     * Compute an unguessable directory path inside wp-content derived from site salts.
     * Prevents public log scanning on Nginx web servers that ignore .htaccess and web.config.
     */
    public static function default_log_dir(): string
    {
        $salt = '';
        if (defined('AUTH_KEY') && '' !== (string) AUTH_KEY) {
            $salt .= (string) AUTH_KEY;
        }
        if (defined('SECURE_AUTH_KEY') && '' !== (string) SECURE_AUTH_KEY) {
            $salt .= (string) SECURE_AUTH_KEY;
        }
        $salt .= defined('ABSPATH') ? (string) ABSPATH : __DIR__;
        $hash = substr(hash('sha256', 'wpdev-perf-dir:' . $salt), 0, 16);

        $base = defined('WP_CONTENT_DIR') ? WP_CONTENT_DIR : dirname(__DIR__);

        return rtrim((string) $base, '/\\') . '/wpdev-perf-logs-' . $hash;
    }

    /* ====================================================================== */
    /* Lifecycle Milestones & Phase Tracking                                  */
    /* ====================================================================== */

    private static function hook_milestones(): void
    {
        if (function_exists('\did_action') && \did_action('muplugins_loaded')) {
            self::record_milestone('muplugins_loaded');
        } elseif (function_exists('\add_action')) {
            \add_action('muplugins_loaded', static function (): void {
                self::record_milestone('muplugins_loaded');
            }, -9999);
        } else {
            self::record_milestone('muplugins_loaded');
        }

        if (!function_exists('\add_action') || !function_exists('\add_filter')) {
            return;
        }

        $lifecycle_actions = array(
            'plugins_loaded',
            'setup_theme',
            'after_setup_theme',
            'init',
            'wp_loaded',
            'parse_request',
            'send_headers',
            'pre_get_posts',
            'wp',
            'template_redirect',
            'wp_head',
            'loop_start',
            'loop_end',
            'wp_footer',
            // Common WooCommerce high-impact lifecycle hooks (recorded if fired):
            'woocommerce_init',
            'woocommerce_before_main_content',
            'woocommerce_before_shop_loop',
            'woocommerce_before_single_product',
            'woocommerce_before_cart',
            'woocommerce_before_checkout_form',
            'woocommerce_checkout_order_processed',
        );

        foreach ($lifecycle_actions as $hook) {
            \add_action($hook, static function () use ($hook): void {
                self::record_milestone($hook);
            }, -9999);
        }

        \add_filter('template_include', static function ($template) {
            self::record_milestone('template_include');
            return $template;
        }, -9999);
    }

    public static function record_milestone(string $name): void
    {
        if (isset(self::$milestones[$name])) {
            return;
        }

        global $wpdb;
        $queries = (is_object($wpdb) && isset($wpdb->num_queries)) ? (int) $wpdb->num_queries : 0;

        self::$milestones[$name] = array(
            'ms'        => self::elapsed_ms(),
            'mem_bytes' => memory_get_usage(false),
            'queries'   => $queries,
        );
    }

    /**
     * Build a structured breakdown of durations, query counts, and memory deltas between consecutive milestones.
     *
     * @return array{milestones_ms: array<string, float>, phases: array<int, array<string, mixed>>, slowest_phase: array<string, mixed>|null}
     */
    private static function compute_phases(): array
    {
        $milestones_ms = array();
        $phases = array();
        $slowest_phase = null;

        // First phase: Server request start -> MU-Plugin bootstrap.
        if (self::$bootstrap_ms > 0.0) {
            $boot_phase = array(
                'phase'        => 'request_start -> mu_bootstrap',
                'ms'           => self::$bootstrap_ms,
                'queries'      => 0,
                'mem_delta_kb' => round(memory_get_usage(false) / 1024.0, 1),
            );
            $phases[] = $boot_phase;
            $slowest_phase = $boot_phase;
        }

        $prev_name = 'mu_bootstrap';
        $prev_ms = 0.0;
        $prev_mem = 0;
        $prev_queries = 0;
        $first = true;

        foreach (self::$milestones as $name => $data) {
            $milestones_ms[$name] = $data['ms'];

            if ($first) {
                $prev_name = $name;
                $prev_ms = $data['ms'];
                $prev_mem = $data['mem_bytes'];
                $prev_queries = $data['queries'];
                $first = false;
                continue;
            }

            $delta_ms = round(max(0.0, $data['ms'] - $prev_ms), 2);
            $delta_queries = max(0, $data['queries'] - $prev_queries);
            $delta_mem_kb = round(($data['mem_bytes'] - $prev_mem) / 1024.0, 1);

            $phase_entry = array(
                'phase'        => "{$prev_name} -> {$name}",
                'ms'           => $delta_ms,
                'queries'      => $delta_queries,
                'mem_delta_kb' => $delta_mem_kb,
            );
            $phases[] = $phase_entry;

            if (null === $slowest_phase || $delta_ms > (float) $slowest_phase['ms']) {
                $slowest_phase = $phase_entry;
            }

            $prev_name = $name;
            $prev_ms = $data['ms'];
            $prev_mem = $data['mem_bytes'];
            $prev_queries = $data['queries'];
        }

        return array(
            'milestones_ms' => $milestones_ms,
            'phases'        => $phases,
            'slowest_phase' => $slowest_phase,
        );
    }

    /* ====================================================================== */
    /* Low-Overhead Hook & Interval Profiler (Replaces buggy 'all' logger)    */
    /* ====================================================================== */

    private static function hook_interval_profiler(): void
    {
        if (!function_exists('\add_action')) {
            return;
        }

        self::$last_hook_name = 'mu_bootstrap';
        self::$last_hook_ms   = self::hrtime_ms();
        self::$last_hook_mem  = memory_get_usage(false);

        \add_action('all', array(self::class, 'on_every_hook'));
    }

    /**
     * O(1) rolling hook interval detector.
     * Avoids storing an unbounded array of every hook and uses $wpdb->num_queries (O(1))
     * instead of count((array) $wpdb->queries) (which caused O(N^2) memory/CPU blowups).
     *
     * @param mixed $hook_name
     */
    public static function on_every_hook($hook_name): void
    {
        if (!is_string($hook_name) || '' === $hook_name) {
            return;
        }

        // Fast skip for high-frequency formatting/translation/option filters.
        if (isset(self::NOISY_HOOKS[$hook_name])) {
            return;
        }
        if (
            0 === strpos($hook_name, 'pre_option_') ||
            0 === strpos($hook_name, 'option_') ||
            0 === strpos($hook_name, 'default_option_') ||
            0 === strpos($hook_name, 'pre_transient_') ||
            0 === strpos($hook_name, 'transient_') ||
            0 === strpos($hook_name, 'pre_site_transient_') ||
            0 === strpos($hook_name, 'site_transient_') ||
            0 === strpos($hook_name, 'sanitize_')
        ) {
            return;
        }

        $now_ms = self::hrtime_ms();
        $delta_ms = $now_ms - self::$last_hook_ms;

        global $wpdb;
        $cur_queries = (is_object($wpdb) && isset($wpdb->num_queries)) ? (int) $wpdb->num_queries : 0;
        $cur_mem = memory_get_usage(false);

        $prev_hook = self::$last_hook_name;
        if ('' !== $prev_hook && $delta_ms >= 1.0) {
            $queries_diff = max(0, $cur_queries - self::$last_hook_queries);
            $mem_diff_kb  = round(($cur_mem - self::$last_hook_mem) / 1024.0, 1);
            $rounded_ms   = round($delta_ms, 2);

            if (!isset(self::$hook_stats[$prev_hook])) {
                // Bound total tracked hook keys in memory to 500 to prevent memory growth on unusual requests.
                if (count(self::$hook_stats) < 500) {
                    self::$hook_stats[$prev_hook] = array(
                        'calls'        => 1,
                        'total_ms'     => $rounded_ms,
                        'max_ms'       => $rounded_ms,
                        'queries'      => $queries_diff,
                        'mem_delta_kb' => $mem_diff_kb,
                    );
                }
            } else {
                self::$hook_stats[$prev_hook]['calls']++;
                self::$hook_stats[$prev_hook]['total_ms'] = round(self::$hook_stats[$prev_hook]['total_ms'] + $rounded_ms, 2);
                if ($rounded_ms > self::$hook_stats[$prev_hook]['max_ms']) {
                    self::$hook_stats[$prev_hook]['max_ms'] = $rounded_ms;
                }
                self::$hook_stats[$prev_hook]['queries'] += $queries_diff;
                self::$hook_stats[$prev_hook]['mem_delta_kb'] = round(self::$hook_stats[$prev_hook]['mem_delta_kb'] + $mem_diff_kb, 1);
            }

            $slow_hook_threshold = max(1.0, (float) (self::$config['SLOW_HOOK_MS'] ?? 10.0));
            if ($rounded_ms >= $slow_hook_threshold) {
                self::$slow_intervals[] = array(
                    'start_hook'   => $prev_hook,
                    'end_hook'     => $hook_name,
                    'ms'           => $rounded_ms,
                    'queries'      => $queries_diff,
                    'mem_delta_kb' => $mem_diff_kb,
                );

                // Keep only top 30 slowest intervals in memory.
                if (count(self::$slow_intervals) > 45) {
                    usort(self::$slow_intervals, static function (array $a, array $b): int {
                        return $b['ms'] <=> $a['ms'];
                    });
                    self::$slow_intervals = array_slice(self::$slow_intervals, 0, 30);
                }
            }
        }

        self::$last_hook_name    = $hook_name;
        self::$last_hook_ms      = $now_ms;
        self::$last_hook_mem     = $cur_mem;
        self::$last_hook_queries = $cur_queries;
    }

    /**
     * Compile slow hooks & intervals report with automatic plugin/theme callback attribution.
     *
     * @return array{slow_hook_count: int, top_slow_hooks: array<int, array<string, mixed>>, top_intervals: array<int, array<string, mixed>>}
     */
    private static function collect_hook_metrics(): array
    {
        $slow_threshold = max(1.0, (float) (self::$config['SLOW_HOOK_MS'] ?? 10.0));
        $cap = max(1, (int) (self::$config['MAX_SLOW_HOOKS'] ?? 20));

        $qualified = array();
        foreach (self::$hook_stats as $hook => $stats) {
            if ($stats['total_ms'] >= $slow_threshold) {
                $qualified[$hook] = $stats;
            }
        }

        uasort($qualified, static function (array $a, array $b): int {
            return $b['total_ms'] <=> $a['total_ms'];
        });

        $top_hooks = array();
        foreach (array_slice($qualified, 0, $cap, true) as $hook => $stats) {
            $entry = array(
                'hook'         => $hook,
                'total_ms'     => $stats['total_ms'],
                'max_ms'       => $stats['max_ms'],
                'calls'        => $stats['calls'],
                'queries'      => $stats['queries'],
                'mem_delta_kb' => $stats['mem_delta_kb'],
            );
            $callbacks = ComponentResolver::resolve_hook_callbacks($hook, 5);
            if (!empty($callbacks)) {
                $entry['callbacks'] = $callbacks;
            }
            $top_hooks[] = $entry;
        }

        usort(self::$slow_intervals, static function (array $a, array $b): int {
            return $b['ms'] <=> $a['ms'];
        });

        return array(
            'slow_hook_count' => count($qualified),
            'top_slow_hooks'  => $top_hooks,
            'top_intervals'   => array_slice(self::$slow_intervals, 0, $cap),
        );
    }

    /* ====================================================================== */
    /* External HTTP API Profiling (With LIFO Matching & Hung Call Detection) */
    /* ====================================================================== */

    private static function hook_http(): void
    {
        if (!function_exists('\add_filter') || !function_exists('\add_action')) {
            return;
        }

        \add_filter('pre_http_request', static function ($pre, $args, $url) {
            try {
                if (false !== $pre || count(self::$http_stack) >= 32) {
                    return $pre;
                }

                $method = (is_array($args) && !empty($args['method'])) ? strtoupper((string) $args['method']) : 'GET';
                self::$http_stack[] = array(
                    'url'      => (string) $url,
                    'method'   => $method,
                    'start_ms' => self::hrtime_ms(),
                    'caller'   => self::capture_compact_backtrace(6),
                );
            } catch (\Throwable $e) {
                // Fail open
            }

            return $pre;
        }, 999999, 3);

        \add_action('http_api_debug', static function ($response, $context, $class, $args, $url): void {
            try {
                if ('response' !== $context) {
                    return;
                }

                self::$http_total_count++;
                $now_ms = self::hrtime_ms();
                $response_method = (is_array($args) && !empty($args['method']))
                    ? strtoupper((string) $args['method'])
                    : 'GET';

                // LIFO search (top of stack downward) so nested HTTP calls match accurately.
                $match_index = null;
                for ($i = count(self::$http_stack) - 1; $i >= 0; $i--) {
                    if ((self::$http_stack[$i]['url'] ?? '') === (string) $url
                        && (self::$http_stack[$i]['method'] ?? 'GET') === $response_method) {
                        $match_index = $i;
                        break;
                    }
                }

                if (null === $match_index) {
                    return;
                }

                $item = self::$http_stack[$match_index];
                array_splice(self::$http_stack, $match_index, 1);

                $duration_ms = round(max(0.0, $now_ms - (float) ($item['start_ms'] ?? $now_ms)), 2);
                self::$http_total_ms += $duration_ms;

                $clean = self::sanitize_url((string) $url);

                $status = 0;
                $error_message = null;
                if (function_exists('\is_wp_error') && \is_wp_error($response)) {
                    $status = 0;
                    $error_message = self::truncate_string(self::redact_text($response->get_error_message()), 160);
                } elseif (is_array($response) && isset($response['response']['code'])) {
                    $status = (int) $response['response']['code'];
                }

                $slow_threshold = max(0.0, (float) (self::$config['SLOW_HTTP_MS'] ?? 1000.0));
                $is_slow  = $duration_ms >= $slow_threshold;
                $is_error = (null !== $error_message) || ($status >= 400 && $status < 600);

                if ($is_slow) {
                    self::$http_slow_count++;
                }
                if ($is_error) {
                    self::$http_error_count++;
                }

                $cap = max(1, (int) (self::$config['MAX_HTTP_CALLS'] ?? 15));
                if (($is_slow || $is_error || self::$is_trace) && count(self::$http_calls) < $cap) {
                    $entry = array(
                        'host'      => $clean['host'],
                        'path'      => $clean['path'],
                        'method'    => (string) ($item['method'] ?? $response_method),
                        'status'    => $status,
                        'ms'        => $duration_ms,
                        'caller'    => (string) ($item['caller'] ?? ''),
                        'component' => ComponentResolver::from_caller_string((string) ($item['caller'] ?? '')),
                    );
                    if (null !== $error_message) {
                        $entry['error'] = $error_message;
                    }
                    self::$http_calls[] = $entry;
                }
            } catch (\Throwable $e) {
                // Fail open
            }
        }, 9999, 5);
    }

    /**
     * Any HTTP request still on $http_stack at shutdown was aborted/hung (e.g. fatal timeout mid-request).
     *
     * @return array<int, array<string, mixed>>
     */
    private static function collect_unfinished_http_calls(): array
    {
        if (empty(self::$http_stack)) {
            return array();
        }

        $now_ms = self::hrtime_ms();
        $unfinished = array();
        foreach (self::$http_stack as $item) {
            $clean = self::sanitize_url((string) ($item['url'] ?? ''));
            $elapsed = round(max(0.0, $now_ms - (float) ($item['start_ms'] ?? $now_ms)), 2);
            $caller = (string) ($item['caller'] ?? '');
            $unfinished[] = array(
                'host'      => $clean['host'],
                'path'      => $clean['path'],
                'method'    => (string) ($item['method'] ?? 'GET'),
                'elapsed_ms'=> $elapsed,
                'caller'    => $caller,
                'component' => ComponentResolver::from_caller_string($caller),
            );
        }

        return $unfinished;
    }

    /* ====================================================================== */
    /* REST API Route & Status Tracking                                       */
    /* ====================================================================== */

    private static function hook_rest(): void
    {
        if (!function_exists('\add_filter')) {
            return;
        }

        \add_filter('rest_pre_dispatch', static function ($result, $server, $request) {
            try {
                if (is_object($request) && method_exists($request, 'get_route')) {
                    self::$rest_route = self::truncate_string((string) $request->get_route(), 120);
                }
                self::record_milestone('rest_dispatch');
            } catch (\Throwable $e) {
                // Fail open
            }

            return $result;
        }, -9999, 3);

        \add_filter('rest_post_dispatch', static function ($response) {
            try {
                if (is_object($response) && method_exists($response, 'get_status')) {
                    $status = (int) $response->get_status();
                    if ($status > 0) {
                        self::$response_status = $status;
                        self::$response_status_source = 'rest';
                    }
                }
            } catch (\Throwable $e) {
                // Fail open
            }

            return $response;
        }, 9999, 1);
    }

    /* ====================================================================== */
    /* Database Query & N+1 Bottleneck Collector                              */
    /* ====================================================================== */

    /**
     * Inspect $wpdb->queries to identify:
     * 1. Slow queries (sorted by slowest first, never dropping the slowest queries if they happened late).
     * 2. N+1 duplicate query patterns (with count, total_ms, avg_ms, sample_caller, and normalized sql_template).
     * 3. Breakdown by SQL verb (SELECT, UPDATE, INSERT, DELETE) and by responsible plugin/theme component.
     *
     * @return array<string, mixed>
     */
    private static function collect_db_metrics(): array
    {
        global $wpdb;

        $metrics = array(
            'connection_state'  => is_object($wpdb) ? 'connected' : 'unavailable',
            'capture'           => 'unavailable',
            'query_count'       => (is_object($wpdb) && isset($wpdb->num_queries)) ? (int) $wpdb->num_queries : 0,
            'total_ms'          => 0.0,
            'slow_count'        => 0,
            'n_plus_one_count'  => 0,
            'by_verb'           => array(),
            'by_component'      => array(),
            'slow_queries'      => array(),
            'duplicate_queries' => array(),
        );

        if (is_object($wpdb) && property_exists($wpdb, 'dbh') && (null === $wpdb->dbh || false === $wpdb->dbh)) {
            $metrics['connection_state'] = 'unavailable';
        }

        if (is_object($wpdb) && isset($wpdb->last_error) && is_string($wpdb->last_error) && '' !== $wpdb->last_error) {
            $metrics['connection_state'] = 'error';
            $metrics['last_error']       = self::truncate_string(self::redact_text($wpdb->last_error), 180);
            $metrics['error_type']       = self::is_connection_error($wpdb->last_error) ? 'connection' : 'query';
        }

        $savequeries_on = defined('SAVEQUERIES') && (bool) constant('SAVEQUERIES');
        if (!$savequeries_on || !is_object($wpdb) || !isset($wpdb->queries) || !is_array($wpdb->queries)) {
            return $metrics;
        }

        $metrics['capture'] = 'savequeries';

        $fingerprint_key    = (string) (self::$config['FINGERPRINT_KEY'] ?? '');
        $slow_threshold     = max(0.0, (float) (self::$config['SLOW_QUERY_MS'] ?? 50.0));
        $n_plus_one_min     = max(2, (int) (self::$config['N_PLUS_ONE_THRESHOLD'] ?? 3));
        $max_slow_queries   = max(1, (int) (self::$config['MAX_SLOW_QUERIES'] ?? 20));
        $max_dup_queries    = max(1, (int) (self::$config['MAX_DUPLICATE_QUERIES'] ?? 15));
        $include_sql        = self::coerce_bool(self::$config['CAPTURE_SQL'] ?? true) || self::$is_trace;

        $total_time = 0.0;
        $slow_count = 0;
        $all_slow_candidates = array();
        $pattern_groups = array();
        $by_verb = array();
        $by_component = array();

        foreach ($wpdb->queries as $q) {
            if (!is_array($q)) {
                continue;
            }

            $sql     = isset($q[0]) ? (string) $q[0] : '';
            $time_ms = round((isset($q[1]) ? (float) $q[1] : 0.0) * 1000.0, 2);
            $caller  = isset($q[2]) ? (string) $q[2] : '';

            $total_time += $time_ms;

            $verb = SqlNormalizer::extract_verb($sql);
            if (!isset($by_verb[$verb])) {
                $by_verb[$verb] = array('count' => 0, 'total_ms' => 0.0);
            }
            $by_verb[$verb]['count']++;
            $by_verb[$verb]['total_ms'] = round($by_verb[$verb]['total_ms'] + $time_ms, 2);

            $clean_caller = self::clean_caller_stack($caller);
            $component    = ComponentResolver::from_caller_string($caller);
            if (!isset($by_component[$component])) {
                $by_component[$component] = array('count' => 0, 'total_ms' => 0.0);
            }
            $by_component[$component]['count']++;
            $by_component[$component]['total_ms'] = round($by_component[$component]['total_ms'] + $time_ms, 2);

            $normalized = SqlNormalizer::normalize($sql);
            if ('' !== $normalized) {
                if (!isset($pattern_groups[$normalized])) {
                    $pattern_groups[$normalized] = array(
                        'count'         => 1,
                        'total_ms'      => $time_ms,
                        'max_ms'        => $time_ms,
                        'sample_caller' => $clean_caller,
                        'component'     => $component,
                    );
                } else {
                    $pattern_groups[$normalized]['count']++;
                    $pattern_groups[$normalized]['total_ms'] = round($pattern_groups[$normalized]['total_ms'] + $time_ms, 2);
                    if ($time_ms > $pattern_groups[$normalized]['max_ms']) {
                        $pattern_groups[$normalized]['max_ms'] = $time_ms;
                        $pattern_groups[$normalized]['sample_caller'] = $clean_caller;
                    }
                }
            }

            if ($time_ms >= $slow_threshold) {
                $slow_count++;
                $entry = array(
                    'fingerprint' => SqlNormalizer::fingerprint($normalized, $fingerprint_key),
                    'ms'          => $time_ms,
                    'verb'        => $verb,
                    'component'   => $component,
                    'caller'      => $clean_caller,
                );
                if ($include_sql && '' !== $normalized) {
                    $entry['sql_template'] = self::truncate_string($normalized, 500);
                }
                $all_slow_candidates[] = $entry;
            }
        }

        // Sort slow queries by duration descending so the worst bottleneck is never truncated.
        usort($all_slow_candidates, static function (array $a, array $b): int {
            return $b['ms'] <=> $a['ms'];
        });

        // Build N+1 / duplicate query list (queries executed >= N_PLUS_ONE_THRESHOLD times).
        $duplicates = array();
        foreach ($pattern_groups as $normalized_sql => $group) {
            if ($group['count'] >= $n_plus_one_min) {
                $dup_entry = array(
                    'fingerprint'   => SqlNormalizer::fingerprint($normalized_sql, $fingerprint_key),
                    'count'         => $group['count'],
                    'total_ms'      => $group['total_ms'],
                    'avg_ms'        => round($group['total_ms'] / $group['count'], 2),
                    'max_ms'        => $group['max_ms'],
                    'component'     => $group['component'],
                    'sample_caller' => $group['sample_caller'],
                );
                if ($include_sql) {
                    $dup_entry['sql_template'] = self::truncate_string($normalized_sql, 500);
                }
                $duplicates[] = $dup_entry;
            }
        }

        // Sort N+1 queries by total time impact descending, then by repetition count.
        usort($duplicates, static function (array $a, array $b): int {
            $cmp = $b['total_ms'] <=> $a['total_ms'];
            return 0 !== $cmp ? $cmp : ($b['count'] <=> $a['count']);
        });

        // Sort component breakdown by total_ms descending.
        uasort($by_component, static function (array $a, array $b): int {
            return $b['total_ms'] <=> $a['total_ms'];
        });

        $metrics['total_ms']          = round($total_time, 2);
        $metrics['slow_count']        = $slow_count;
        $metrics['n_plus_one_count']  = count($duplicates);
        $metrics['by_verb']           = $by_verb;
        $metrics['by_component']      = array_slice($by_component, 0, 10, true);
        $metrics['slow_queries']      = array_slice($all_slow_candidates, 0, $max_slow_queries);
        $metrics['duplicate_queries'] = array_slice($duplicates, 0, $max_dup_queries);

        return $metrics;
    }

    /**
     * Filter internal WordPress DB/hook/cache boilerplate from caller stacks while preserving
     * enough application frames (up to 4) to identify the calling plugin or theme function.
     */
    public static function clean_caller_stack(string $caller): string
    {
        $parts = explode(',', $caller);
        $filtered = array();

        $noise_prefixes = array(
            'wp-includes/wp-db.php',
            'wp-includes/class-wpdb.php',
            'wpdb->',
            'require(',
            'require_once(',
            'include(',
            'include_once(',
            'do_action(',
            'apply_filters(',
            'WP_Hook->',
        );

        foreach ($parts as $part) {
            $part = trim($part);
            if ('' === $part) {
                continue;
            }
            $skip = false;
            foreach ($noise_prefixes as $prefix) {
                if (false !== strpos($part, $prefix)) {
                    $skip = true;
                    break;
                }
            }
            if (!$skip) {
                $filtered[] = $part;
            }
        }

        $meaningful = array_slice($filtered, -4);

        return self::truncate_string(self::redact_text(implode(' -> ', $meaningful)), 220);
    }

    /* ====================================================================== */
    /* Autoloaded Options Bloat & Object Cache / OPcache Collectors           */
    /* ====================================================================== */

    /**
     * Inspect in-memory alloptions cache (zero extra DB queries) to detect autoloaded wp_options bloat.
     *
     * @return array<string, mixed>
     */
    private static function collect_autoload_metrics(): array
    {
        if (!function_exists('\wp_load_alloptions')) {
            return array('capture' => 'unavailable');
        }

        try {
            // Only inspect if alloptions is already cached in memory; avoid triggering a DB query if not loaded.
            $alloptions = null;
            if (function_exists('\wp_cache_get')) {
                $cached = \wp_cache_get('alloptions', 'options');
                if (is_array($cached)) {
                    $alloptions = $cached;
                }
            }
            if (null === $alloptions) {
                return array('capture' => 'not_cached');
            }

            $total_bytes = 0;
            $sizes = array();

            foreach ($alloptions as $key => $val) {
                $bytes = strlen((string) $key) + (is_string($val) ? strlen($val) : strlen(serialize($val)));
                $total_bytes += $bytes;
                if ($bytes >= 4096) { // Track individual options >= 4 KB
                    $sizes[(string) $key] = round($bytes / 1024.0, 2);
                }
            }

            arsort($sizes);
            $total_kb = round($total_bytes / 1024.0, 2);
            $warn_kb  = max(100.0, (float) (self::$config['AUTOLOAD_WARN_KB'] ?? 800.0));

            return array(
                'capture'         => 'memory_cache',
                'option_count'    => count($alloptions),
                'total_kb'        => $total_kb,
                'is_bloated'      => $total_kb >= $warn_kb,
                'largest_options' => array_slice($sizes, 0, 5, true),
            );
        } catch (\Throwable $e) {
            return array('capture' => 'error');
        }
    }

    /**
     * Collect Object Cache hit/miss ratios, drop-in presence, and PHP OPcache efficiency.
     *
     * @return array<string, mixed>
     */
    private static function collect_cache_metrics(): array
    {
        global $wp_object_cache;

        $ext_object_cache = function_exists('\wp_using_ext_object_cache') && (bool) \wp_using_ext_object_cache();
        $hits = null;
        $misses = null;
        $hit_ratio = null;

        if (is_object($wp_object_cache)) {
            if (isset($wp_object_cache->cache_hits) && is_numeric($wp_object_cache->cache_hits)) {
                $hits = (int) $wp_object_cache->cache_hits;
            }
            if (isset($wp_object_cache->cache_misses) && is_numeric($wp_object_cache->cache_misses)) {
                $misses = (int) $wp_object_cache->cache_misses;
            }
            if (null !== $hits && null !== $misses && ($hits + $misses) > 0) {
                $hit_ratio = round($hits / ($hits + $misses), 3);
            }
        }

        $content_dir = defined('WP_CONTENT_DIR') ? WP_CONTENT_DIR : dirname(__DIR__);
        $dropins = array(
            'object_cache'   => @is_file($content_dir . '/object-cache.php'),
            'advanced_cache' => @is_file($content_dir . '/advanced-cache.php'),
            'db'             => @is_file($content_dir . '/db.php'),
        );

        $opcache_info = array('enabled' => false);
        if (function_exists('opcache_get_status')) {
            $op = @opcache_get_status(false);
            if (is_array($op) && !empty($op['opcache_enabled'])) {
                $opcache_info = array(
                    'enabled'        => true,
                    'hit_rate'       => isset($op['opcache_statistics']['opcache_hit_rate'])
                        ? round((float) $op['opcache_statistics']['opcache_hit_rate'], 2)
                        : null,
                    'used_memory_mb' => isset($op['memory_usage']['used_memory'])
                        ? round((float) $op['memory_usage']['used_memory'] / 1048576.0, 2)
                        : null,
                    'oom_restarts'   => isset($op['opcache_statistics']['oom_restarts'])
                        ? (int) $op['opcache_statistics']['oom_restarts']
                        : 0,
                );
            }
        }

        return array(
            'ext_object_cache' => $ext_object_cache,
            'hits'             => $hits,
            'misses'           => $misses,
            'hit_ratio'        => $hit_ratio,
            'dropins'          => $dropins,
            'opcache'          => $opcache_info,
        );
    }

    /**
     * Collect WordPress runtime, template, and WooCommerce context signals.
     *
     * @return array<string, mixed>
     */
    private static function collect_context_signals(): array
    {
        $ctx = array(
            'php_version'          => PHP_VERSION,
            'wp_version'           => defined('WP_VERSION') ? (string) WP_VERSION : (isset($GLOBALS['wp_version']) ? (string) $GLOBALS['wp_version'] : 'unknown'),
            'is_multisite'         => function_exists('\is_multisite') ? (bool) \is_multisite() : false,
            'site_id'              => function_exists('\get_current_blog_id') ? (int) \get_current_blog_id() : 1,
            'active_plugins_count' => 0,
            'theme'                => 'unknown',
            'template_type'        => 'unknown',
        );

        try {
            if (function_exists('\get_option')) {
                $active = \get_option('active_plugins');
                if (is_array($active)) {
                    $ctx['active_plugins_count'] = count($active);
                }
                $stylesheet = \get_option('stylesheet');
                if (is_string($stylesheet) && '' !== $stylesheet) {
                    $ctx['theme'] = $stylesheet;
                }
            }

            if (function_exists('\is_404') && \is_404()) {
                $ctx['template_type'] = '404';
            } elseif (function_exists('\is_search') && \is_search()) {
                $ctx['template_type'] = 'search';
            } elseif (function_exists('\is_front_page') && \is_front_page()) {
                $ctx['template_type'] = 'front_page';
            } elseif (function_exists('\is_singular') && \is_singular()) {
                $post_type = function_exists('\get_post_type') ? (string) \get_post_type() : 'post';
                $ctx['template_type'] = 'singular:' . ($post_type ?: 'post');
            } elseif (function_exists('\is_archive') && \is_archive()) {
                $ctx['template_type'] = 'archive';
            }

            // Detect WooCommerce high-value pages if WooCommerce conditional functions exist.
            if (function_exists('\is_checkout') && \is_checkout()) {
                $ctx['wc_page'] = 'checkout';
            } elseif (function_exists('\is_cart') && \is_cart()) {
                $ctx['wc_page'] = 'cart';
            } elseif (function_exists('\is_account_page') && \is_account_page()) {
                $ctx['wc_page'] = 'my_account';
            } elseif (function_exists('\is_product') && \is_product()) {
                $ctx['wc_page'] = 'product';
            } elseif (function_exists('\is_shop') && \is_shop()) {
                $ctx['wc_page'] = 'shop';
            }
        } catch (\Throwable $e) {
            // Fail open
        }

        return $ctx;
    }

    /* ====================================================================== */
    /* Request Classification & User Context (Zero PII)                       */
    /* ====================================================================== */

    /**
     * @return array{type: string, route: string, action: string}
     */
    public static function classify_request(): array
    {
        if (defined('WP_CLI') && WP_CLI) {
            $args = isset($_SERVER['argv']) && is_array($_SERVER['argv']) ? $_SERVER['argv'] : array();
            $subcommand = '';
            if (count($args) > 1) {
                $meaningful = array();
                foreach (array_slice($args, 1) as $arg) {
                    $arg = (string) $arg;
                    if (0 === strpos($arg, '-')) {
                        continue; // skip flags like --format=json or -v
                    }
                    $meaningful[] = $arg;
                    if (count($meaningful) >= 3) {
                        break;
                    }
                }
                $subcommand = implode(' ', $meaningful);
            }
            $route = '' !== $subcommand ? 'wp ' . $subcommand : (isset($args[0]) ? basename((string) $args[0]) : 'cli');
            return array('type' => 'cli', 'route' => self::truncate_string($route, 100), 'action' => $subcommand);
        }

        if (function_exists('\wp_doing_cron') && \wp_doing_cron()) {
            return array('type' => 'cron', 'route' => 'wp-cron.php', 'action' => '');
        }

        if (function_exists('\wp_doing_ajax') && \wp_doing_ajax()) {
            $action = isset($_REQUEST['action']) && is_scalar($_REQUEST['action'])
                ? self::sanitize_key_safe((string) $_REQUEST['action'])
                : 'unknown';
            return array('type' => 'ajax', 'route' => 'admin-ajax:' . $action, 'action' => $action);
        }

        if ('' !== self::$rest_route) {
            return array('type' => 'rest', 'route' => self::sanitize_route_path(self::$rest_route, 120), 'action' => '');
        }

        if (defined('REST_REQUEST') && REST_REQUEST) {
            $route = isset($_GET['rest_route']) && is_scalar($_GET['rest_route'])
                ? self::sanitize_text_safe((string) $_GET['rest_route'])
                : 'rest-unknown';
            return array('type' => 'rest', 'route' => self::sanitize_route_path($route, 120), 'action' => '');
        }

        if (function_exists('\is_admin') && \is_admin()) {
            $page = isset($_GET['page']) && is_scalar($_GET['page']) ? self::sanitize_key_safe((string) $_GET['page']) : '';
            $script = isset($_SERVER['SCRIPT_NAME']) ? basename((string) $_SERVER['SCRIPT_NAME']) : 'admin.php';
            $route = '' !== $page ? "{$script}?page={$page}" : $script;
            return array('type' => 'admin', 'route' => $route, 'action' => $page);
        }

        $uri_path = isset($_SERVER['REQUEST_URI']) ? (string) parse_url((string) $_SERVER['REQUEST_URI'], PHP_URL_PATH) : '/';
        if (0 === strpos($uri_path, '/wp-json/') || '/wp-json' === $uri_path) {
            return array('type' => 'rest', 'route' => self::sanitize_route_path($uri_path, 120), 'action' => '');
        }
        if (isset($_GET['wc-ajax']) && is_scalar($_GET['wc-ajax'])) {
            $wc_action = self::sanitize_key_safe((string) $_GET['wc-ajax']);
            return array('type' => 'wc-ajax', 'route' => 'wc-ajax:' . $wc_action, 'action' => $wc_action);
        }

        return array('type' => 'frontend', 'route' => self::sanitize_route_path($uri_path, 120), 'action' => '');
    }

    /**
     * Collect anonymous user role context without project-hardcoded role lists or PII.
     *
     * @return array{logged_in: bool, role: string}
     */
    private static function collect_user_context(): array
    {
        $logged_in = function_exists('\is_user_logged_in') && \is_user_logged_in();
        $role = 'guest';

        if ($logged_in && function_exists('\wp_get_current_user')) {
            $user = \wp_get_current_user();
            if ($user && !empty($user->roles) && is_array($user->roles)) {
                $primary_role = (string) reset($user->roles);
                $sanitized = self::sanitize_key_safe($primary_role);
                $role = '' !== $sanitized ? $sanitized : 'authenticated';
            } else {
                $role = 'authenticated';
            }
        }

        return array(
            'logged_in' => $logged_in,
            'role'      => $role,
        );
    }

    /* ====================================================================== */
    /* Shutdown Handler & Record Assembly                                     */
    /* ====================================================================== */

    public static function handle_shutdown(): void
    {
        if (self::$shutdown_handled) {
            return;
        }
        self::$shutdown_handled = true;

        try {
            if (!self::coerce_bool(self::$config['ENABLED'] ?? false)) {
                return;
            }

            // Flush final hook interval before shutdown.
            if (self::coerce_bool(self::$config['PROFILE_HOOKS'] ?? true) || self::$is_trace) {
                self::on_every_hook('shutdown');
            }

            self::record_milestone('shutdown');

            $wall_ms = round(max(0.0, (microtime(true) - (float) self::$config['bootstrap_base']) * 1000.0), 2);

            $classification  = self::classify_request();
            $fatal           = self::detect_fatal_error();
            $db              = self::collect_db_metrics();
            $memory          = self::collect_memory_metrics();
            $phase_data      = self::compute_phases();
            $hook_data       = self::collect_hook_metrics();
            $autoload        = self::collect_autoload_metrics();
            $unfinished_http = self::collect_unfinished_http_calls();

            $triggers = self::build_triggers(
                $wall_ms,
                $db,
                $memory,
                $phase_data,
                $hook_data,
                $autoload,
                $unfinished_http,
                $fatal['is_fatal']
            );

            if (empty($triggers)) {
                // Skip healthy admin-ajax heartbeat polls if configured.
                if (
                    self::coerce_bool(self::$config['SKIP_HEARTBEAT'] ?? true) &&
                    'ajax' === $classification['type'] &&
                    'heartbeat' === $classification['action']
                ) {
                    return;
                }

                $rate = self::clamped_sample_rate();
                $threshold = (int) round($rate * 10000);
                if ($threshold <= 0 || random_int(1, 10000) > $threshold) {
                    return;
                }
                $triggers[] = 'sample';
            }

            $sample_rate = self::clamped_sample_rate();
            $weight      = self::sample_weight_for($triggers, $sample_rate);

            $record = self::assemble_record(
                $wall_ms,
                $classification,
                $db,
                $memory,
                $phase_data,
                $hook_data,
                $autoload,
                $unfinished_http,
                $fatal,
                $triggers,
                $sample_rate,
                $weight
            );

            $json = json_encode($record, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);
            if (false === $json) {
                return;
            }

            $json = self::enforce_record_cap($record, $json, max(2048, (int) (self::$config['MAX_RECORD_BYTES'] ?? 98304)));
            if (null === $json) {
                return;
            }

            self::write_log_line($json);

            // Probabilistic retention & directory size pruning (1% of logged requests).
            if (random_int(1, 100) === 1) {
                self::maybe_prune_old_logs();
            }
        } catch (\Throwable $e) {
            // Fail open
        }
    }

    /**
     * @param array<string, mixed> $db
     * @param array<string, mixed> $memory
     * @param array<string, mixed> $phase_data
     * @param array<string, mixed> $hook_data
     * @param array<string, mixed> $autoload
     * @param array<int, array<string, mixed>> $unfinished_http
     * @return string[]
     */
    private static function build_triggers(
        float $wall_ms,
        array $db,
        array $memory,
        array $phase_data,
        array $hook_data,
        array $autoload,
        array $unfinished_http,
        bool $is_fatal
    ): array {
        $triggers = array();

        if (self::$is_trace) {
            $triggers[] = 'trace';
        }
        if ($wall_ms >= max(0.0, (float) (self::$config['SLOW_REQUEST_MS'] ?? 500.0))) {
            $triggers[] = 'slow_request';
        }
        if ((int) ($db['slow_count'] ?? 0) > 0) {
            $triggers[] = 'slow_query';
        }
        if ((int) ($db['n_plus_one_count'] ?? 0) > 0 && $wall_ms >= 150.0) {
            $triggers[] = 'n_plus_one_queries';
        }
        if ('unavailable' === ($db['connection_state'] ?? '') || 'connection' === ($db['error_type'] ?? '')) {
            $triggers[] = 'db_connection_error';
        } elseif ('error' === ($db['connection_state'] ?? '')) {
            $triggers[] = 'db_query_error';
        }
        if (self::$http_slow_count > 0) {
            $triggers[] = 'slow_http';
        }
        if (self::$http_error_count > 0) {
            $triggers[] = 'http_error';
        }
        if (!empty($unfinished_http)) {
            $triggers[] = 'http_unfinished';
        }

        $slow_phase_ms = max(20.0, (float) (self::$config['SLOW_PHASE_MS'] ?? 100.0));
        if (
            $wall_ms >= max(0.0, (float) (self::$config['SLOW_REQUEST_MS'] ?? 500.0)) &&
            isset($phase_data['slowest_phase']['ms']) &&
            (float) $phase_data['slowest_phase']['ms'] >= $slow_phase_ms
        ) {
            $triggers[] = 'slow_phase';
        }

        if ((int) ($hook_data['slow_hook_count'] ?? 0) > 0 && $wall_ms >= max(0.0, (float) (self::$config['SLOW_REQUEST_MS'] ?? 500.0))) {
            $triggers[] = 'slow_hook';
        }

        if (self::is_memory_high($memory['usage_ratio'] ?? null)) {
            $triggers[] = 'memory_high';
        }

        if (!empty($autoload['is_bloated']) && $wall_ms >= max(0.0, (float) (self::$config['SLOW_REQUEST_MS'] ?? 500.0))) {
            $triggers[] = 'autoload_bloat';
        }

        if ($is_fatal) {
            $triggers[] = 'fatal';
        }

        $status = $is_fatal && self::resolve_status_code() < 400 ? 500 : self::resolve_status_code();
        if ($status >= 500) {
            $triggers[] = 'error_5xx';
        }

        return array_values(array_unique($triggers));
    }

    /**
     * @param array<string, mixed> $classification
     * @param array<string, mixed> $db
     * @param array<string, mixed> $memory
     * @param array<string, mixed> $phase_data
     * @param array<string, mixed> $hook_data
     * @param array<string, mixed> $autoload
     * @param array<int, array<string, mixed>> $unfinished_http
     * @param array{is_fatal: bool, error?: array<string, mixed>} $fatal
     * @param string[] $triggers
     * @return array<string, mixed>
     */
    private static function assemble_record(
        float $wall_ms,
        array $classification,
        array $db,
        array $memory,
        array $phase_data,
        array $hook_data,
        array $autoload,
        array $unfinished_http,
        array $fatal,
        array $triggers,
        float $sample_rate,
        float $weight
    ): array {
        $duration = array(
            'wall_ms'      => $wall_ms,
            'bootstrap_ms' => self::$bootstrap_ms,
        );

        $cpu_delta = CpuHelper::delta_ms(self::$cpu_start, CpuHelper::snapshot());
        if (null !== $cpu_delta) {
            $cpu_total = $cpu_delta['cpu_total_ms'];
            $duration['cpu_user_ms']   = $cpu_delta['cpu_user_ms'];
            $duration['cpu_system_ms'] = $cpu_delta['cpu_system_ms'];
            $duration['cpu_total_ms']  = $cpu_total;
            $duration['io_wait_ms']    = round(max(0.0, $wall_ms - $cpu_total), 2);
            $duration['io_wait_ratio'] = $wall_ms > 0.0 ? round(min(1.0, $duration['io_wait_ms'] / $wall_ms), 3) : 0.0;
            $duration['cpu_capture']   = $cpu_total > $wall_ms ? 'skew' : 'delta';
        } else {
            $duration['cpu_capture'] = 'unavailable';
        }

        $status_code = $fatal['is_fatal'] && self::resolve_status_code() < 400 ? 500 : self::resolve_status_code();

        $system_load = array('capture' => 'unavailable');
        if (function_exists('sys_getloadavg')) {
            $load = @sys_getloadavg();
            if (is_array($load) && count($load) >= 3) {
                $system_load = array(
                    'load_1m'  => round((float) $load[0], 2),
                    'load_5m'  => round((float) $load[1], 2),
                    'load_15m' => round((float) $load[2], 2),
                    'capture'  => 'sys_getloadavg',
                );
            }
        }

        $record = array(
            'schema_version' => self::SCHEMA_VERSION,
            'logger_version' => self::LOGGER_VERSION,
            'brand'          => 'wpdev',
            'timestamp_utc'  => self::timestamp_utc(),
            'request_id'     => self::$request_id,
            'environment'    => self::$environment,
            'host_id'        => (string) (self::$config['HOST_ID'] ?? 'wpdev-worker'),
            'triggers'       => $triggers,
            'sample_weight'  => $weight,
            'sample_rate'    => $sample_rate,
            'request'        => array(
                'type'          => $classification['type'],
                'method'        => self::truncate_string(isset($_SERVER['REQUEST_METHOD']) ? strtoupper((string) $_SERVER['REQUEST_METHOD']) : 'CLI', 16),
                'route'         => $classification['route'],
                'action'        => $classification['action'],
                'status'        => $status_code,
                'status_source' => self::$response_status_source,
            ),
            'duration'       => $duration,
            'milestones_ms'  => $phase_data['milestones_ms'],
            'phases'         => array(
                'slowest'   => $phase_data['slowest_phase'],
                'breakdown' => $phase_data['phases'],
            ),
            'hooks'          => $hook_data,
            'db'             => $db,
            'autoload'       => $autoload,
            'http'           => array(
                'total_count'      => self::$http_total_count,
                'slow_count'       => self::$http_slow_count,
                'error_count'      => self::$http_error_count,
                'unfinished_count' => count($unfinished_http),
                'total_ms'         => round(self::$http_total_ms, 2),
                'calls'            => self::$http_calls,
                'unfinished_calls' => $unfinished_http,
            ),
            'cache'          => self::collect_cache_metrics(),
            'memory'         => $memory,
            'system_load'    => $system_load,
            'context'        => self::collect_context_signals(),
            'user'           => self::collect_user_context(),
        );

        if ($fatal['is_fatal'] && isset($fatal['error'])) {
            $record['fatal_error'] = $fatal['error'];
        }

        return $record;
    }

    /**
     * Progressive truncation ladder so oversized records shed detail arrays gracefully before dropping.
     *
     * @param array<string, mixed> $record
     */
    private static function enforce_record_cap(array $record, string $json, int $max_bytes): ?string
    {
        if (strlen($json) <= $max_bytes) {
            return $json;
        }

        // Step 1: Trim hook intervals and reduce slow queries / duplicates / HTTP calls to top 5.
        $record['hooks']['top_intervals']   = array_slice($record['hooks']['top_intervals'] ?? array(), 0, 5);
        $record['hooks']['top_slow_hooks']  = array_slice($record['hooks']['top_slow_hooks'] ?? array(), 0, 5);
        $record['db']['slow_queries']       = array_slice($record['db']['slow_queries'] ?? array(), 0, 5);
        $record['db']['duplicate_queries']  = array_slice($record['db']['duplicate_queries'] ?? array(), 0, 5);
        $record['http']['calls']            = array_slice($record['http']['calls'] ?? array(), 0, 5);
        $record['truncated_level']          = 1;

        $json = json_encode($record, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);
        if (false !== $json && strlen($json) <= $max_bytes) {
            return $json;
        }

        // Step 2: Strip heavy arrays while keeping summary counts and slowest phase.
        $record['hooks']['top_intervals']  = array();
        $record['hooks']['top_slow_hooks'] = array();
        $record['db']['slow_queries']      = array();
        $record['db']['duplicate_queries'] = array();
        $record['http']['calls']           = array();
        $record['phases']['breakdown']     = array();
        $record['truncated_level']         = 2;

        $json = json_encode($record, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);
        if (false !== $json && strlen($json) <= $max_bytes) {
            return $json;
        }

        // Step 3: Minimal emergency record.
        $minimal = array(
            'schema_version'  => self::SCHEMA_VERSION,
            'logger_version'  => self::LOGGER_VERSION,
            'brand'           => 'wpdev',
            'timestamp_utc'   => self::timestamp_utc(),
            'request_id'      => self::$request_id,
            'triggers'        => $record['triggers'],
            'request'         => $record['request'],
            'duration'        => $record['duration'],
            'truncated_level' => 3,
        );

        $json = json_encode($minimal, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);
        if (false !== $json && strlen($json) <= $max_bytes) {
            return $json;
        }

        return null;
    }

    /* ====================================================================== */
    /* Non-Blocking File Storage, Rotation & Retention Pruning                */
    /* ====================================================================== */

    private static function write_log_line(string $json_line): void
    {
        $log_dir = rtrim((string) (self::$config['LOG_DIR'] ?? ''), '/\\');
        if ('' === $log_dir) {
            return;
        }

        if (!@is_dir($log_dir)) {
            if (!@mkdir($log_dir, 0750, true) && !@is_dir($log_dir)) {
                return;
            }
            @chmod($log_dir, 0750);
        }

        if (!@is_writable($log_dir)) {
            return;
        }

        if (!self::$guards_verified) {
            self::ensure_directory_guards($log_dir);
            self::$guards_verified = true;
        }

        $free_bytes = @disk_free_space($log_dir);
        if (false !== $free_bytes && $free_bytes < (int) (self::$config['MIN_FREE_BYTES'] ?? 10485760)) {
            return;
        }

        $line           = $json_line . "\n";
        $max_file_bytes = max(10240, (int) (self::$config['MAX_FILE_BYTES'] ?? 52428800));
        $date           = gmdate('Y-m-d');

        for ($segment = 0; $segment <= 100; $segment++) {
            $suffix = 0 === $segment ? '' : '-' . $segment;
            $file_path = "{$log_dir}/wpdev-perf-{$date}{$suffix}.jsonl";
            $result = self::append_log_line($file_path, $line, $max_file_bytes);

            if (1 === $result) {
                if (self::$log_dir_size >= 0) {
                    self::$log_dir_size += strlen($line);
                }
                return;
            }
            if (0 === $result) {
                // Lock busy or I/O error -> fail open without blocking worker.
                return;
            }
        }
    }

    /**
     * Protect log directory from direct web access on Apache, IIS, and PHP index browsing.
     */
    private static function ensure_directory_guards(string $log_dir): void
    {
        $htaccess = $log_dir . '/.htaccess';
        if (!@file_exists($htaccess)) {
            @file_put_contents(
                $htaccess,
                "<IfModule mod_authz_core.c>\n\tRequire all denied\n</IfModule>\n<IfModule !mod_authz_core.c>\n\tDeny from all\n</IfModule>\n"
            );
        }

        $web_config = $log_dir . '/web.config';
        if (!@file_exists($web_config)) {
            @file_put_contents(
                $web_config,
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<configuration>\n\t<system.webServer>\n\t\t<authorization>\n\t\t\t<deny users=\"*\" />\n\t\t</authorization>\n\t</system.webServer>\n</configuration>\n"
            );
        }

        $index = $log_dir . '/index.php';
        if (!@file_exists($index)) {
            @file_put_contents($index, "<?php\n// Silence is golden.\n");
        }
    }

    /**
     * Append a JSONL line using a non-blocking exclusive flock with bounded micro-retries.
     *
     * @return int 1 = written, 0 = busy/error (dropped), -1 = segment full (rotate to next segment)
     */
    private static function append_log_line(string $log_file, string $line, int $max_file_bytes): int
    {
        $handle = @fopen($log_file, 'ab');
        if (false === $handle) {
            return 0;
        }

        $locked = false;
        // Bounded micro-retry with jitter (up to 4 attempts) to survive concurrent worker bursts.
        for ($attempt = 0; $attempt < 4; $attempt++) {
            if (@flock($handle, LOCK_EX | LOCK_NB)) {
                $locked = true;
                break;
            }
            if ($attempt < 3) {
                usleep((500 * (1 << $attempt)) + random_int(0, 250));
            }
        }

        if (!$locked) {
            @fclose($handle);
            return 0;
        }

        @fseek($handle, 0, SEEK_END);
        $size = @ftell($handle);
        if (false === $size || ($size > 0 && ($size + strlen($line)) > $max_file_bytes)) {
            @flock($handle, LOCK_UN);
            @fclose($handle);
            return -1;
        }

        if (0 === $size) {
            @chmod($log_file, 0640);
        }

        $written = @fwrite($handle, $line);
        @fflush($handle);
        @flock($handle, LOCK_UN);
        @fclose($handle);

        return strlen($line) === $written ? 1 : 0;
    }

    private static function maybe_prune_old_logs(): void
    {
        $log_dir = rtrim((string) (self::$config['LOG_DIR'] ?? ''), '/\\');
        if ('' === $log_dir || !@is_dir($log_dir)) {
            return;
        }

        self::$log_dir_size = -1;

        $files = @glob("{$log_dir}/wpdev-perf-*.jsonl");
        if (!is_array($files) || empty($files)) {
            return;
        }

        $retention_days  = (int) (self::$config['RETENTION_DAYS'] ?? 7);
        $max_total_bytes = max(0, (int) (self::$config['MAX_TOTAL_BYTES'] ?? 524288000));

        if ($retention_days > 0) {
            $day_seconds = defined('DAY_IN_SECONDS') ? (int) DAY_IN_SECONDS : 86400;
            $cutoff = time() - ($retention_days * $day_seconds);
            foreach ($files as $file) {
                $mtime = @filemtime($file);
                if (@is_file($file) && false !== $mtime && $mtime < $cutoff) {
                    @unlink($file);
                }
            }
        }

        if ($max_total_bytes <= 0) {
            return;
        }

        $files = @glob("{$log_dir}/wpdev-perf-*.jsonl");
        if (!is_array($files) || empty($files)) {
            return;
        }

        usort($files, static function (string $left, string $right): int {
            return ((int) @filemtime($left)) <=> ((int) @filemtime($right));
        });

        $total = self::log_directory_size($log_dir);
        $active_prefix = 'wpdev-perf-' . gmdate('Y-m-d');

        foreach ($files as $file) {
            if ($total <= $max_total_bytes) {
                break;
            }
            if (0 === strpos(basename($file), $active_prefix)) {
                continue;
            }
            $size = @is_file($file) ? (int) @filesize($file) : 0;
            if ($size > 0 && @unlink($file)) {
                $total -= $size;
            }
        }

        self::$log_dir_size = max(0, $total);
    }

    private static function log_directory_size(string $log_dir): int
    {
        if (self::$log_dir_size >= 0) {
            return self::$log_dir_size;
        }

        $total = 0;
        $files = @glob(rtrim($log_dir, '/\\') . '/wpdev-perf-*.jsonl');
        if (!is_array($files)) {
            self::$log_dir_size = 0;
            return 0;
        }

        foreach ($files as $file) {
            if (@is_file($file)) {
                $size = @filesize($file);
                if (false !== $size) {
                    $total += (int) $size;
                }
            }
        }

        self::$log_dir_size = $total;

        return $total;
    }

    /* ====================================================================== */
    /* Diagnostics, Sanitization & Utility Helpers                            */
    /* ====================================================================== */

    /**
     * Capture a concise application caller trace for HTTP requests.
     */
    private static function capture_compact_backtrace(int $max_frames = 5): string
    {
        if (!function_exists('debug_backtrace')) {
            return '';
        }

        $trace = @debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 18);
        if (!is_array($trace)) {
            return '';
        }

        $frames = array();
        foreach ($trace as $frame) {
            $file  = isset($frame['file']) ? str_replace('\\', '/', (string) $frame['file']) : '';
            $class = isset($frame['class']) ? (string) $frame['class'] : '';
            $func  = isset($frame['function']) ? (string) $frame['function'] : '';

            // Skip internal profiler frames and WP core HTTP/Hook boilerplate.
            if (
                false !== strpos($class, __NAMESPACE__) ||
                false !== strpos($file, 'wp-includes/class-wp-hook.php') ||
                false !== strpos($file, 'wp-includes/plugin.php') ||
                false !== strpos($file, 'wp-includes/http.php') ||
                false !== strpos($file, 'wp-includes/class-wp-http')
            ) {
                continue;
            }

            $comp = '' !== $file ? ComponentResolver::from_path($file) : '';
            $call = '' !== $class ? "{$class}::{$func}" : $func;
            if ('' !== $comp && 'core' !== $comp && 0 !== strpos($comp, 'other:')) {
                $frames[] = "[{$comp}] {$call}";
            } else {
                $frames[] = $call;
            }

            if (count($frames) >= $max_frames) {
                break;
            }
        }

        return self::truncate_string(implode(' <- ', $frames), 200);
    }

    /**
     * @return array{is_fatal: bool, error?: array{type: int, file: string, line: int, component: string, message: string}}
     */
    private static function detect_fatal_error(): array
    {
        $last = error_get_last();
        if (null === $last) {
            return array('is_fatal' => false);
        }

        $fatal_types = array(E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR, E_USER_ERROR);
        if (!in_array((int) $last['type'], $fatal_types, true)) {
            return array('is_fatal' => false);
        }

        $raw_file = (string) ($last['file'] ?? '');

        return array(
            'is_fatal' => true,
            'error'    => array(
                'type'      => (int) $last['type'],
                'file'      => basename($raw_file),
                'line'      => (int) ($last['line'] ?? 0),
                'component' => ComponentResolver::from_path($raw_file),
                'message'   => self::truncate_string(self::redact_text((string) ($last['message'] ?? 'Fatal error')), 220),
            ),
        );
    }

    private static function collect_memory_metrics(): array
    {
        $limit_raw   = function_exists('ini_get') ? (string) (@ini_get('memory_limit') ?: '') : '';
        $limit_bytes = MemoryHelper::parse_limit_to_bytes($limit_raw);

        return MemoryHelper::build_metrics(
            memory_get_usage(true),
            memory_get_peak_usage(true),
            memory_get_peak_usage(false),
            $limit_bytes
        );
    }

    private static function is_memory_high($ratio): bool
    {
        if (null === $ratio || !is_numeric($ratio) || (float) $ratio <= 0.0) {
            return false;
        }

        return (float) $ratio >= max(0.05, min(1.0, (float) (self::$config['MEMORY_WATERMARK_RATIO'] ?? 0.80)));
    }

    private static function is_connection_error(string $message): bool
    {
        return 1 === preg_match(
            "/(?:connection refused|can't connect|cannot connect|connection timed out|server has gone away|lost connection|too many connections|access denied for user)/i",
            $message
        );
    }

    private static function resolve_status_code(): int
    {
        if (self::$response_status > 0) {
            return self::$response_status;
        }

        if (function_exists('http_response_code')) {
            $raw = http_response_code();
            if (false !== $raw && (int) $raw > 0) {
                self::$response_status_source = 'http_response_code';
                return (int) $raw;
            }
        }

        self::$response_status_source = 'default';

        return 200;
    }

    private static function clamped_sample_rate(): float
    {
        return max(0.0, min(1.0, (float) (self::$config['SAMPLE_RATE'] ?? 0.05)));
    }

    /**
     * @param string[] $triggers
     */
    public static function sample_weight_for(array $triggers, float $rate): float
    {
        if (!empty(array_intersect($triggers, self::MANDATORY_TRIGGERS))) {
            return 1.0;
        }

        $rate = max(0.0, min(1.0, $rate));
        if ($rate <= 0.0 || $rate >= 1.0) {
            return 1.0;
        }

        return round(1.0 / $rate, 4);
    }

    public static function validate_environment(string $value): string
    {
        $value = strtolower(trim($value));

        return in_array($value, array('production', 'staging', 'development', 'local'), true) ? $value : 'production';
    }

    public static function normalize_header_key(string $header): string
    {
        $header = strtoupper(trim(str_replace(' ', '_', $header)));
        if ('' === $header) {
            return '';
        }

        return 0 === strpos($header, 'HTTP_')
            ? $header
            : 'HTTP_' . str_replace('-', '_', $header);
    }

    /**
     * @param mixed $value
     */
    public static function coerce_bool($value): bool
    {
        if (is_bool($value)) {
            return $value;
        }
        if (is_int($value) || is_float($value)) {
            return 0.0 !== (float) $value;
        }
        if (is_string($value)) {
            $norm = strtolower(trim($value));
            if (in_array($norm, array('', '0', 'false', 'no', 'off'), true)) {
                return false;
            }
            if (in_array($norm, array('1', 'true', 'yes', 'on'), true)) {
                return true;
            }
        }

        return (bool) $value;
    }

    /**
     * @param mixed $allowlist
     * @return string[]|null
     */
    public static function normalize_ip_allowlist($allowlist): ?array
    {
        if (null === $allowlist) {
            return array();
        }
        if (is_array($allowlist)) {
            $out = array();
            foreach ($allowlist as $ip) {
                if (!is_scalar($ip)) {
                    continue;
                }
                $ip = trim((string) $ip);
                if ('' !== $ip) {
                    $out[] = $ip;
                }
            }
            return $out;
        }
        if (is_string($allowlist)) {
            $allowlist = trim($allowlist);
            if ('' === $allowlist) {
                return array();
            }
            $out = array();
            foreach (explode(',', $allowlist) as $ip) {
                $ip = trim($ip);
                if ('' !== $ip) {
                    $out[] = $ip;
                }
            }
            return $out;
        }

        return null;
    }

    private static function is_trace_request(): bool
    {
        $secret = trim((string) (self::$config['TRACE_SECRET'] ?? ''));
        if ('' === $secret) {
            return false;
        }

        $key = self::normalize_header_key((string) (self::$config['TRACE_HEADER'] ?? 'HTTP_X_WPDEV_TRACE'));
        if ('' === $key || !isset($_SERVER[$key]) || !is_scalar($_SERVER[$key])) {
            return false;
        }

        $provided = trim((string) $_SERVER[$key]);
        if ('' === $provided || strlen($provided) > 256) {
            return false;
        }

        $allowlist = self::normalize_ip_allowlist(self::$config['TRACE_IP_ALLOWLIST'] ?? array());
        if (null === $allowlist) {
            return false;
        }
        if (!empty($allowlist)) {
            $remote = isset($_SERVER['REMOTE_ADDR']) ? (string) $_SERVER['REMOTE_ADDR'] : '';
            if ('' === $remote || !in_array($remote, $allowlist, true)) {
                return false;
            }
        }

        return function_exists('hash_equals') && hash_equals($secret, $provided);
    }

    private static function new_request_id(): string
    {
        try {
            return 'req_' . bin2hex(random_bytes(6));
        } catch (\Throwable $e) {
            return 'req_' . substr(hash('sha256', microtime(true) . ':' . (function_exists('getmypid') ? (string) getmypid() : '')), 0, 12);
        }
    }

    private static function hrtime_ms(): float
    {
        if (function_exists('hrtime')) {
            return (float) hrtime(true) / 1e6;
        }

        return microtime(true) * 1000.0;
    }

    private static function elapsed_ms(): float
    {
        return round(max(0.0, self::hrtime_ms() - self::$boot_hrtime_ms), 2);
    }

    private static function timestamp_utc(): string
    {
        $now = microtime(true);
        $ms  = (int) floor(($now - floor($now)) * 1000);

        return gmdate('Y-m-d\TH:i:s', (int) $now) . '.' . sprintf('%03d', $ms) . 'Z';
    }

    /**
     * @return array{host: string, path: string}
     */
    public static function sanitize_url(string $url): array
    {
        $parts = parse_url($url);
        if (!is_array($parts)) {
            return array('host' => 'unknown', 'path' => '/');
        }

        $host = isset($parts['host']) ? strtolower((string) $parts['host']) : 'unknown';
        $path = isset($parts['path']) ? (string) $parts['path'] : '/';

        return array(
            'host' => $host,
            'path' => self::sanitize_route_path($path, 120),
        );
    }

    public static function sanitize_route_path(string $path, int $limit): string
    {
        $path = preg_replace('/\/(?:\d+|[0-9a-f]{8}-[0-9a-f-]{27,})\b/i', '/:id', $path) ?? $path;

        return self::truncate_string('' !== $path ? $path : '/', $limit);
    }

    private static function sanitize_key_safe(string $value): string
    {
        if (function_exists('\sanitize_key')) {
            return \sanitize_key($value);
        }

        return strtolower(preg_replace('/[^a-z0-9_\-]/', '', strtolower($value)) ?? '');
    }

    private static function sanitize_text_safe(string $value): string
    {
        if (function_exists('\sanitize_text_field')) {
            return \sanitize_text_field($value);
        }

        return trim(strip_tags($value));
    }

    public static function redact_text(string $text): string
    {
        $text = preg_replace('/\bBearer\s+[A-Za-z0-9._~+\/-]+=*/i', 'Bearer [redacted]', $text) ?? $text;
        $text = preg_replace('/\bBasic\s+[A-Za-z0-9+\/]+=*/i', 'Basic [redacted]', $text) ?? $text;
        $text = preg_replace(
            '/(["\']?)(password|passwd|pwd|token|secret|auth|authorization|cookie|api[_-]?key|session[_-]?token|access[_-]?token|client[_-]?secret|private[_-]?key|nonce)\1(\s*[:=]\s*)(?:["\'][^"\']*["\']|[^\s,;{}]+)/i',
            '$1$2$1$3[redacted]',
            $text
        ) ?? $text;
        $text = preg_replace('/\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}\b/i', '[redacted-email]', $text) ?? $text;

        return $text;
    }

    public static function truncate_string(string $str, int $limit): string
    {
        if ($limit <= 3) {
            return '';
        }
        $length = function_exists('mb_strlen') ? mb_strlen($str) : strlen($str);
        if ($length <= $limit) {
            return $str;
        }

        $prefix = function_exists('mb_substr') ? mb_substr($str, 0, $limit - 3) : substr($str, 0, $limit - 3);

        return $prefix . '...';
    }
}

// Auto-bootstrap unless explicitly disabled for unit testing.
if ((!defined('WPDEV_PERF_NO_BOOT') || !WPDEV_PERF_NO_BOOT) && defined('ABSPATH')) {
    Profiler::bootstrap();
}
