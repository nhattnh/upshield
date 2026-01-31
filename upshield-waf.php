<?php
/**
 * Plugin Name: UpShield WAF
 * Plugin URI: https://upshield.io
 * Description: High-performance Web Application Firewall for WordPress with real-time threat detection and blocking.
 * Version: 1.0.0
 * Author: UpShield Security
 * Author URI: https://upshield.io
 * License: GPLv2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: upshield-waf
 * Domain Path: /languages
 * Requires at least: 5.0
 * Tested up to: 6.9
 * Requires PHP: 7.4
 */

if (!defined('ABSPATH')) {
    exit;
}

define('UPSHIELD_VERSION', '1.0.0');
define('UPSHIELD_PLUGIN_DIR', plugin_dir_path(__FILE__));
define('UPSHIELD_PLUGIN_URL', plugin_dir_url(__FILE__));
define('UPSHIELD_PLUGIN_BASENAME', plugin_basename(__FILE__));
define('UPSHIELD_DB_VERSION', '1.1.0');

/**
 * Autoloader for plugin classes
 */
spl_autoload_register(function ($class) {
    $prefix = 'UpShield\\';
    $base_dir = UPSHIELD_PLUGIN_DIR . 'includes/';

    $len = strlen($prefix);
    if (strncmp($prefix, $class, $len) !== 0) {
        return;
    }

    $relative_class = substr($class, $len);
    
    $class_map = [
        'Waf\\WafEngine' => 'waf/class-waf-engine.php',
        'Waf\\RequestAnalyzer' => 'waf/class-request-analyzer.php',
        'Waf\\RuleMatcher' => 'waf/class-rule-matcher.php',
        'Waf\\ThreatDetector' => 'waf/class-threat-detector.php',
        'Waf\\ResponseHandler' => 'waf/class-response-handler.php',
        'Waf\\CaptchaHandler' => 'waf/class-captcha-handler.php',
        'Firewall\\IPManager' => 'firewall/class-ip-manager.php',
        'Firewall\\RateLimiter' => 'firewall/class-rate-limiter.php',
        'Firewall\\GeoLocator' => 'firewall/class-geo-locator.php',
        'Firewall\\CountryBlocker' => 'firewall/class-country-blocker.php',
        'Firewall\\EarlyBlocker' => 'firewall/class-early-blocker.php',
        'Firewall\\ThreatIntelligence' => 'firewall/class-threat-intelligence.php',
        'Firewall\\CloudflareIntegration' => 'firewall/class-cloudflare-integration.php',
        'Firewall\\IPWhitelistSync' => 'firewall/class-ip-whitelist-sync.php',
        'Firewall\\ThreatsSharing' => 'firewall/class-threats-sharing.php',
        'Scanner\\FileScanner' => 'scanner/class-file-scanner.php',
        'Scanner\\MalwareScanner' => 'scanner/class-malware-scanner.php',
        'Logging\\TrafficLogger' => 'logging/class-traffic-logger.php',
        'Integrations\\Cloudflare' => 'integrations/class-cloudflare.php',
        'Integrations\\LoginSecurity' => 'integrations/class-login-security.php',
    ];

    if (isset($class_map[$relative_class])) {
        $file = $base_dir . $class_map[$relative_class];
    } else {
        $file = $base_dir . 'class-' . strtolower(str_replace('\\', '-', $relative_class)) . '.php';
    }

    if (file_exists($file)) {
        require $file;
    }
});

/**
 * Load required files
 */
require_once UPSHIELD_PLUGIN_DIR . 'includes/class-upshield-activator.php';
require_once UPSHIELD_PLUGIN_DIR . 'includes/class-upshield-deactivator.php';

/**
 * Activation hook
 */
register_activation_hook(__FILE__, ['UpShield_Activator', 'activate']);

/**
 * Deactivation hook
 */
register_deactivation_hook(__FILE__, ['UpShield_Deactivator', 'deactivate']);

/**
 * Initialize WAF as early as possible
 */
add_action('muplugins_loaded', 'upshield_init_waf_early', -999999);
add_action('plugins_loaded', 'upshield_init_waf_early', -999999);

function upshield_init_waf_early() {
    static $initialized = false;
    if ($initialized) {
        return;
    }
    $initialized = true;

    $options = get_option('upshield_options', []);
    
    if (empty($options['waf_enabled'])) {
        return;
    }

    require_once UPSHIELD_PLUGIN_DIR . 'includes/waf/class-waf-engine.php';
    $waf = new \UpShield\Waf\WafEngine();
    $waf->init();
}

/**
 * Initialize admin and integrations
 */
add_action('plugins_loaded', 'upshield_init');

function upshield_init() {
    // Load text domain
    load_plugin_textdomain('upshield-waf', false, dirname(UPSHIELD_PLUGIN_BASENAME) . '/languages');

    // Initialize admin
    if (is_admin()) {
        require_once UPSHIELD_PLUGIN_DIR . 'admin/class-admin-dashboard.php';
        new UpShield_Admin_Dashboard();
    }

    // Initialize login security
    $options = get_option('upshield_options', []);
    if (!empty($options['login_security_enabled'])) {
        require_once UPSHIELD_PLUGIN_DIR . 'includes/integrations/class-login-security.php';
        new \UpShield\Integrations\LoginSecurity();
    }
}

/**
 * Cron schedules
 */
add_filter('cron_schedules', function ($schedules) {
    if (!isset($schedules['weekly'])) {
        $schedules['weekly'] = [
            'interval' => 7 * DAY_IN_SECONDS,
            'display' => __('Once Weekly', 'upshield-waf')
        ];
    }
    if (!isset($schedules['five_minutes'])) {
        $schedules['five_minutes'] = [
            'interval' => 5 * MINUTE_IN_SECONDS,
            'display' => __('Every 5 Minutes', 'upshield-waf')
        ];
    }
    return $schedules;
});

/**
 * Scheduled file scan
 */
add_action('upshield_file_scan_event', function () {
    require_once UPSHIELD_PLUGIN_DIR . 'includes/scanner/class-file-scanner.php';
    $scanner = new \UpShield\Scanner\FileScanner();
    $scanner->run_scan();
});

/**
 * Scheduled malware scan
 */
add_action('upshield_malware_scan_event', function () {
    require_once UPSHIELD_PLUGIN_DIR . 'includes/scanner/class-malware-scanner.php';
    $scanner = new \UpShield\Scanner\MalwareScanner();
    $options = get_option('upshield_options', []);
    $scanner->run_scan(!empty($options['scan_deep_mode']));
});

/**
 * Threat intelligence sync
 */
add_action('upshield_threat_intel_sync', function () {
    require_once UPSHIELD_PLUGIN_DIR . 'includes/firewall/class-threat-intelligence.php';
    \UpShield\Firewall\ThreatIntelligence::cron_sync();
});

/**
 * Scheduled log cleanup
 */
add_action('upshield_cleanup_logs', function () {
    require_once UPSHIELD_PLUGIN_DIR . 'includes/class-scheduled-tasks.php';
    UpShield_Scheduled_Tasks::cleanup_logs();
});

/**
 * Scheduled stats aggregation
 */
add_action('upshield_aggregate_stats', function () {
    require_once UPSHIELD_PLUGIN_DIR . 'includes/class-scheduled-tasks.php';
    UpShield_Scheduled_Tasks::aggregate_stats();
});

/**
 * Initialize cron jobs
 */
add_action('init', function () {
    // Threat Intelligence Sync (every 6 hours)
    if (!wp_next_scheduled('upshield_threat_intel_sync')) {
        wp_schedule_event(time(), 'twicedaily', 'upshield_threat_intel_sync');
    }

    // Log cleanup (daily)
    if (!wp_next_scheduled('upshield_cleanup_logs')) {
        wp_schedule_event(time(), 'daily', 'upshield_cleanup_logs');
    }

    // Stats aggregation (hourly)
    if (!wp_next_scheduled('upshield_aggregate_stats')) {
        wp_schedule_event(time(), 'hourly', 'upshield_aggregate_stats');
    }
});

/**
 * Add settings link on plugin page
 */
add_filter('plugin_action_links_' . UPSHIELD_PLUGIN_BASENAME, function ($links) {
    $settings_link = '<a href="' . admin_url('admin.php?page=upshield-waf') . '">' . __('Settings', 'upshield-waf') . '</a>';
    array_unshift($links, $settings_link);
    return $links;
});
