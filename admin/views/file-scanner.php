<?php
if (!defined('ABSPATH')) {
    exit;
}

$vswaf_options = get_option('upshield_options', []);
$vswaf_enabled = $vswaf_options['file_scanner_enabled'] ?? true;
$vswaf_schedule = $vswaf_options['file_scan_schedule'] ?? 'weekly';
// $vswaf_latest_scan is passed from controller
?>
<div class="wrap upshield-wrap" id="upshield-file-scanner">
    <div class="upshield-header">
        <div class="upshield-logo">
            <span class="dashicons dashicons-shield-alt"></span>
            <h1><?php esc_html_e('File Scanner', 'upshield-waf'); ?> <span style="font-size: 13px; color: #666; font-weight: 400; margin-left: 8px;">v<?php echo esc_html(UPSHIELD_VERSION); ?></span></h1>
        </div>
        <div class="upshield-status">
            <?php if ($vswaf_enabled): ?>
                <span class="status-badge status-active">
                    <span class="dashicons dashicons-yes-alt"></span>
                    <?php esc_html_e('Scanner Enabled', 'upshield-waf'); ?>
                </span>
            <?php else: ?>
                <span class="status-badge status-inactive">
                    <span class="dashicons dashicons-dismiss"></span>
                    <?php esc_html_e('Scanner Disabled', 'upshield-waf'); ?>
                </span>
            <?php endif; ?>
        </div>
    </div>

    <div class="upshield-card">
        <div class="card-header">
            <h2>
                <span class="dashicons dashicons-search"></span>
                <?php esc_html_e('Core Integrity Scan', 'upshield-waf'); ?>
            </h2>
            <div class="header-actions">
                <button id="upshield-run-scan" class="button button-primary" <?php disabled(!$vswaf_enabled); ?>>
                    <span class="dashicons dashicons-update"></span>
                    <?php esc_html_e('Run Scan', 'upshield-waf'); ?>
                </button>
                <button id="upshield-clear-file-history" class="button button-secondary">
                    <span class="dashicons dashicons-trash"></span>
                    <?php esc_html_e('Clear History', 'upshield-waf'); ?>
                </button>
            </div>
        </div>
        <div class="card-body">
            <p class="description">
                <?php esc_html_e('This scan checks WordPress core files against official checksums to detect modifications or unknown files in core directories (wp-admin, wp-includes).', 'upshield-waf'); ?>
            </p>
            <div class="scan-meta">
                <div><strong><?php esc_html_e('Schedule:', 'upshield-waf'); ?></strong> <?php echo esc_html(ucfirst($vswaf_schedule)); ?></div>
                <div><strong><?php esc_html_e('Last Scan:', 'upshield-waf'); ?></strong>
                    <?php
                    if (is_array($vswaf_latest_scan) && !empty($vswaf_latest_scan['finished_at'])) {
                        require_once UPSHIELD_PLUGIN_DIR . 'includes/class-upshield-helpers.php';
                        echo esc_html(\UpShield_Helpers::format_timestamp($vswaf_latest_scan['finished_at'], 'Y-m-d H:i:s'));
                    } else {
                        esc_html_e('Never', 'upshield-waf');
                    }
                    ?>
                </div>
            </div>
        </div>
    </div>

    <div class="upshield-stats-grid" id="upshield-scan-stats">
        <div class="stat-card stat-total">
            <div class="stat-icon">
                <span class="dashicons dashicons-forms"></span>
            </div>
            <div class="stat-content">
                <div class="stat-value" id="scan-total-files">0</div>
                <div class="stat-label"><?php esc_html_e('Total Core Files', 'upshield-waf'); ?></div>
            </div>
        </div>
        <div class="stat-card stat-success">
            <div class="stat-icon">
                <span class="dashicons dashicons-yes-alt"></span>
            </div>
            <div class="stat-content">
                <div class="stat-value" id="scan-ok-files">0</div>
                <div class="stat-label"><?php esc_html_e('Files OK', 'upshield-waf'); ?></div>
            </div>
        </div>
        <div class="stat-card stat-blocked">
            <div class="stat-icon">
                <span class="dashicons dashicons-warning"></span>
            </div>
            <div class="stat-content">
                <div class="stat-value" id="scan-modified-files">0</div>
                <div class="stat-label"><?php esc_html_e('Modified Files', 'upshield-waf'); ?></div>
            </div>
        </div>
        <div class="stat-card stat-info" title="<?php esc_attr_e('Missing files are counted but not logged (most are intentionally removed)', 'upshield-waf'); ?>">
            <div class="stat-icon">
                <span class="dashicons dashicons-info"></span>
            </div>
            <div class="stat-content">
                <div class="stat-value" id="scan-missing-files">0</div>
                <div class="stat-label"><?php esc_html_e('Missing (Info Only)', 'upshield-waf'); ?></div>
            </div>
        </div>
        <div class="stat-card stat-ips">
            <div class="stat-icon">
                <span class="dashicons dashicons-visibility"></span>
            </div>
            <div class="stat-content">
                <div class="stat-value" id="scan-unknown-files">0</div>
                <div class="stat-label"><?php esc_html_e('Unknown Files', 'upshield-waf'); ?></div>
            </div>
        </div>
    </div>

    <div class="upshield-card">
        <div class="card-header">
            <h2>
                <span class="dashicons dashicons-list-view"></span>
                <?php esc_html_e('Scan Results', 'upshield-waf'); ?>
            </h2>
            <div class="header-actions">
                <select id="scan-status-filter">
                    <option value=""><?php esc_html_e('All Issues', 'upshield-waf'); ?></option>
                    <option value="modified"><?php esc_html_e('Modified', 'upshield-waf'); ?></option>
                    <option value="unknown"><?php esc_html_e('Unknown', 'upshield-waf'); ?></option>
                </select>
            </div>
        </div>
        <div class="card-body">
            <table class="upshield-table" id="scan-results-table">
                <thead>
                    <tr>
                        <th><?php esc_html_e('Status', 'upshield-waf'); ?></th>
                        <th><?php esc_html_e('File Path', 'upshield-waf'); ?></th>
                        <th><?php esc_html_e('Expected Hash', 'upshield-waf'); ?></th>
                        <th><?php esc_html_e('Actual Hash', 'upshield-waf'); ?></th>
                        <th><?php esc_html_e('Size', 'upshield-waf'); ?></th>
                        <th><?php esc_html_e('Modified Time', 'upshield-waf'); ?></th>
                    </tr>
                </thead>
                <tbody>
                    <tr class="empty-row">
                        <td colspan="6"><?php esc_html_e('No scan results yet. Run a scan to view findings.', 'upshield-waf'); ?></td>
                    </tr>
                </tbody>
            </table>
            <div class="scan-pagination" id="scan-pagination"></div>
        </div>
    </div>
    
    <?php include UPSHIELD_PLUGIN_DIR . 'admin/views/partials/footer.php'; ?>
</div>
