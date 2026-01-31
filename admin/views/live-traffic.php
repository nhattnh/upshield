<?php
if (!defined('ABSPATH')) {
    exit;
}
?>
<div class="wrap upshield-wrap">
    <div class="upshield-header">
        <div class="upshield-logo">
            <span class="dashicons dashicons-shield"></span>
            <h1><?php esc_html_e('Live Traffic', 'upshield-waf'); ?> <span style="font-size: 13px; color: #666; font-weight: 400; margin-left: 8px;">v<?php echo esc_html(UPSHIELD_VERSION); ?></span></h1>
        </div>
        <div class="header-actions">
            <button id="toggle-live" class="button button-primary">
                <span class="dashicons dashicons-controls-pause"></span>
                <?php esc_html_e('Pause', 'upshield-waf'); ?>
            </button>
            <button id="clear-logs-btn" class="button">
                <span class="dashicons dashicons-trash"></span>
                <?php esc_html_e('Clear Logs', 'upshield-waf'); ?>
            </button>
        </div>
    </div>

    <!-- Filters -->
    <div class="upshield-card">
        <div class="card-body">
            <div class="traffic-filters">
                <div class="filter-group">
                    <label for="filter-action"><?php esc_html_e('Action', 'upshield-waf'); ?></label>
                    <select id="filter-action">
                        <option value=""><?php esc_html_e('All', 'upshield-waf'); ?></option>
                        <option value="blocked"><?php esc_html_e('Blocked', 'upshield-waf'); ?></option>
                        <option value="allowed"><?php esc_html_e('Allowed', 'upshield-waf'); ?></option>
                        <option value="monitored"><?php esc_html_e('Monitored', 'upshield-waf'); ?></option>
                        <option value="rate_limited"><?php esc_html_e('Rate Limited', 'upshield-waf'); ?></option>
                    </select>
                </div>
                <div class="filter-group">
                    <label for="filter-type"><?php esc_html_e('Attack Type', 'upshield-waf'); ?></label>
                    <select id="filter-type">
                        <option value=""><?php esc_html_e('All', 'upshield-waf'); ?></option>
                        <option value="sqli"><?php esc_html_e('SQL Injection', 'upshield-waf'); ?></option>
                        <option value="xss"><?php esc_html_e('XSS', 'upshield-waf'); ?></option>
                        <option value="rce"><?php esc_html_e('RCE', 'upshield-waf'); ?></option>
                        <option value="lfi"><?php esc_html_e('LFI', 'upshield-waf'); ?></option>
                        <option value="bad_bot"><?php esc_html_e('Bad Bot', 'upshield-waf'); ?></option>
                        <option value="brute_force"><?php esc_html_e('Brute Force', 'upshield-waf'); ?></option>
                        <option value="threat_intel"><?php esc_html_e('Threat Intelligence', 'upshield-waf'); ?></option>
                        <option value="enumeration"><?php esc_html_e('Enumeration', 'upshield-waf'); ?></option>
                        <option value="rate_limit"><?php esc_html_e('Rate Limit', 'upshield-waf'); ?></option>
                        <option value="xmlrpc"><?php esc_html_e('XML-RPC', 'upshield-waf'); ?></option>
                        <option value="ssrf"><?php esc_html_e('SSRF', 'upshield-waf'); ?></option>
                    </select>
                </div>
                <div class="filter-group">
                    <label for="filter-ip"><?php esc_html_e('IP Address', 'upshield-waf'); ?></label>
                    <input type="text" id="filter-ip" placeholder="<?php esc_attr_e('Filter by IP', 'upshield-waf'); ?>">
                </div>
                <div class="filter-group">
                    <label for="filter-block-id"><?php esc_html_e('Block ID', 'upshield-waf'); ?></label>
                    <input type="text" id="filter-block-id" placeholder="<?php esc_attr_e('Filter by Block ID', 'upshield-waf'); ?>">
                </div>
                <div class="filter-group">
                    <label for="filter-search"><?php esc_html_e('Search', 'upshield-waf'); ?></label>
                    <input type="text" id="filter-search" placeholder="<?php esc_attr_e('Search in URI, UA...', 'upshield-waf'); ?>">
                </div>
                <div class="filter-group">
                    <label>&nbsp;</label>
                    <button id="apply-filters" class="button"><?php esc_html_e('Apply Filters', 'upshield-waf'); ?></button>
                </div>
            </div>
        </div>
    </div>

    <!-- Traffic Table -->
    <div class="upshield-card">
        <div class="card-body">
            <div id="live-traffic-status" class="live-status">
                <span class="status-dot live"></span>
                <span class="status-text"><?php esc_html_e('Live - Auto-refreshing every 5 seconds', 'upshield-waf'); ?></span>
            </div>
            
            <div class="table-responsive">
                <table class="upshield-table traffic-table" id="traffic-table">
                    <thead>
                        <tr>
                            <th class="col-time"><?php esc_html_e('Time', 'upshield-waf'); ?></th>
                            <th class="col-ip"><?php esc_html_e('IP', 'upshield-waf'); ?></th>
                            <th class="col-country"><?php esc_html_e('Country', 'upshield-waf'); ?></th>
                            <th class="col-asn-number"><?php esc_html_e('ASN Number', 'upshield-waf'); ?></th>
                            <th class="col-asn-name"><?php esc_html_e('ASN Name', 'upshield-waf'); ?></th>
                            <th class="col-method"><?php esc_html_e('Method', 'upshield-waf'); ?></th>
                            <th class="col-uri"><?php esc_html_e('URI', 'upshield-waf'); ?></th>
                            <th class="col-action"><?php esc_html_e('Action', 'upshield-waf'); ?></th>
                            <th class="col-type"><?php esc_html_e('Type', 'upshield-waf'); ?></th>
                            <th class="col-block-id"><?php esc_html_e('Block ID', 'upshield-waf'); ?></th>
                            <th class="col-actions"><?php esc_html_e('Actions', 'upshield-waf'); ?></th>
                        </tr>
                    </thead>
                    <tbody id="traffic-body">
                        <tr class="loading-row">
                            <td colspan="11">
                                <span class="spinner is-active"></span>
                                <?php esc_html_e('Loading traffic data...', 'upshield-waf'); ?>
                            </td>
                        </tr>
                    </tbody>
                </table>
            </div>

            <!-- Pagination -->
            <div class="traffic-pagination">
                <button id="prev-page" class="button" disabled>&laquo; <?php esc_html_e('Previous', 'upshield-waf'); ?></button>
                <span id="page-info"><?php esc_html_e('Page 1', 'upshield-waf'); ?></span>
                <button id="next-page" class="button"><?php esc_html_e('Next', 'upshield-waf'); ?> &raquo;</button>
            </div>
        </div>
    </div>

    <!-- Request Details Modal -->
    <div id="request-modal" class="upshield-modal" style="display:none;">
        <div class="modal-overlay"></div>
        <div class="modal-content">
            <div class="modal-header">
                <h3><?php esc_html_e('Request Details', 'upshield-waf'); ?></h3>
                <button class="modal-close" type="button">&times;</button>
            </div>
            <div class="modal-body" id="request-details">
                <!-- Details loaded via AJAX -->
            </div>
        </div>
    </div>
</div>



    <?php include UPSHIELD_PLUGIN_DIR . 'admin/views/partials/footer.php'; ?>
</div>
