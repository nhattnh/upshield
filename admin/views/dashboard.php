<?php
if (!defined('ABSPATH')) {
    exit;
}

$vswaf_totals = $stats['totals'] ?? [];
$vswaf_threat_intel_synced = $threat_intel_synced ?? 0;
$vswaf_threat_intel_blocked = $threat_intel_blocked ?? 0;
$vswaf_recent_attacks = $recent_attacks ?? [];
$vswaf_top_ips = $top_ips ?? [];
?>
<div class="wrap upshield-wrap">
    <div class="upshield-header">
        <div class="upshield-logo">
            <span class="dashicons dashicons-shield"></span>
            <h1><?php esc_html_e('UpShield WAF', 'upshield-waf'); ?> <span style="font-size: 13px; color: #666; font-weight: 400; margin-left: 8px;">v<?php echo esc_html(UPSHIELD_VERSION); ?></span></h1>
        </div>
        <div class="upshield-status">
            <?php if ($this->options['waf_enabled'] ?? true): ?>
                <span class="status-badge status-active">
                    <span class="dashicons dashicons-yes-alt"></span>
                    <?php esc_html_e('Protection Active', 'upshield-waf'); ?>
                </span>
            <?php else: ?>
                <span class="status-badge status-inactive">
                    <span class="dashicons dashicons-dismiss"></span>
                    <?php esc_html_e('Protection Disabled', 'upshield-waf'); ?>
                </span>
            <?php endif; ?>
            <span class="firewall-mode">
                <?php 
                $vswaf_mode = $this->options['firewall_mode'] ?? 'protecting';
                // Backward compatibility: map old values to new
                if ($vswaf_mode === 'extended') {
                    $vswaf_mode = 'protecting';
                }
                $vswaf_mode_labels = [
                    'learning' => __('Learning Mode', 'upshield-waf'),
                    'protecting' => __('Protecting Mode - Block threats and Logging', 'upshield-waf'),
                ];
                echo esc_html($vswaf_mode_labels[$vswaf_mode] ?? $vswaf_mode);
                ?>
            </span>
        </div>
    </div>

    <!-- Stats Cards -->
    <div class="upshield-stats-grid">
        <div class="stat-card stat-total">
            <div class="stat-icon">
                <span class="dashicons dashicons-visibility"></span>
            </div>
            <div class="stat-content">
                <div class="stat-value"><?php echo number_format($vswaf_totals['total_requests'] ?? 0); ?></div>
                <div class="stat-label"><?php esc_html_e('Total Requests', 'upshield-waf'); ?></div>
            </div>
        </div>
        
        <div class="stat-card stat-blocked">
            <div class="stat-icon">
                <span class="dashicons dashicons-shield-alt"></span>
            </div>
            <div class="stat-content">
                <div class="stat-value"><?php echo number_format($vswaf_totals['blocked'] ?? 0); ?></div>
                <div class="stat-label"><?php esc_html_e('Attacks Blocked', 'upshield-waf'); ?></div>
            </div>
        </div>
        
        <div class="stat-card stat-intelligence">
            <div class="stat-icon">
                <span class="dashicons dashicons-networking"></span>
            </div>
            <div class="stat-content">
                <div class="stat-value"><?php echo number_format($vswaf_threat_intel_synced); ?></div>
                <div class="stat-label"><?php esc_html_e('Intelligence Threats', 'upshield-waf'); ?></div>
            </div>
        </div>
        
        <div class="stat-card stat-intelligence-blocked">
            <div class="stat-icon">
                <span class="dashicons dashicons-shield"></span>
            </div>
            <div class="stat-content">
                <div class="stat-value"><?php echo number_format($vswaf_threat_intel_blocked); ?></div>
                <div class="stat-label"><?php esc_html_e('Intelligence Blocked', 'upshield-waf'); ?></div>
            </div>
        </div>
    </div>

    <!-- Main Content Grid -->
    <div class="upshield-content-grid">
        <!-- Recent Attacks -->
        <div class="upshield-card">
            <div class="card-header">
                <h2>
                    <span class="dashicons dashicons-warning"></span>
                    <?php esc_html_e('Recent Attacks', 'upshield-waf'); ?>
                </h2>
                <a href="<?php echo esc_url(admin_url('admin.php?page=upshield-traffic')); ?>" class="button button-small">
                    <?php esc_html_e('View All', 'upshield-waf'); ?>
                </a>
            </div>
            <div class="card-body">
                <?php if (empty($vswaf_recent_attacks)): ?>
                    <div class="empty-state">
                        <span class="dashicons dashicons-yes-alt"></span>
                        <p><?php esc_html_e('No attacks detected recently. Your site is safe!', 'upshield-waf'); ?></p>
                    </div>
                <?php else: ?>
                    <table class="upshield-table">
                        <thead>
                            <tr>
                                <th><?php esc_html_e('Time', 'upshield-waf'); ?></th>
                                <th><?php esc_html_e('IP', 'upshield-waf'); ?></th>
                                <th><?php esc_html_e('Type', 'upshield-waf'); ?></th>
                                <th><?php esc_html_e('Severity', 'upshield-waf'); ?></th>
                                <th><?php esc_html_e('Action', 'upshield-waf'); ?></th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($vswaf_recent_attacks as $vswaf_attack): ?>
                                <tr>
                                    <td class="time-col">
                                        <?php 
                                        require_once UPSHIELD_PLUGIN_DIR . 'includes/class-upshield-helpers.php';
                                        $vswaf_formatted_time = UpShield_Helpers::format_timestamp($vswaf_attack['timestamp'], 'Y-m-d H:i:s');
                                        echo esc_html($vswaf_formatted_time);
                                        ?>
                                    </td>
                                    <td class="ip-col">
                                        <code><?php echo esc_html($vswaf_attack['ip']); ?></code>
                                    </td>
                                    <td class="type-col">
                                        <?php 
                                        $vswaf_attack_type = $vswaf_attack['attack_type'];
                                        // For rate_limited with no attack_type, show the action
                                        if (empty($vswaf_attack_type) && $vswaf_attack['action'] === 'rate_limited') {
                                            $vswaf_attack_type = 'rate_limit';
                                        }
                                        ?>
                                        <span class="attack-type type-<?php echo esc_attr($vswaf_attack_type ?: 'unknown'); ?>">
                                            <?php echo esc_html(strtoupper($vswaf_attack_type ?: 'UNKNOWN')); ?>
                                        </span>
                                    </td>
                                    <td class="severity-col">
                                        <span class="severity severity-<?php echo esc_attr($vswaf_attack['severity']); ?>">
                                            <?php echo esc_html(ucfirst($vswaf_attack['severity'])); ?>
                                        </span>
                                    </td>
                                    <td class="action-col">
                                        <?php if ($vswaf_attack['ip_status'] === 'whitelisted'): ?>
                                            <span class="dashicons dashicons-yes" title="<?php esc_attr_e('Whitelisted', 'upshield-waf'); ?>" style="color: #46b450;"></span>
                                        <?php elseif ($vswaf_attack['ip_status'] === 'blacklisted'): ?>
                                            <button class="button button-small unblock-ip-btn button-link-delete" 
                                                    data-ip="<?php echo esc_attr($vswaf_attack['ip']); ?>">
                                                <?php esc_html_e('Unblock', 'upshield-waf'); ?>
                                            </button>
                                        <?php elseif ($vswaf_attack['ip_status'] === 'temporary'): ?>
                                            <button class="button button-small unblock-ip-btn button-link-delete" 
                                                    data-ip="<?php echo esc_attr($vswaf_attack['ip']); ?>" 
                                                    style="margin-bottom: 2px;">
                                                <?php esc_html_e('Unblock', 'upshield-waf'); ?>
                                            </button>
                                            <button class="button button-small block-ip-btn" 
                                                    data-ip="<?php echo esc_attr($vswaf_attack['ip']); ?>">
                                                <?php esc_html_e('Blacklist', 'upshield-waf'); ?>
                                            </button>
                                        <?php else: ?>
                                            <button class="button button-small block-ip-btn" 
                                                    data-ip="<?php echo esc_attr($vswaf_attack['ip']); ?>">
                                                <?php esc_html_e('Block IP', 'upshield-waf'); ?>
                                            </button>
                                        <?php endif; ?>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                <?php endif; ?>
            </div>
        </div>

        <!-- Top Blocked IPs -->
        <div class="upshield-card">
            <div class="card-header">
                <h2>
                    <span class="dashicons dashicons-admin-users"></span>
                    <?php esc_html_e('Top Blocked IPs', 'upshield-waf'); ?>
                </h2>
            </div>
            <div class="card-body">
                <?php if (empty($vswaf_top_ips)): ?>
                    <div class="empty-state">
                        <span class="dashicons dashicons-yes-alt"></span>
                        <p><?php esc_html_e('No IPs have been blocked yet.', 'upshield-waf'); ?></p>
                    </div>
                <?php else: ?>
                    <table class="upshield-table">
                        <thead>
                            <tr>
                                <th><?php esc_html_e('IP Address', 'upshield-waf'); ?></th>
                                <th><?php esc_html_e('Blocks', 'upshield-waf'); ?></th>
                                <th><?php esc_html_e('Attack Types', 'upshield-waf'); ?></th>
                                <th><?php esc_html_e('Action', 'upshield-waf'); ?></th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($vswaf_top_ips as $vswaf_ip_data): ?>
                                <tr>
                                    <td class="ip-col">
                                        <code><?php echo esc_html($vswaf_ip_data['ip']); ?></code>
                                    </td>
                                    <td class="count-col">
                                        <strong><?php echo esc_html($vswaf_ip_data['block_count']); ?></strong>
                                    </td>
                                    <td class="types-col">
                                        <?php 
                                        $vswaf_types = array_filter(explode(',', $vswaf_ip_data['attack_types'] ?? ''));
                                        $vswaf_actions = array_filter(explode(',', $vswaf_ip_data['actions'] ?? ''));
                                        
                                        // If no attack types but has rate_limited action
                                        if (empty($vswaf_types) && in_array('rate_limited', $vswaf_actions)) {
                                            $vswaf_types = ['rate_limit'];
                                        }
                                        
                                        if (empty($vswaf_types)) {
                                            $vswaf_types = ['unknown'];
                                        }
                                        
                                        foreach ($vswaf_types as $vswaf_type): 
                                        ?>
                                            <span class="attack-type type-<?php echo esc_attr($vswaf_type); ?>">
                                                <?php echo esc_html(strtoupper($vswaf_type)); ?>
                                            </span>
                                        <?php endforeach; ?>
                                    </td>
                                    <td class="action-col">
                                        <button class="button button-small block-ip-btn" 
                                                data-ip="<?php echo esc_attr($vswaf_ip_data['ip']); ?>">
                                            <?php esc_html_e('Permanent Block', 'upshield-waf'); ?>
                                        </button>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                <?php endif; ?>
            </div>
        </div>
    </div>

    <!-- Quick Actions -->
    <div class="upshield-card">
        <div class="card-header">
            <h2>
                <span class="dashicons dashicons-admin-tools"></span>
                <?php esc_html_e('Quick Actions', 'upshield-waf'); ?>
            </h2>
        </div>
        <div class="card-body">
            <div class="quick-actions">
                <a href="<?php echo esc_url(admin_url('admin.php?page=upshield-settings')); ?>" class="quick-action">
                    <span class="dashicons dashicons-admin-settings"></span>
                    <span><?php esc_html_e('Configure Settings', 'upshield-waf'); ?></span>
                </a>
                <a href="<?php echo esc_url(admin_url('admin.php?page=upshield-firewall')); ?>" class="quick-action">
                    <span class="dashicons dashicons-list-view"></span>
                    <span><?php esc_html_e('Manage IP Lists', 'upshield-waf'); ?></span>
                </a>
                <a href="<?php echo esc_url(admin_url('admin.php?page=upshield-traffic')); ?>" class="quick-action">
                    <span class="dashicons dashicons-chart-area"></span>
                    <span><?php esc_html_e('View Live Traffic', 'upshield-waf'); ?></span>
                </a>
                <button class="quick-action" id="clear-logs-btn">
                    <span class="dashicons dashicons-trash"></span>
                    <span><?php esc_html_e('Clear All Logs', 'upshield-waf'); ?></span>
                </button>
            </div>
        </div>
    </div>
    
    <?php include UPSHIELD_PLUGIN_DIR . 'admin/views/partials/footer.php'; ?>
</div>
