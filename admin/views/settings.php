<?php
if (!defined('ABSPATH')) {
    exit;
}

// Get options
$vswaf_options = get_option('upshield_options', []);
$vswaf_needs_update = false;

// Initialize Early Blocker (logic only, no UI stats needed)
// Early Blocker is handled internally by the firewall based on settings

// Ensure default values for new options
if (!isset($vswaf_options['firewall_mode'])) {
    $vswaf_options['firewall_mode'] = 'protecting';
    $vswaf_needs_update = true;
}

if (!isset($vswaf_options['early_blocking_enabled'])) {
    $vswaf_options['early_blocking_enabled'] = false; 
    $vswaf_needs_update = true;
}

// Update options if needed
if ($vswaf_needs_update) {
    update_option('upshield_options', $vswaf_options);
}

// Get firewall mode for display logic
$vswaf_firewall_mode = $vswaf_options['firewall_mode'];
$vswaf_early_blocking_enabled = $vswaf_options['early_blocking_enabled'];
?>
<div class="wrap upshield-wrap">
    <div class="upshield-header">
        <div class="upshield-logo">
            <span class="dashicons dashicons-shield"></span>
            <h1><?php esc_html_e('UpShield WAF Settings', 'upshield-waf'); ?> <span style="font-size: 13px; color: #666; font-weight: 400; margin-left: 8px;">v<?php echo esc_html(UPSHIELD_VERSION); ?></span></h1>
        </div>
        <div class="upshield-header-actions">
            <button type="submit" form="upshield-settings-form" class="button button-primary">
                <span class="dashicons dashicons-yes"></span>
                <?php esc_html_e('Save Settings', 'upshield-waf'); ?>
            </button>
        </div>
    </div>

    <div class="upshield-tabs">
        <a href="#general" class="tab-btn active">
            <span class="dashicons dashicons-admin-settings"></span>
            <?php esc_html_e('General', 'upshield-waf'); ?>
        </a>
        <a href="#firewall" class="tab-btn">
            <span class="dashicons dashicons-shield"></span>
            <?php esc_html_e('Firewall', 'upshield-waf'); ?>
        </a>
        <a href="#captcha" class="tab-btn">
            <span class="dashicons dashicons-lock"></span>
            <?php esc_html_e('CAPTCHA', 'upshield-waf'); ?>
        </a>
        <a href="#login" class="tab-btn">
            <span class="dashicons dashicons-admin-users"></span>
            <?php esc_html_e('Login Security', 'upshield-waf'); ?>
        </a>
        <a href="#scanner" class="tab-btn">
            <span class="dashicons dashicons-search"></span>
            <?php esc_html_e('Scanners', 'upshield-waf'); ?>
        </a>
        <a href="#advanced" class="tab-btn">
            <span class="dashicons dashicons-admin-tools"></span>
            <?php esc_html_e('Advanced', 'upshield-waf'); ?>
        </a>
        <a href="#threat-intel" class="tab-btn">
            <span class="dashicons dashicons-admin-site-alt3"></span>
            <?php esc_html_e('Threat Intel', 'upshield-waf'); ?>
        </a>
        <a href="#about" class="tab-btn">
            <span class="dashicons dashicons-info"></span>
            <?php esc_html_e('About', 'upshield-waf'); ?>
        </a>
        <a href="#telegram" class="tab-btn">
            <span class="dashicons dashicons-format-chat"></span>
            <?php esc_html_e('Telegram', 'upshield-waf'); ?>
            <span class="badge badge-new">NEW</span>
        </a>
        <a href="#two-factor" class="tab-btn">
            <span class="dashicons dashicons-smartphone"></span>
            <?php esc_html_e('2FA', 'upshield-waf'); ?>
            <span class="badge badge-new">NEW</span>
        </a>
        <a href="#security-headers" class="tab-btn">
            <span class="dashicons dashicons-admin-network"></span>
            <?php esc_html_e('Headers', 'upshield-waf'); ?>
            <span class="badge badge-new">NEW</span>
        </a>
    </div>

    <form method="post" action="options.php" id="upshield-settings-form">
        <?php settings_fields('upshield_options'); ?>
        
        <!-- General Settings -->
        <div class="upshield-tab-content active" id="general">
            <div class="upshield-card">
                <div class="card-header">
                    <h2>
                        <span class="dashicons dashicons-admin-settings"></span>
                        <?php esc_html_e('General Configuration', 'upshield-waf'); ?>
                    </h2>
                </div>
                <div class="card-body">
                    <table class="form-table">
                        <tr>
                            <th scope="row"><?php esc_html_e('WAF Status', 'upshield-waf'); ?></th>
                            <td>
                                <label class="upshield-switch">
                                    <input type="checkbox" name="upshield_options[waf_enabled]" value="1" 
                                           <?php checked($vswaf_options['waf_enabled'] ?? false); ?>>
                                    <span class="slider"></span>
                                </label>
                                <p class="description"><?php esc_html_e('Enable or disable the entire Web Application Firewall.', 'upshield-waf'); ?></p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><?php esc_html_e('Firewall Mode', 'upshield-waf'); ?></th>
                            <td>
                                <div class="upshield-radio-group">
                                    <label class="radio-card <?php echo $vswaf_firewall_mode === 'protecting' ? 'active' : ''; ?>">
                                        <input type="radio" name="upshield_options[firewall_mode]" value="protecting" 
                                               <?php checked($vswaf_firewall_mode, 'protecting'); ?>>
                                        <div class="radio-icon">
                                            <span class="dashicons dashicons-shield"></span>
                                        </div>
                                        <div class="radio-content">
                                            <div class="radio-header">
                                                <strong><?php esc_html_e('Protection Mode', 'upshield-waf'); ?></strong>
                                                <span class="badge badge-pro">Pro</span>
                                                <span class="radio-check dashicons dashicons-yes"></span>
                                            </div>
                                            <p><?php esc_html_e('Blocks known attacks and malicious traffic. Recommended for live sites.', 'upshield-waf'); ?></p>
                                        </div>
                                    </label>
                                    <label class="radio-card <?php echo $vswaf_firewall_mode === 'learning' ? 'active' : ''; ?>">
                                        <input type="radio" name="upshield_options[firewall_mode]" value="learning" 
                                               <?php checked($vswaf_firewall_mode, 'learning'); ?>>
                                        <div class="radio-icon">
                                            <span class="dashicons dashicons-welcome-learn-more"></span>
                                        </div>
                                        <div class="radio-content">
                                            <div class="radio-header">
                                                <strong><?php esc_html_e('Learning Mode', 'upshield-waf'); ?></strong>
                                                <span class="radio-check dashicons dashicons-yes"></span>
                                            </div>
                                            <p><?php esc_html_e('Logs attacks but does not block them. Use this to test for false positives.', 'upshield-waf'); ?></p>
                                        </div>
                                    </label>
                                </div>
                                </div>
                            </td>
                        </tr>

                        <tr>
                            <th scope="row"><?php esc_html_e('Email Alerts', 'upshield-waf'); ?></th>
                            <td>
                                <label class="upshield-switch">
                                    <input type="checkbox" name="upshield_options[email_alerts]" value="1" 
                                           <?php checked($vswaf_options['email_alerts'] ?? false); ?>>
                                    <span class="slider"></span>
                                </label>
                                <p class="description"><?php esc_html_e('Receive email notifications for critical security events.', 'upshield-waf'); ?></p>
                                
                                <div class="dependent-field" style="margin-top: 10px;">
                                    <input type="email" name="upshield_options[alert_email]" 
                                           value="<?php echo esc_attr($vswaf_options['alert_email'] ?? get_option('admin_email')); ?>" 
                                           class="regular-text" placeholder="admin@example.com">
                                    <p class="description"><?php esc_html_e('Email address to send alerts to.', 'upshield-waf'); ?></p>
                                </div>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><?php esc_html_e('Whitelist Admins', 'upshield-waf'); ?></th>
                            <td>
                                <label class="upshield-switch">
                                    <input type="checkbox" name="upshield_options[whitelist_admins]" value="1" 
                                           <?php checked($vswaf_options['whitelist_admins'] ?? true); ?>>
                                    <span class="slider"></span>
                                </label>
                                <p class="description"><?php esc_html_e('Automatically whitelist logged-in administrators (recommended).', 'upshield-waf'); ?></p>
                            </td>
                        </tr>
                    </table>
                </div>
            </div>
        </div>

        <!-- Firewall Protection -->
        <div class="upshield-tab-content" id="firewall">
            <div class="upshield-card">
                <div class="card-header">
                    <h2>
                        <span class="dashicons dashicons-shield-alt"></span>
                        <?php esc_html_e('Attack Protection', 'upshield-waf'); ?>
                    </h2>
                </div>
                <div class="card-body">
                    <p class="description mb-20">
                        <?php esc_html_e('Configure which types of attacks UpShield should block.', 'upshield-waf'); ?>
                    </p>
                    
                    <table class="form-table">
                        <tr>
                            <th scope="row"><?php esc_html_e('SQL Injection (SQLi)', 'upshield-waf'); ?></th>
                            <td>
                                <label class="upshield-switch">
                                    <input type="checkbox" name="upshield_options[block_sqli]" value="1" 
                                           <?php checked($vswaf_options['block_sqli'] ?? true); ?>>
                                    <span class="slider"></span>
                                </label>
                                <p class="description"><?php esc_html_e('Block attempts to inject malicious SQL commands.', 'upshield-waf'); ?></p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><?php esc_html_e('Cross-Site Scripting (XSS)', 'upshield-waf'); ?></th>
                            <td>
                                <label class="upshield-switch">
                                    <input type="checkbox" name="upshield_options[block_xss]" value="1" 
                                           <?php checked($vswaf_options['block_xss'] ?? true); ?>>
                                    <span class="slider"></span>
                                </label>
                                <p class="description"><?php esc_html_e('Block attempts to inject malicious scripts.', 'upshield-waf'); ?></p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><?php esc_html_e('Remote Code Execution (RCE)', 'upshield-waf'); ?></th>
                            <td>
                                <label class="upshield-switch">
                                    <input type="checkbox" name="upshield_options[block_rce]" value="1" 
                                           <?php checked($vswaf_options['block_rce'] ?? false); ?>>
                                    <span class="slider"></span>
                                </label>
                                <p class="description">
                                    <?php esc_html_e('Block attempts to execute arbitrary code on the server.', 'upshield-waf'); ?>
                                    <strong><?php esc_html_e('Note:', 'upshield-waf'); ?></strong>
                                    <?php esc_html_e('This is disabled by default to avoid false positives with Google Ads. Enable with caution and configure whitelist patterns below.', 'upshield-waf'); ?>
                                </p>
                                
                                <div class="dependent-field" style="margin-top: 15px; <?php echo empty($vswaf_options['block_rce']) ? 'display: none;' : ''; ?>" id="rce-whitelist-section">
                                    <h4 style="margin-top: 0; margin-bottom: 10px;"><?php esc_html_e('RCE Whitelist Patterns', 'upshield-waf'); ?></h4>
                                    <p class="description" style="margin-bottom: 10px;"><?php esc_html_e('Add regex patterns to whitelist legitimate traffic (e.g., Google Ads parameters). One pattern per line.', 'upshield-waf'); ?></p>
                                    <textarea name="upshield_options[rce_whitelist_patterns]" 
                                              rows="8" 
                                              class="large-text code" 
                                              placeholder="/gclid=/i&#10;/utm_source=/i&#10;/safeframe\.googlesyndication\.com/i"><?php 
                                        $rce_patterns = $vswaf_options['rce_whitelist_patterns'] ?? [];
                                        if (is_array($rce_patterns)) {
                                            echo esc_textarea(implode("\n", $rce_patterns));
                                        }
                                    ?></textarea>
                                    <p class="description" style="margin-top: 5px;">
                                        <?php esc_html_e('Default patterns include Google Ads (gclid, utm_*, gad_*), Google SafeFrame, and common tracking parameters.', 'upshield-waf'); ?>
                                    </p>
                                </div>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><?php esc_html_e('Local File Inclusion (LFI)', 'upshield-waf'); ?></th>
                            <td>
                                <label class="upshield-switch">
                                    <input type="checkbox" name="upshield_options[block_lfi]" value="1" 
                                           <?php checked($vswaf_options['block_lfi'] ?? true); ?>>
                                    <span class="slider"></span>
                                </label>
                                <p class="description"><?php esc_html_e('Block attempts to access local files (e.g., /etc/passwd).', 'upshield-waf'); ?></p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><?php esc_html_e('Bad Bots & Crawlers', 'upshield-waf'); ?></th>
                            <td>
                                <label class="upshield-switch">
                                    <input type="checkbox" name="upshield_options[block_bad_bots]" value="1" 
                                           <?php checked($vswaf_options['block_bad_bots'] ?? true); ?>>
                                    <span class="slider"></span>
                                </label>
                                <p class="description"><?php esc_html_e('Block known bad bots, scrapers, and aggressive crawlers.', 'upshield-waf'); ?></p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><?php esc_html_e('XML-RPC Protection', 'upshield-waf'); ?></th>
                            <td>
                                <label class="upshield-switch">
                                    <input type="checkbox" name="upshield_options[block_xmlrpc]" value="1" 
                                           <?php checked($vswaf_options['block_xmlrpc'] ?? false); ?>>
                                    <span class="slider"></span>
                                </label>
                                <p class="description"><?php esc_html_e('Block all XML-RPC requests (pingbacks, remote publishing). Recommended if you don\'t use the WordPress app or Jetpack.', 'upshield-waf'); ?></p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><?php esc_html_e('Block Author Enumeration', 'upshield-waf'); ?></th>
                            <td>
                                <label class="upshield-switch">
                                    <input type="checkbox" name="upshield_options[block_author_scan]" value="1" 
                                           <?php checked($vswaf_options['block_author_scan'] ?? true); ?>>
                                    <span class="slider"></span>
                                </label>
                                <p class="description"><?php esc_html_e('Block attempts to enumerate users via ?author=N queries and REST API.', 'upshield-waf'); ?></p>
                            </td>
                        </tr>
                    </table>
                </div>
            </div>

            <!-- Country Blocking -->
            <div class="upshield-card">
                <div class="card-header">
                    <h2>
                        <span class="dashicons dashicons-admin-site-alt"></span>
                        <?php esc_html_e('Country Blocking', 'upshield-waf'); ?>
                    </h2>
                </div>
                <div class="card-body">
                    <p class="description mb-20">
                        <?php esc_html_e('Block or allow requests based on geographic location. Uses IP geolocation to determine visitor country.', 'upshield-waf'); ?>
                    </p>
                    <table class="form-table">
                        <tr>
                            <th scope="row"><?php esc_html_e('Enable Country Blocking', 'upshield-waf'); ?></th>
                            <td>
                                <label class="upshield-switch">
                                    <input type="checkbox" name="upshield_options[country_blocking_enabled]" value="1"
                                           <?php checked($vswaf_options['country_blocking_enabled'] ?? false); ?>>
                                    <span class="slider"></span>
                                </label>
                                <p class="description"><?php esc_html_e('Block requests from specific countries based on IP geolocation.', 'upshield-waf'); ?></p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><?php esc_html_e('Blocking Mode', 'upshield-waf'); ?></th>
                            <td>
                                <?php $vswaf_country_mode = $vswaf_options['country_blocking_mode'] ?? 'block_selected'; ?>
                                <div class="upshield-radio-group" style="flex-direction: column; gap: 10px;">
                                    <label class="radio-card <?php echo $vswaf_country_mode === 'block_selected' ? 'active' : ''; ?>" style="padding: 15px;">
                                        <input type="radio" name="upshield_options[country_blocking_mode]" value="block_selected"
                                               <?php checked($vswaf_country_mode, 'block_selected'); ?>>
                                        <div class="radio-content">
                                            <div class="radio-header">
                                                <strong><?php esc_html_e('Block Selected Countries', 'upshield-waf'); ?></strong>
                                                <span class="radio-check dashicons dashicons-yes"></span>
                                            </div>
                                            <p style="margin: 5px 0 0;"><?php esc_html_e('Block only the countries you select below. All other countries are allowed.', 'upshield-waf'); ?></p>
                                        </div>
                                    </label>
                                    <label class="radio-card <?php echo $vswaf_country_mode === 'allow_selected' ? 'active' : ''; ?>" style="padding: 15px;">
                                        <input type="radio" name="upshield_options[country_blocking_mode]" value="allow_selected"
                                               <?php checked($vswaf_country_mode, 'allow_selected'); ?>>
                                        <div class="radio-content">
                                            <div class="radio-header">
                                                <strong><?php esc_html_e('Allow Selected Countries Only', 'upshield-waf'); ?></strong>
                                                <span class="radio-check dashicons dashicons-yes"></span>
                                            </div>
                                            <p style="margin: 5px 0 0;"><?php esc_html_e('Allow only the countries you select below. All other countries are blocked.', 'upshield-waf'); ?></p>
                                        </div>
                                    </label>
                                </div>
                                <div id="country-mode-warning" class="notice notice-warning inline" style="margin-top: 10px; padding: 10px; display: none;">
                                    <p><strong><?php esc_html_e('Warning:', 'upshield-waf'); ?></strong> <?php esc_html_e('You have selected "Allow Selected Countries Only" mode but no countries are selected. This will block ALL traffic!', 'upshield-waf'); ?></p>
                                </div>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><?php esc_html_e('Block Unknown Countries', 'upshield-waf'); ?></th>
                            <td>
                                <label class="upshield-switch">
                                    <input type="checkbox" name="upshield_options[block_unknown_countries]" value="1"
                                           <?php checked($vswaf_options['block_unknown_countries'] ?? false); ?>>
                                    <span class="slider"></span>
                                </label>
                                <p class="description"><?php esc_html_e('Block requests when country cannot be determined.', 'upshield-waf'); ?></p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row">
                                <span id="countries-list-label">
                                    <?php echo $vswaf_country_mode === 'allow_selected' ? esc_html__('Allowed Countries', 'upshield-waf') : esc_html__('Blocked Countries', 'upshield-waf'); ?>
                                </span>
                            </th>
                            <td>
                                <?php
                                require_once UPSHIELD_PLUGIN_DIR . 'includes/firewall/class-country-blocker.php';
                                $vswaf_country_blocker = new \UpShield\Firewall\CountryBlocker();
                                $vswaf_countries = $vswaf_country_blocker->get_countries_list();
                                $vswaf_blocked_countries = $vswaf_options['blocked_countries'] ?? [];
                                ?>
                                <div style="max-height: 300px; overflow-y: auto; border: 1px solid #ddd; padding: 10px; border-radius: 4px; background: #f9f9f9;">
                                    <div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 8px;">
                                        <?php foreach ($vswaf_countries as $vswaf_code => $vswaf_name): ?>
                                            <label style="display: flex; align-items: center; gap: 6px; font-size: 13px;">
                                                <input type="checkbox"
                                                       name="upshield_options[blocked_countries][]"
                                                       value="<?php echo esc_attr($vswaf_code); ?>"
                                                       <?php checked(in_array($vswaf_code, $vswaf_blocked_countries)); ?>>
                                                <span><?php echo esc_html($vswaf_name); ?> (<?php echo esc_html($vswaf_code); ?>)</span>
                                            </label>
                                        <?php endforeach; ?>
                                    </div>
                                </div>
                                <p class="description"><?php esc_html_e('Select countries to block. Use Ctrl/Cmd+Click to select multiple.', 'upshield-waf'); ?></p>
                            </td>
                        </tr>
                    </table>
                </div>
            </div>

        </div>

        <!-- CAPTCHA Settings -->
        <div class="upshield-tab-content" id="captcha">
            <div class="upshield-card">
                <div class="card-header">
                    <h2>
                        <span class="dashicons dashicons-lock"></span>
                        <?php esc_html_e('CAPTCHA Challenge', 'upshield-waf'); ?>
                    </h2>
                </div>
                <div class="card-body">
                    <p class="description mb-20">
                        <?php esc_html_e('Show CAPTCHA challenge instead of blocking. Allows legitimate users to verify themselves while stopping automated attacks.', 'upshield-waf'); ?>
                    </p>
                    
                    <?php
                    require_once UPSHIELD_PLUGIN_DIR . 'includes/waf/class-captcha-handler.php';
                    $vswaf_captcha_providers = \UpShield\WAF\CaptchaHandler::get_provider_list();
                    ?>
                    
                    <table class="form-table">
                        <tr>
                            <th scope="row"><?php esc_html_e('Enable CAPTCHA Challenge', 'upshield-waf'); ?></th>
                            <td>
                                <label class="upshield-switch">
                                    <input type="checkbox" name="upshield_options[captcha_enabled]" value="1"
                                           <?php checked($vswaf_options['captcha_enabled'] ?? false); ?>
                                           id="captcha-enabled-toggle">
                                    <span class="slider"></span>
                                </label>
                                <p class="description">
                                    <?php esc_html_e('When enabled, suspicious requests will be shown a CAPTCHA challenge instead of being blocked immediately.', 'upshield-waf'); ?>
                                    <br><strong><?php esc_html_e('Note:', 'upshield-waf'); ?></strong>
                                    <?php esc_html_e('Threat Intelligence blocks are always immediate (no CAPTCHA).', 'upshield-waf'); ?>
                                </p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><?php esc_html_e('CAPTCHA Provider', 'upshield-waf'); ?></th>
                            <td>
                                <select name="upshield_options[captcha_provider]" id="captcha-provider-select" class="regular-text">
                                    <option value=""><?php esc_html_e('-- Select Provider --', 'upshield-waf'); ?></option>
                                    <?php foreach ($vswaf_captcha_providers as $vswaf_provider_key => $vswaf_provider_name): ?>
                                        <option value="<?php echo esc_attr($vswaf_provider_key); ?>"
                                                <?php selected($vswaf_options['captcha_provider'] ?? '', $vswaf_provider_key); ?>>
                                            <?php echo esc_html($vswaf_provider_name); ?>
                                        </option>
                                    <?php endforeach; ?>
                                </select>
                                <p class="description">
                                    <?php esc_html_e('Choose your CAPTCHA provider. You will need to configure API keys from your provider dashboard.', 'upshield-waf'); ?>
                                </p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><?php esc_html_e('Site Key', 'upshield-waf'); ?></th>
                            <td>
                                <input type="text" name="upshield_options[captcha_site_key]"
                                       value="<?php echo esc_attr($vswaf_options['captcha_site_key'] ?? ''); ?>"
                                       class="regular-text" placeholder="Enter your site key">
                                <p class="description">
                                    <?php esc_html_e('The public site key from your CAPTCHA provider.', 'upshield-waf'); ?>
                                </p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><?php esc_html_e('Secret Key', 'upshield-waf'); ?></th>
                            <td>
                                <input type="password" name="upshield_options[captcha_secret_key]"
                                       value="<?php echo esc_attr($vswaf_options['captcha_secret_key'] ?? ''); ?>"
                                       class="regular-text" placeholder="Enter your secret key">
                                <p class="description">
                                    <?php esc_html_e('The private secret key from your CAPTCHA provider. Keep this secure.', 'upshield-waf'); ?>
                                </p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><?php esc_html_e('Session Duration', 'upshield-waf'); ?></th>
                            <td>
                                <select name="upshield_options[captcha_session_duration]">
                                    <option value="1800" <?php selected($vswaf_options['captcha_session_duration'] ?? 3600, 1800); ?>><?php esc_html_e('30 minutes', 'upshield-waf'); ?></option>
                                    <option value="3600" <?php selected($vswaf_options['captcha_session_duration'] ?? 3600, 3600); ?>><?php esc_html_e('1 hour', 'upshield-waf'); ?></option>
                                    <option value="7200" <?php selected($vswaf_options['captcha_session_duration'] ?? 3600, 7200); ?>><?php esc_html_e('2 hours', 'upshield-waf'); ?></option>
                                    <option value="14400" <?php selected($vswaf_options['captcha_session_duration'] ?? 3600, 14400); ?>><?php esc_html_e('4 hours', 'upshield-waf'); ?></option>
                                    <option value="28800" <?php selected($vswaf_options['captcha_session_duration'] ?? 3600, 28800); ?>><?php esc_html_e('8 hours', 'upshield-waf'); ?></option>
                                    <option value="86400" <?php selected($vswaf_options['captcha_session_duration'] ?? 3600, 86400); ?>><?php esc_html_e('24 hours', 'upshield-waf'); ?></option>
                                </select>
                                <p class="description">
                                    <?php esc_html_e('How long a verified session lasts before requiring another CAPTCHA.', 'upshield-waf'); ?>
                                </p>
                            </td>
                        </tr>
                        <tr id="recaptcha-v3-score-row" style="<?php echo ($vswaf_options['captcha_provider'] ?? '') === 'recaptcha_v3' ? '' : 'display: none;'; ?>">
                            <th scope="row"><?php esc_html_e('reCAPTCHA v3 Min Score', 'upshield-waf'); ?></th>
                            <td>
                                <input type="number" name="upshield_options[recaptcha_v3_min_score]"
                                       value="<?php echo esc_attr($vswaf_options['recaptcha_v3_min_score'] ?? '0.5'); ?>"
                                       class="small-text" min="0" max="1" step="0.1">
                                <p class="description">
                                    <?php esc_html_e('Minimum score (0.0-1.0) to pass verification. Lower = more permissive. Default: 0.5', 'upshield-waf'); ?>
                                </p>
                            </td>
                        </tr>
                    </table>
                    
                    <div class="notice notice-info inline" style="margin: 20px 0 10px;">
                        <p>
                            <strong><?php esc_html_e('Provider Setup Links:', 'upshield-waf'); ?></strong><br>
                            • <a href="https://www.google.com/recaptcha/admin" target="_blank">Google reCAPTCHA</a> -
                            <?php esc_html_e('Free, widely supported', 'upshield-waf'); ?><br>
                            • <a href="https://dash.cloudflare.com/?to=/:account/turnstile" target="_blank">Cloudflare Turnstile</a> -
                            <?php esc_html_e('Free, privacy-focused, no puzzles', 'upshield-waf'); ?><br>
                            • <a href="https://dashboard.hcaptcha.com/" target="_blank">hCaptcha</a> -
                            <?php esc_html_e('Privacy-first alternative', 'upshield-waf'); ?>
                        </p>
                    </div>
                    
                    <!-- Attack Types Section (inside CAPTCHA card) -->
                    <hr style="margin: 25px 0;">
                    <h3 style="margin-top: 0; margin-bottom: 15px; font-size: 16px; font-weight: 600;">
                        <span class="dashicons dashicons-shield-alt" style="font-size: 18px; vertical-align: middle;"></span>
                        <?php esc_html_e('Attack Types for CAPTCHA', 'upshield-waf'); ?>
                    </h3>
                    <p class="description mb-20">
                        <?php esc_html_e('Select which attack types should trigger CAPTCHA challenge. If none selected, CAPTCHA will apply to all attack types.', 'upshield-waf'); ?>
                    </p>
                    
                    <?php
                    $vswaf_captcha_types = $vswaf_options['captcha_types'] ?? [];
                    $vswaf_available_types = [
                        'sqli' => __('SQL Injection (SQLi)', 'upshield-waf'),
                        'xss' => __('Cross-Site Scripting (XSS)', 'upshield-waf'),
                        'rce' => __('Remote Code Execution (RCE)', 'upshield-waf'),
                        'lfi' => __('Local File Inclusion (LFI)', 'upshield-waf'),
                        'bad_bot' => __('Bad Bots & Crawlers', 'upshield-waf'),
                        'author_scan' => __('Author Enumeration', 'upshield-waf'),
                        'rate_limit' => __('Rate Limiting', 'upshield-waf'),
                    ];
                    ?>
                    
                    <div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(250px, 1fr)); gap: 10px;">
                        <?php foreach ($vswaf_available_types as $vswaf_type_key => $vswaf_type_label): ?>
                            <label style="display: flex; align-items: center; gap: 8px; padding: 10px; background: #f9f9f9; border-radius: 4px;">
                                <input type="checkbox"
                                       name="upshield_options[captcha_types][]"
                                       value="<?php echo esc_attr($vswaf_type_key); ?>"
                                       <?php checked(in_array($vswaf_type_key, $vswaf_captcha_types)); ?>>
                                <span><?php echo esc_html($vswaf_type_label); ?></span>
                            </label>
                        <?php endforeach; ?>
                    </div>
                    
                    <p class="description" style="margin-top: 15px;">
                        <strong><?php esc_html_e('Excluded from CAPTCHA:', 'upshield-waf'); ?></strong>
                        <?php esc_html_e('Threat Intelligence, Country Blocking, and XML-RPC attacks are always blocked immediately (no CAPTCHA option).', 'upshield-waf'); ?>
                    </p>
                </div>
            </div>
        </div>

        <!-- Login Security -->
        <div class="upshield-tab-content" id="login">
            <div class="upshield-card">
                <div class="card-header">
                    <h2>
                        <span class="dashicons dashicons-lock"></span>
                        <?php esc_html_e('Login Security', 'upshield-waf'); ?>
                    </h2>
                </div>
                <div class="card-body">
                    <table class="form-table">
                        <tr>
                            <th scope="row"><?php esc_html_e('Enable Login Security', 'upshield-waf'); ?></th>
                            <td>
                                <label class="upshield-switch">
                                    <input type="checkbox" name="upshield_options[login_security_enabled]" value="1" 
                                           <?php checked($vswaf_options['login_security_enabled'] ?? true); ?>>
                                    <span class="slider"></span>
                                </label>
                                <p class="description"><?php esc_html_e('Protect WordPress login page from brute force attacks.', 'upshield-waf'); ?></p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><?php esc_html_e('Max Login Attempts', 'upshield-waf'); ?></th>
                            <td>
                                <input type="number" name="upshield_options[login_max_attempts]" 
                                       value="<?php echo esc_attr($vswaf_options['login_max_attempts'] ?? 5); ?>" 
                                       class="small-text" min="1" max="20">
                                <span class="description"><?php esc_html_e('Maximum failed login attempts before blocking IP', 'upshield-waf'); ?></span>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><?php esc_html_e('Time Window', 'upshield-waf'); ?></th>
                            <td>
                                <input type="number" name="upshield_options[login_time_window]" 
                                       value="<?php echo esc_attr($vswaf_options['login_time_window'] ?? 900); ?>" 
                                       class="small-text" min="60" max="3600">
                                <span class="description"><?php esc_html_e('Time window in seconds to count attempts (default: 900 = 15 minutes)', 'upshield-waf'); ?></span>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><?php esc_html_e('Lockout Duration', 'upshield-waf'); ?></th>
                            <td>
                                <select name="upshield_options[login_lockout_duration]">
                                    <option value="300" <?php selected($vswaf_options['login_lockout_duration'] ?? 900, 300); ?>>5 minutes</option>
                                    <option value="900" <?php selected($vswaf_options['login_lockout_duration'] ?? 900, 900); ?>>15 minutes</option>
                                    <option value="1800" <?php selected($vswaf_options['login_lockout_duration'] ?? 900, 1800); ?>>30 minutes</option>
                                    <option value="3600" <?php selected($vswaf_options['login_lockout_duration'] ?? 900, 3600); ?>>1 hour</option>
                                    <option value="7200" <?php selected($vswaf_options['login_lockout_duration'] ?? 900, 7200); ?>>2 hours</option>
                                    <option value="86400" <?php selected($vswaf_options['login_lockout_duration'] ?? 900, 86400); ?>>24 hours</option>
                                </select>
                                <p class="description"><?php esc_html_e('How long to block IP after max attempts reached', 'upshield-waf'); ?></p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><?php esc_html_e('Enable Honeypot', 'upshield-waf'); ?></th>
                            <td>
                                <label class="upshield-switch">
                                    <input type="checkbox" name="upshield_options[login_honeypot_enabled]" value="1" 
                                           <?php checked($vswaf_options['login_honeypot_enabled'] ?? true); ?>>
                                    <span class="slider"></span>
                                </label>
                                <p class="description"><?php esc_html_e('Add hidden honeypot field to catch bots', 'upshield-waf'); ?></p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><?php esc_html_e('Enable Email Notifications', 'upshield-waf'); ?></th>
                            <td>
                                <label class="upshield-switch">
                                    <input type="checkbox" name="upshield_options[login_notifications_enabled]" value="1" 
                                           <?php checked($vswaf_options['login_notifications_enabled'] ?? false); ?>>
                                    <span class="slider"></span>
                                </label>
                                <p class="description"><?php esc_html_e('Send email alerts for failed login attempts', 'upshield-waf'); ?></p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><?php esc_html_e('Notification Threshold', 'upshield-waf'); ?></th>
                            <td>
                                <input type="number" name="upshield_options[login_notification_threshold]" 
                                       value="<?php echo esc_attr($vswaf_options['login_notification_threshold'] ?? 3); ?>" 
                                       class="small-text" min="1" max="10">
                                <span class="description"><?php esc_html_e('Send email after this many failed attempts', 'upshield-waf'); ?></span>
                            </td>
                        </tr>
                    </table>
                </div>
            </div>
        </div>
        <!-- Scanner -->
        <div class="upshield-tab-content" id="scanner">
            <!-- File Scanner Card -->
            <div class="upshield-card">
                <div class="card-header">
                    <h2>
                        <span class="dashicons dashicons-media-text"></span>
                        <?php esc_html_e('File Scanner (Core Integrity)', 'upshield-waf'); ?>
                    </h2>
                </div>
                <div class="card-body">
                    <p class="description mb-20">
                        <?php esc_html_e('Compare WordPress core files against official checksums to detect unauthorized modifications.', 'upshield-waf'); ?>
                    </p>
                    <table class="form-table">
                        <tr>
                            <th scope="row"><?php esc_html_e('Enable File Scanner', 'upshield-waf'); ?></th>
                            <td>
                                <label class="upshield-switch">
                                    <input type="checkbox" name="upshield_options[file_scanner_enabled]" value="1"
                                           <?php checked($vswaf_options['file_scanner_enabled'] ?? false); ?>>
                                    <span class="slider"></span>
                                </label>
                                <p class="description"><?php esc_html_e('Monitor WordPress core files for unauthorized changes.', 'upshield-waf'); ?></p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><?php esc_html_e('Scan Schedule', 'upshield-waf'); ?></th>
                            <td>
                                <select name="upshield_options[file_scan_schedule]">
                                    <option value="manual" <?php selected($vswaf_options['file_scan_schedule'] ?? 'manual', 'manual'); ?>>
                                        <?php esc_html_e('Manual Only', 'upshield-waf'); ?>
                                    </option>
                                    <option value="daily" <?php selected($vswaf_options['file_scan_schedule'] ?? 'manual', 'daily'); ?>>
                                        <?php esc_html_e('Daily', 'upshield-waf'); ?>
                                    </option>
                                    <option value="weekly" <?php selected($vswaf_options['file_scan_schedule'] ?? 'manual', 'weekly'); ?>>
                                        <?php esc_html_e('Weekly', 'upshield-waf'); ?>
                                    </option>
                                </select>
                                <p class="description"><?php esc_html_e('How often to check core files.', 'upshield-waf'); ?></p>
                            </td>
                        </tr>
                    </table>
                </div>
            </div>

            <!-- Malware Scanner Card -->
            <div class="upshield-card">
                <div class="card-header">
                    <h2>
                        <span class="dashicons dashicons-shield-alt"></span>
                        <?php esc_html_e('Malware Scanner', 'upshield-waf'); ?>
                    </h2>
                </div>
                <div class="card-body">
                    <p class="description mb-20">
                        <?php esc_html_e('Scan your themes, plugins, and uploads for malware, backdoors, and suspicious code patterns.', 'upshield-waf'); ?>
                    </p>
                    <table class="form-table">
                        <tr>
                            <th scope="row"><?php esc_html_e('Enable Malware Scanner', 'upshield-waf'); ?></th>
                            <td>
                                <label class="upshield-switch">
                                    <input type="hidden" name="upshield_options[malware_scanner_enabled]" value="0">
                                    <input type="checkbox" name="upshield_options[malware_scanner_enabled]" value="1"
                                           <?php checked($vswaf_options['malware_scanner_enabled'] ?? true); ?>>
                                    <span class="slider"></span>
                                </label>
                                <p class="description"><?php esc_html_e('Scan themes, plugins, and uploads for malware, backdoors, and suspicious code.', 'upshield-waf'); ?></p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><?php esc_html_e('Scan Schedule', 'upshield-waf'); ?></th>
                            <td>
                                <select name="upshield_options[malware_scan_schedule]">
                                    <option value="manual" <?php selected($vswaf_options['malware_scan_schedule'] ?? 'weekly', 'manual'); ?>>
                                        <?php esc_html_e('Manual Only', 'upshield-waf'); ?>
                                    </option>
                                    <option value="daily" <?php selected($vswaf_options['malware_scan_schedule'] ?? 'weekly', 'daily'); ?>>
                                        <?php esc_html_e('Daily', 'upshield-waf'); ?>
                                    </option>
                                    <option value="weekly" <?php selected($vswaf_options['malware_scan_schedule'] ?? 'weekly', 'weekly'); ?>>
                                        <?php esc_html_e('Weekly', 'upshield-waf'); ?>
                                    </option>
                                </select>
                                <p class="description"><?php esc_html_e('Scheduled scans will run automatically based on this interval.', 'upshield-waf'); ?></p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><?php esc_html_e('Scan Scope', 'upshield-waf'); ?></th>
                            <td>
                                <select name="upshield_options[malware_scan_scope]">
                                    <option value="all" <?php selected($vswaf_options['malware_scan_scope'] ?? 'all', 'all'); ?>>
                                        <?php esc_html_e('All (Themes, Plugins, Uploads)', 'upshield-waf'); ?>
                                    </option>
                                    <option value="themes" <?php selected($vswaf_options['malware_scan_scope'] ?? 'all', 'themes'); ?>>
                                        <?php esc_html_e('Themes Only', 'upshield-waf'); ?>
                                    </option>
                                    <option value="plugins" <?php selected($vswaf_options['malware_scan_scope'] ?? 'all', 'plugins'); ?>>
                                        <?php esc_html_e('Plugins Only', 'upshield-waf'); ?>
                                    </option>
                                    <option value="uploads" <?php selected($vswaf_options['malware_scan_scope'] ?? 'all', 'uploads'); ?>>
                                        <?php esc_html_e('Uploads Only', 'upshield-waf'); ?>
                                    </option>
                                </select>
                                <p class="description"><?php esc_html_e('Select which directories to scan for malware.', 'upshield-waf'); ?></p>
                            </td>
                        </tr>
                    </table>
                </div>
            </div>
        </div>

        <!-- Advanced -->
        <div class="upshield-tab-content" id="advanced">
            <!-- Rate Limiting -->
            <div class="upshield-card">
                <div class="card-header">
                    <h2>
                        <span class="dashicons dashicons-clock"></span>
                        <?php esc_html_e('Rate Limiting', 'upshield-waf'); ?>
                    </h2>
                </div>
                <div class="card-body">
                    <table class="form-table">
                        <tr>
                            <th scope="row"><?php esc_html_e('Enable Rate Limiting', 'upshield-waf'); ?></th>
                            <td>
                                <label class="upshield-switch">
                                    <input type="checkbox" name="upshield_options[rate_limiting_enabled]" value="1" 
                                           <?php checked($vswaf_options['rate_limiting_enabled'] ?? true); ?>>
                                    <span class="slider"></span>
                                </label>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><?php esc_html_e('Global Rate Limit', 'upshield-waf'); ?></th>
                            <td>
                                <input type="number" name="upshield_options[rate_limit_global]"
                                       value="<?php echo esc_attr($vswaf_options['rate_limit_global'] ?? 250); ?>"
                                       class="small-text" min="10" max="1000">
                                <span class="description"><?php esc_html_e('requests per minute', 'upshield-waf'); ?></span>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><?php esc_html_e('Login Rate Limit', 'upshield-waf'); ?></th>
                            <td>
                                <input type="number" name="upshield_options[rate_limit_login]" 
                                       value="<?php echo esc_attr($vswaf_options['rate_limit_login'] ?? 20); ?>" 
                                       class="small-text" min="1" max="100">
                                <span class="description"><?php esc_html_e('attempts per 5 minutes', 'upshield-waf'); ?></span>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><?php esc_html_e('XML-RPC Rate Limit', 'upshield-waf'); ?></th>
                            <td>
                                <input type="number" name="upshield_options[rate_limit_xmlrpc]" 
                                       value="<?php echo esc_attr($vswaf_options['rate_limit_xmlrpc'] ?? 20); ?>" 
                                       class="small-text" min="1" max="100">
                                <span class="description"><?php esc_html_e('requests per minute', 'upshield-waf'); ?></span>
                            </td>
                        </tr>
                    </table>
                </div>
            </div>

            <!-- Auto Block -->
            <div class="upshield-card">
                <div class="card-header">
                    <h2>
                        <span class="dashicons dashicons-dismiss"></span>
                        <?php esc_html_e('Auto Block', 'upshield-waf'); ?>
                    </h2>
                </div>
                <div class="card-body">
                    <table class="form-table">
                        <tr>
                            <th scope="row"><?php esc_html_e('Auto Block Threshold', 'upshield-waf'); ?></th>
                            <td>
                                <input type="number" name="upshield_options[auto_block_threshold]" 
                                       value="<?php echo esc_attr($vswaf_options['auto_block_threshold'] ?? 10); ?>" 
                                       class="small-text" min="0" max="100">
                                <span class="description"><?php esc_html_e('blocked requests before auto-blocking IP (0 to disable)', 'upshield-waf'); ?></span>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><?php esc_html_e('Auto Block Duration', 'upshield-waf'); ?></th>
                            <td>
                                <select name="upshield_options[auto_block_duration]">
                                    <option value="3600" <?php selected($vswaf_options['auto_block_duration'] ?? 3600, 3600); ?>>1 hour</option>
                                    <option value="7200" <?php selected($vswaf_options['auto_block_duration'] ?? 3600, 7200); ?>>2 hours</option>
                                    <option value="21600" <?php selected($vswaf_options['auto_block_duration'] ?? 3600, 21600); ?>>6 hours</option>
                                    <option value="43200" <?php selected($vswaf_options['auto_block_duration'] ?? 3600, 43200); ?>>12 hours</option>
                                    <option value="86400" <?php selected($vswaf_options['auto_block_duration'] ?? 3600, 86400); ?>>24 hours</option>
                                    <option value="604800" <?php selected($vswaf_options['auto_block_duration'] ?? 3600, 604800); ?>>7 days</option>
                                </select>
                            </td>
                        </tr>
                    </table>
                </div>
            </div>

            <!-- Logging -->
            <div class="upshield-card">
                <div class="card-header">
                    <h2>
                        <span class="dashicons dashicons-media-text"></span>
                        <?php esc_html_e('Logging', 'upshield-waf'); ?>
                    </h2>
                </div>
                <div class="card-body">
                    <table class="form-table">
                        <tr>
                            <th scope="row"><?php esc_html_e('Log All Traffic', 'upshield-waf'); ?></th>
                            <td>
                                <label class="upshield-switch">
                                    <input type="checkbox" name="upshield_options[log_all_traffic]" value="1" 
                                           <?php checked($vswaf_options['log_all_traffic'] ?? false); ?>>
                                    <span class="slider"></span>
                                </label>
                                <p class="description"><?php esc_html_e('Log all requests, not just blocked ones. May increase database size.', 'upshield-waf'); ?></p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><?php esc_html_e('Log Retention', 'upshield-waf'); ?></th>
                            <td>
                                <input type="number" name="upshield_options[log_retention_days]" 
                                       value="<?php echo esc_attr($vswaf_options['log_retention_days'] ?? 30); ?>" 
                                       class="small-text" min="1" max="365">
                                <span class="description"><?php esc_html_e('days to keep logs', 'upshield-waf'); ?></span>
                            </td>
                        </tr>

                    </table>
                </div>
            </div>

            <!-- IP Whitelist -->
            <div class="upshield-card">
                <div class="card-header">
                    <h2>
                        <span class="dashicons dashicons-list-view"></span>
                        <?php esc_html_e('IP Whitelist', 'upshield-waf'); ?>
                    </h2>
                </div>
                <div class="card-body">
                    <?php
                    // Get auto-whitelist sync status
                    require_once UPSHIELD_PLUGIN_DIR . 'includes/firewall/class-ip-whitelist-sync.php';
                    $vswaf_whitelist_status = \UpShield\Firewall\IPWhitelistSync::get_sync_status();
                    ?>
                    <table class="form-table">
                        <tr>
                            <th scope="row"><?php esc_html_e('Whitelist Googlebot', 'upshield-waf'); ?></th>
                            <td>
                                <label class="upshield-switch">
                                    <input type="checkbox" name="upshield_options[whitelist_googlebot]" value="1" 
                                           <?php checked($vswaf_options['whitelist_googlebot'] ?? true); ?>>
                                    <span class="slider"></span>
                                </label>
                                <p class="description">
                                    <?php esc_html_e('Auto-whitelist Google crawler IP ranges (Googlebot, AdsBot, etc.). Updated daily from Google.', 'upshield-waf'); ?>
                                    <?php if ($vswaf_whitelist_status['googlebot_count'] > 0): ?>
                                        <br><strong><?php 
                                        /* translators: %d: number of IP ranges */
                                        printf(esc_html__('Currently whitelisted: %d IP ranges', 'upshield-waf'), intval($vswaf_whitelist_status['googlebot_count'])); 
                                        ?></strong>
                                    <?php endif; ?>
                                </p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><?php esc_html_e('Enable Cloudflare Support', 'upshield-waf'); ?></th>
                            <td>
                                <label class="upshield-switch">
                                    <input type="checkbox" name="upshield_options[cloudflare_enabled]" value="1" 
                                           <?php checked($vswaf_options['cloudflare_enabled'] ?? false); ?>>
                                    <span class="slider"></span>
                                </label>
                                <p class="description"><?php esc_html_e('Auto-whitelist Cloudflare IP ranges. Enable this if your site is behind Cloudflare.', 'upshield-waf'); ?></p>
                            </td>
                        </tr>

                    </table>
                    
                    <div style="margin: 15px 0 20px;">
                        <button type="button" id="ip-whitelist-sync-btn" class="button button-secondary">
                            <span class="dashicons dashicons-update"></span>
                            <?php esc_html_e('Sync Now', 'upshield-waf'); ?>
                        </button>
                        <span id="ip-whitelist-message" style="margin-left: 10px; font-style: italic;"></span>
                    </div>

                    <hr style="margin: 30px 0;">
                    <h3 style="margin-top: 0; margin-bottom: 15px; font-size: 16px; font-weight: 600;">
                        <span class="dashicons dashicons-edit" style="font-size: 18px; vertical-align: middle;"></span>
                        <?php esc_html_e('Manual IP Lists', 'upshield-waf'); ?>
                    </h3>
                    <table class="form-table">
                        <tr>
                            <th scope="row"><?php esc_html_e('Whitelisted IPs', 'upshield-waf'); ?></th>
                            <td>
                                <textarea name="upshield_options[whitelisted_ips]" rows="5" class="large-text code"><?php 
                                    echo esc_textarea(implode("\n", $vswaf_options['whitelisted_ips'] ?? [])); 
                                ?></textarea>
                                <p class="description"><?php esc_html_e('One IP per line. Supports CIDR notation (e.g., 192.168.1.0/24)', 'upshield-waf'); ?></p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><?php esc_html_e('Trusted Proxies', 'upshield-waf'); ?></th>
                            <td>
                                <textarea name="upshield_options[trusted_proxies]" rows="5" class="large-text code"><?php 
                                    echo esc_textarea(implode("\n", $vswaf_options['trusted_proxies'] ?? [])); 
                                ?></textarea>
                                <p class="description"><?php esc_html_e('One IP or CIDR per line. These IPs will be trusted to provide the real client IP via X-Forwarded-For headers.', 'upshield-waf'); ?></p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><?php esc_html_e('Blacklisted IPs', 'upshield-waf'); ?></th>
                            <td>
                                <textarea name="upshield_options[blacklisted_ips]" rows="5" class="large-text code"><?php 
                                    echo esc_textarea(implode("\n", $vswaf_options['blacklisted_ips'] ?? [])); 
                                ?></textarea>
                                <p class="description"><?php esc_html_e('One IP per line. These IPs will be permanently blocked.', 'upshield-waf'); ?></p>
                            </td>
                        </tr>
                    </table>
                </div>
            </div>
            
            <!-- Scheduled Tasks -->
            <div class="upshield-card">
                <div class="card-header">
                    <h2>
                        <span class="dashicons dashicons-clock"></span>
                        <?php esc_html_e('Scheduled Tasks', 'upshield-waf'); ?>
                    </h2>
                </div>
                <div class="card-body">
                    <table class="form-table">
                        <tr>
                            <th scope="row"><?php esc_html_e('Scheduled Tasks Status', 'upshield-waf'); ?></th>
                            <td>
                                <ul style="list-style: disc; margin-left: 20px;">
                                    <li>
                                        <strong><?php esc_html_e('Log Cleanup:', 'upshield-waf'); ?></strong> 
                                        <?php 
                                        $vswaf_next_cleanup = wp_next_scheduled('upshield_cleanup_logs');
                                        echo $vswaf_next_cleanup ? esc_html(wp_date('Y-m-d H:i:s', $vswaf_next_cleanup)) : esc_html__('Not scheduled', 'upshield-waf');
                                        ?>
                                        <span class="description"> (<?php esc_html_e('Daily', 'upshield-waf'); ?>)</span>
                                    </li>
                                    <li>
                                        <strong><?php esc_html_e('Stats Aggregation:', 'upshield-waf'); ?></strong> 
                                        <?php 
                                        $vswaf_next_stats = wp_next_scheduled('upshield_aggregate_stats');
                                        echo $vswaf_next_stats ? esc_html(wp_date('Y-m-d H:i:s', $vswaf_next_stats)) : esc_html__('Not scheduled', 'upshield-waf');
                                        ?>
                                        <span class="description"> (<?php esc_html_e('Hourly', 'upshield-waf'); ?>)</span>
                                    </li>
                                    <li>
                                        <strong><?php esc_html_e('Maintenance:', 'upshield-waf'); ?></strong> 
                                        <?php 
                                        $vswaf_next_maintenance = wp_next_scheduled('upshield_maintenance');
                                        echo $vswaf_next_maintenance ? esc_html(wp_date('Y-m-d H:i:s', $vswaf_next_maintenance)) : esc_html__('Not scheduled', 'upshield-waf');
                                        ?>
                                        <span class="description"> (<?php esc_html_e('Weekly', 'upshield-waf'); ?>)</span>
                                    </li>
                                    <li>
                                        <strong><?php esc_html_e('Threats Sharing:', 'upshield-waf'); ?></strong> 
                                        <?php 
                                        $vswaf_next_threats = wp_next_scheduled('upshield_submit_threats');
                                        echo $vswaf_next_threats ? esc_html(wp_date('Y-m-d H:i:s', $vswaf_next_threats)) : esc_html__('Not scheduled', 'upshield-waf');
                                        ?>
                                        <span class="description"> (<?php esc_html_e('Every 5 minutes', 'upshield-waf'); ?>)</span>
                                    </li>
                                    <li>
                                        <strong><?php esc_html_e('Googlebot IP Whitelist:', 'upshield-waf'); ?></strong> 
                                        <?php 
                                        $vswaf_next_whitelist = wp_next_scheduled('upshield_ip_whitelist_sync');
                                        echo $vswaf_next_whitelist ? esc_html(wp_date('Y-m-d H:i:s', $vswaf_next_whitelist)) : esc_html__('Not scheduled', 'upshield-waf');
                                        ?>
                                        <span class="description"> (<?php esc_html_e('Daily', 'upshield-waf'); ?>)</span>
                                    </li>
                                </ul>
                                <p class="description"><?php esc_html_e('These tasks run automatically to keep your site optimized and secure.', 'upshield-waf'); ?></p>
                            </td>
                        </tr>
                    </table>
                </div>
            </div>
        </div>

        <!-- Threat Intelligence -->
        <div class="upshield-tab-content" id="threat-intel">
            <div class="upshield-card">
                <div class="card-header">
                    <h2>
                        <span class="dashicons dashicons-shield"></span>
                        <?php esc_html_e('Threat Intelligence', 'upshield-waf'); ?>
                    </h2>
                </div>
                <div class="card-body">
                    <?php
                    require_once UPSHIELD_PLUGIN_DIR . 'includes/firewall/class-threat-intelligence.php';
                    $vswaf_threat_intel = new \UpShield\Firewall\ThreatIntelligence();
                    $vswaf_sync_status = $vswaf_threat_intel->get_sync_status();
                    $vswaf_is_syncing = get_transient('upshield_threat_intel_syncing');
                    ?>
                    <table class="form-table">
                        <tr>
                            <th scope="row"><?php esc_html_e('Enable Threat Intelligence', 'upshield-waf'); ?></th>
                            <td>
                                <label class="upshield-switch">
                                    <input type="checkbox" name="upshield_options[threat_intel_enabled]" value="1" 
                                           <?php checked($vswaf_options['threat_intel_enabled'] ?? false); ?>
                                           id="threat-intel-enabled">
                                    <span class="slider"></span>
                                </label>
                                <p class="description"><?php esc_html_e('Automatically block IPs from UpShield Threat Intelligence feed.', 'upshield-waf'); ?></p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><?php esc_html_e('Feed Category', 'upshield-waf'); ?></th>
                            <td>
                                <select name="upshield_options[threat_intel_category]" 
                                        id="threat-intel-category" 
                                        class="regular-text"
                                        <?php disabled($vswaf_is_syncing); ?>>
                                    <option value=""><?php esc_html_e('-- Select Category --', 'upshield-waf'); ?></option>
                                    <option value="1d" <?php selected($vswaf_options['threat_intel_category'] ?? '', '1d'); ?>>
                                        <?php esc_html_e('1 Day (Most Recent Threats)', 'upshield-waf'); ?>
                                    </option>
                                    <option value="3d" <?php selected($vswaf_options['threat_intel_category'] ?? '', '3d'); ?>>
                                        <?php esc_html_e('3 Days', 'upshield-waf'); ?>
                                    </option>
                                    <option value="7d" <?php selected($vswaf_options['threat_intel_category'] ?? '', '7d'); ?>>
                                        <?php esc_html_e('7 Days', 'upshield-waf'); ?>
                                    </option>
                                    <option value="14d" <?php selected($vswaf_options['threat_intel_category'] ?? '', '14d'); ?>>
                                        <?php esc_html_e('14 Days', 'upshield-waf'); ?>
                                    </option>
                                    <option value="30d" <?php selected($vswaf_options['threat_intel_category'] ?? '', '30d'); ?>>
                                        <?php esc_html_e('30 Days (Largest List)', 'upshield-waf'); ?>
                                    </option>
                                </select>
                                <p class="description">
                                    <?php esc_html_e('Select threat intelligence feed category. Only one category can be active at a time.', 'upshield-waf'); ?>
                                </p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><?php esc_html_e('Sync Status', 'upshield-waf'); ?></th>
                            <td>
                                <div id="threat-intel-status">
                                    <?php if ($vswaf_sync_status['count'] > 0): ?>
                                        <p>
                                            <strong><?php esc_html_e('IPs in Database:', 'upshield-waf'); ?></strong> 
                                            <?php echo number_format($vswaf_sync_status['count']); ?>
                                        </p>
                                        <?php if ($vswaf_sync_status['last_sync']): ?>
                                            <p>
                                                <strong><?php esc_html_e('Last Sync:', 'upshield-waf'); ?></strong> 
                                                <?php 
                                                require_once UPSHIELD_PLUGIN_DIR . 'includes/class-upshield-helpers.php';
                                                echo esc_html(\UpShield_Helpers::format_timestamp($vswaf_sync_status['last_sync'], 'Y-m-d H:i:s'));
                                                ?>
                                            </p>
                                        <?php endif; ?>
                                        <?php if ($vswaf_sync_status['category']): ?>
                                            <p>
                                                <strong><?php esc_html_e('Category:', 'upshield-waf'); ?></strong> 
                                                <?php echo esc_html(strtoupper($vswaf_sync_status['category'])); ?>
                                            </p>
                                        <?php endif; ?>
                                        <?php if (!empty($vswaf_sync_status['next_sync'])): ?>
                                            <p>
                                                <strong><?php esc_html_e('Next Auto-Sync:', 'upshield-waf'); ?></strong> 
                                                <?php 
                                                require_once UPSHIELD_PLUGIN_DIR . 'includes/class-upshield-helpers.php';
                                                echo esc_html(\UpShield_Helpers::format_timestamp($vswaf_sync_status['next_sync'], 'Y-m-d H:i:s'));
                                                ?>
                                            </p>
                                        <?php endif; ?>
                                    <?php else: ?>
                                        <p class="description"><?php esc_html_e('No threat intelligence data synced yet.', 'upshield-waf'); ?></p>
                                    <?php endif; ?>
                                </div>
                                <p>
                                    <button type="button" 
                                            id="threat-intel-sync-btn" 
                                            class="button button-secondary"
                                            <?php disabled($vswaf_is_syncing); ?>>
                                        <span class="dashicons dashicons-update"></span>
                                        <?php esc_html_e('Sync Now', 'upshield-waf'); ?>
                                    </button>
                                    <button type="button" 
                                            id="threat-intel-clear-btn" 
                                            class="button button-secondary"
                                            <?php disabled($vswaf_is_syncing); ?>
                                            style="<?php echo $vswaf_sync_status['count'] > 0 ? '' : 'display:none;'; ?>">
                                        <span class="dashicons dashicons-trash"></span>
                                        <?php esc_html_e('Clear Data', 'upshield-waf'); ?>
                                    </button>
                                </p>
                                <?php if ($vswaf_is_syncing): ?>
                                <p class="description" style="color: #f59e0b;">
                                    <span class="dashicons dashicons-update spin"></span>
                                    <?php esc_html_e('Sync in progress... Please wait.', 'upshield-waf'); ?>
                                </p>
                                <?php endif; ?>
                            </td>
                        </tr>
                    </table>
                </div>
            </div>

            <!-- Threats Sharing -->
            <div class="upshield-card">
                <div class="card-header">
                    <h2>
                        <span class="dashicons dashicons-share"></span>
                        <?php esc_html_e('Threats Sharing', 'upshield-waf'); ?>
                    </h2>
                </div>
                <div class="card-body">
                    <?php
                    require_once UPSHIELD_PLUGIN_DIR . 'includes/firewall/class-threats-sharing.php';
                    $vswaf_threats_stats = \UpShield\Firewall\ThreatsSharing::get_stats();
                    $vswaf_next_submit = wp_next_scheduled('upshield_submit_threats');
                    ?>
                    <table class="form-table">
                        <tr>
                            <th scope="row"><?php esc_html_e('Status', 'upshield-waf'); ?></th>
                            <td>
                                <p>
                                    <strong style="color: #46b450;"><?php esc_html_e('Always Enabled', 'upshield-waf'); ?></strong>
                                    <span class="description"><?php esc_html_e('This feature cannot be disabled. Blocked IPs are automatically shared with the UpShield Intelligence community to help protect other websites.', 'upshield-waf'); ?></span>
                                </p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><?php esc_html_e('Queue Statistics', 'upshield-waf'); ?></th>
                            <td>
                                <ul style="list-style: disc; margin-left: 20px;">
                                    <li>
                                        <strong><?php esc_html_e('Pending:', 'upshield-waf'); ?></strong> 
                                        <?php echo number_format($vswaf_threats_stats['pending']); ?>
                                        <span class="description"><?php esc_html_e('IPs waiting to be submitted', 'upshield-waf'); ?></span>
                                    </li>
                                    <li>
                                        <strong><?php esc_html_e('Submitted:', 'upshield-waf'); ?></strong> 
                                        <?php echo number_format($vswaf_threats_stats['submitted']); ?>
                                        <span class="description"><?php esc_html_e('IPs successfully shared', 'upshield-waf'); ?></span>
                                    </li>
                                    <?php if ($vswaf_threats_stats['failed'] > 0): ?>
                                    <li>
                                        <strong style="color: #dc3232;"><?php esc_html_e('Failed:', 'upshield-waf'); ?></strong> 
                                        <?php echo number_format($vswaf_threats_stats['failed']); ?>
                                        <span class="description"><?php esc_html_e('IPs that failed to submit (max retries reached)', 'upshield-waf'); ?></span>
                                    </li>
                                    <?php endif; ?>
                                    <?php if ($vswaf_threats_stats['last_submission']): ?>
                                    <li>
                                        <strong><?php esc_html_e('Last Submission:', 'upshield-waf'); ?></strong> 
                                        <?php 
                                        require_once UPSHIELD_PLUGIN_DIR . 'includes/class-upshield-helpers.php';
                                        echo esc_html(\UpShield_Helpers::format_timestamp($vswaf_threats_stats['last_submission'], 'Y-m-d H:i:s'));
                                        ?>
                                    </li>
                                    <?php endif; ?>
                                </ul>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><?php esc_html_e('Auto-Submit Schedule', 'upshield-waf'); ?></th>
                            <td>
                                <p>
                                    <strong><?php esc_html_e('Next Submission:', 'upshield-waf'); ?></strong> 
                                    <?php 
                                    if ($vswaf_next_submit) {
                                        echo esc_html(wp_date('Y-m-d H:i:s', $vswaf_next_submit));
                                    } else {
                                        esc_html_e('Not scheduled', 'upshield-waf');
                                    }
                                    ?>
                                    <span class="description"> (<?php esc_html_e('Every 5 minutes', 'upshield-waf'); ?>)</span>
                                </p>
                                <p class="description">
                                    <?php esc_html_e('Blocked IPs are automatically queued and submitted to the Intelligence API every 5 minutes. This helps protect the entire community by sharing threat data.', 'upshield-waf'); ?>
                                </p>
                            </td>
                        </tr>
                    </table>
                </div>
            </div>
        </div>

        <!-- About -->
        <div class="upshield-tab-content" id="about">
            <!-- Plugin Information -->
            <div class="upshield-card">
                <div class="card-header">
                    <h2>
                        <span class="dashicons dashicons-info"></span>
                        <?php esc_html_e('Plugin Information', 'upshield-waf'); ?>
                    </h2>
                </div>
                <div class="card-body">
                    <div style="display: flex; align-items: center; gap: 15px; margin-bottom: 20px;">
                        <div style="background: linear-gradient(135deg, #1e40af 0%, #3b82f6 100%); width: 48px; height: 48px; min-width: 48px; border-radius: 8px; display: flex; align-items: center; justify-content: center;">
                            <span class="dashicons dashicons-shield" style="font-size: 24px; width: 24px; height: 24px; color: white;"></span>
                        </div>
                        <div>
                            <h3 style="margin: 0 0 3px; font-size: 18px; font-weight: 600;"><?php esc_html_e('UpShield WAF', 'upshield-waf'); ?></h3>
                            <p style="margin: 0; color: #666; font-size: 13px;"><?php esc_html_e('Web Application Firewall for WordPress', 'upshield-waf'); ?></p>
                        </div>
                    </div>
                    
                    <table class="form-table" style="margin-top: 0;">
                        <tr>
                            <th scope="row"><?php esc_html_e('Version', 'upshield-waf'); ?></th>
                            <td><strong>v<?php echo esc_html(UPSHIELD_VERSION); ?></strong></td>
                        </tr>
                        <tr>
                            <th scope="row"><?php esc_html_e('Author', 'upshield-waf'); ?></th>
                            <td>
                                <a href="https://github.com/UpShield-Security" target="_blank">UpShield Security</a>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><?php esc_html_e('License', 'upshield-waf'); ?></th>
                            <td>GPL v2 or later</td>
                        </tr>
                        <tr>
                            <th scope="row"><?php esc_html_e('PHP Version', 'upshield-waf'); ?></th>
                            <td><?php echo esc_html(PHP_VERSION); ?></td>
                        </tr>
                        <tr>
                            <th scope="row"><?php esc_html_e('WordPress Version', 'upshield-waf'); ?></th>
                            <td><?php echo esc_html(get_bloginfo('version')); ?></td>
                        </tr>
                    </table>
                </div>
            </div>

            <!-- Plugin Updates -->
            <div class="upshield-card">
                <div class="card-header">
                    <h2>
                        <span class="dashicons dashicons-update"></span>
                        <?php esc_html_e('Plugin Updates', 'upshield-waf'); ?>
                    </h2>
                </div>
                <div class="card-body">
                    <?php
                    // Get update info from transient
                    $vswaf_update_transient = get_site_transient('update_plugins');
                    $vswaf_plugin_file = 'upshield-waf/upshield-waf.php';
                    $vswaf_has_update = isset($vswaf_update_transient->response[$vswaf_plugin_file]);
                    $vswaf_update_info = $vswaf_has_update ? $vswaf_update_transient->response[$vswaf_plugin_file] : null;
                    ?>
                    <table class="form-table">
                        <tr>
                            <th scope="row"><?php esc_html_e('Current Version', 'upshield-waf'); ?></th>
                            <td>
                                <strong>v<?php echo esc_html(UPSHIELD_VERSION); ?></strong>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><?php esc_html_e('Update Status', 'upshield-waf'); ?></th>
                            <td>
                                <div id="upshield-update-status">
                                    <?php if ($vswaf_has_update && $vswaf_update_info): ?>
                                        <p style="color: #f59e0b; margin: 0 0 10px;">
                                            <span class="dashicons dashicons-warning"></span>
                                            <strong><?php
                                            /* translators: %s: new version number */
                                            printf(esc_html__('New version available: v%s', 'upshield-waf'), esc_html($vswaf_update_info->new_version));
                                            ?></strong>
                                        </p>
                                        <a href="<?php echo esc_url(admin_url('update-core.php')); ?>" class="button button-primary">
                                            <span class="dashicons dashicons-update"></span>
                                            <?php esc_html_e('Update Now', 'upshield-waf'); ?>
                                        </a>
                                    <?php else: ?>
                                        <p style="color: #46b450; margin: 0;">
                                            <span class="dashicons dashicons-yes-alt"></span>
                                            <?php esc_html_e('You are running the latest version.', 'upshield-waf'); ?>
                                        </p>
                                    <?php endif; ?>
                                </div>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><?php esc_html_e('Check for Updates', 'upshield-waf'); ?></th>
                            <td>
                                <button type="button" id="upshield-check-update-btn" class="button button-secondary">
                                    <span class="dashicons dashicons-update"></span>
                                    <?php esc_html_e('Check Now', 'upshield-waf'); ?>
                                </button>
                                <span id="upshield-update-message" style="margin-left: 10px; font-style: italic;"></span>
                                <p class="description">
                                    <?php esc_html_e('Manually check for new versions from GitHub Releases.', 'upshield-waf'); ?>
                                </p>
                            </td>
                        </tr>
                    </table>
                </div>
            </div>

            <!-- Support & Links -->
            <div class="upshield-card">
                <div class="card-header">
                    <h2>
                        <span class="dashicons dashicons-sos"></span>
                        <?php esc_html_e('Support & Resources', 'upshield-waf'); ?>
                    </h2>
                </div>
                <div class="card-body">
                    <div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(250px, 1fr)); gap: 15px;">
                        <a href="https://github.com/UpShield-Security/upshield-waf" target="_blank" class="button button-secondary" style="display: flex; align-items: center; gap: 8px; justify-content: center; padding: 12px 15px; height: auto;">
                            <span class="dashicons dashicons-editor-code"></span>
                            <?php esc_html_e('GitHub Repository', 'upshield-waf'); ?>
                        </a>
                        <a href="https://github.com/UpShield-Security/upshield-waf/issues" target="_blank" class="button button-secondary" style="display: flex; align-items: center; gap: 8px; justify-content: center; padding: 12px 15px; height: auto;">
                            <span class="dashicons dashicons-flag"></span>
                            <?php esc_html_e('Report an Issue', 'upshield-waf'); ?>
                        </a>
                        <a href="https://github.com/UpShield-Security/upshield-waf/releases" target="_blank" class="button button-secondary" style="display: flex; align-items: center; gap: 8px; justify-content: center; padding: 12px 15px; height: auto;">
                            <span class="dashicons dashicons-download"></span>
                            <?php esc_html_e('Release Notes', 'upshield-waf'); ?>
                        </a>
                        <a href="https://github.com/UpShield-Security/upshield-waf/wiki" target="_blank" class="button button-secondary" style="display: flex; align-items: center; gap: 8px; justify-content: center; padding: 12px 15px; height: auto;">
                            <span class="dashicons dashicons-book"></span>
                            <?php esc_html_e('Documentation', 'upshield-waf'); ?>
                        </a>
                    </div>
                    
                    <div class="notice notice-info inline" style="margin: 20px 0 0;">
                        <p>
                            <strong><?php esc_html_e('Need help?', 'upshield-waf'); ?></strong>
                            <?php esc_html_e('If you encounter any issues or have feature requests, please create an issue on our GitHub repository. We respond to all issues within 24-48 hours.', 'upshield-waf'); ?>
                        </p>
                    </div>
                </div>
            </div>

            <!-- Credits -->
            <div class="upshield-card">
                <div class="card-header">
                    <h2>
                        <span class="dashicons dashicons-heart"></span>
                        <?php esc_html_e('Credits', 'upshield-waf'); ?>
                    </h2>
                </div>
                <div class="card-body">
                    <p><?php esc_html_e('UpShield WAF is an open-source project developed with ❤️ by the UpShield Security team.', 'upshield-waf'); ?></p>
                    <p><?php esc_html_e('This plugin uses the following technologies and services:', 'upshield-waf'); ?></p>
                    <ul style="list-style: disc; margin-left: 20px;">
                        <li><?php esc_html_e('UpShield Threat Intelligence API - Community-powered threat feed', 'upshield-waf'); ?></li>
                        <li><?php esc_html_e('MaxMind GeoLite2 - IP geolocation data', 'upshield-waf'); ?></li>
                        <li><?php esc_html_e('Google reCAPTCHA / Cloudflare Turnstile / hCaptcha - CAPTCHA providers', 'upshield-waf'); ?></li>
                    </ul>
                    
                    <div style="margin-top: 20px; padding: 15px; background: #f0f0f1; border-radius: 6px; text-align: center;">
                        <p style="margin: 0 0 10px; font-size: 14px;">
                            <?php esc_html_e('If you find UpShield WAF useful, please consider:', 'upshield-waf'); ?>
                        </p>
                        <a href="https://github.com/UpShield-Security/upshield-waf" target="_blank" class="button button-primary">
                            <span class="dashicons dashicons-star-filled"></span>
                            <?php esc_html_e('Star us on GitHub', 'upshield-waf'); ?>
                        </a>
                    </div>
                </div>
            </div>
        </div>

        <!-- Telegram Alerts (NEW) -->
        <div class="upshield-tab-content" id="telegram">
            <div class="upshield-card">
                <div class="card-header">
                    <h2>
                        <span class="dashicons dashicons-format-chat"></span>
                        <?php esc_html_e('Telegram Alerts', 'upshield-waf'); ?>
                        <span class="badge badge-new" style="margin-left: 10px;">NEW in v1.1</span>
                    </h2>
                </div>
                <div class="card-body">
                    <div class="notice notice-info inline" style="margin: 0 0 20px;">
                        <p>
                            <strong><?php esc_html_e('How to setup:', 'upshield-waf'); ?></strong>
                            <?php esc_html_e('1. Create a bot via @BotFather on Telegram. 2. Get your Chat ID via @userinfobot. 3. Enter both below.', 'upshield-waf'); ?>
                        </p>
                    </div>
                    
                    <table class="form-table">
                        <tr>
                            <th scope="row"><?php esc_html_e('Enable Telegram Alerts', 'upshield-waf'); ?></th>
                            <td>
                                <label class="upshield-switch">
                                    <input type="checkbox" name="upshield_options[telegram_enabled]" value="1" 
                                           <?php checked($vswaf_options['telegram_enabled'] ?? false); ?>>
                                    <span class="slider"></span>
                                </label>
                                <p class="description"><?php esc_html_e('Receive real-time security alerts via Telegram.', 'upshield-waf'); ?></p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><?php esc_html_e('Bot Token', 'upshield-waf'); ?></th>
                            <td>
                                <input type="text" name="upshield_options[telegram_bot_token]" 
                                       value="<?php echo esc_attr($vswaf_options['telegram_bot_token'] ?? ''); ?>" 
                                       class="regular-text" placeholder="123456789:ABCdefGHIjklMNOpqrsTUVwxyz">
                                <p class="description"><?php esc_html_e('Get this from @BotFather when you create your bot.', 'upshield-waf'); ?></p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><?php esc_html_e('Chat ID', 'upshield-waf'); ?></th>
                            <td>
                                <input type="text" name="upshield_options[telegram_chat_id]" 
                                       value="<?php echo esc_attr($vswaf_options['telegram_chat_id'] ?? ''); ?>" 
                                       class="regular-text" placeholder="-1001234567890">
                                <p class="description"><?php esc_html_e('Your personal or group chat ID. Get it from @userinfobot.', 'upshield-waf'); ?></p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><?php esc_html_e('Test Connection', 'upshield-waf'); ?></th>
                            <td>
                                <button type="button" class="button" id="test-telegram-btn">
                                    <span class="dashicons dashicons-admin-plugins" style="vertical-align: text-bottom;"></span>
                                    <?php esc_html_e('Send Test Message', 'upshield-waf'); ?>
                                </button>
                                <span id="telegram-test-result" style="margin-left: 10px;"></span>
                            </td>
                        </tr>
                    </table>
                </div>
            </div>
        </div>

        <!-- Two-Factor Authentication (NEW) -->
        <div class="upshield-tab-content" id="two-factor">
            <div class="upshield-card">
                <div class="card-header">
                    <h2>
                        <span class="dashicons dashicons-smartphone"></span>
                        <?php esc_html_e('Two-Factor Authentication (2FA)', 'upshield-waf'); ?>
                        <span class="badge badge-new" style="margin-left: 10px;">NEW in v1.1</span>
                    </h2>
                </div>
                <div class="card-body">
                    <div class="notice notice-info inline" style="margin: 0 0 20px;">
                        <p>
                            <strong><?php esc_html_e('TOTP-based 2FA', 'upshield-waf'); ?></strong> - 
                            <?php esc_html_e('Compatible with Google Authenticator, Authy, Microsoft Authenticator, and other TOTP apps.', 'upshield-waf'); ?>
                        </p>
                    </div>
                    
                    <table class="form-table">
                        <tr>
                            <th scope="row"><?php esc_html_e('Enable 2FA', 'upshield-waf'); ?></th>
                            <td>
                                <label class="upshield-switch">
                                    <input type="checkbox" name="upshield_options[two_factor_enabled]" value="1" 
                                           <?php checked($vswaf_options['two_factor_enabled'] ?? false); ?>>
                                    <span class="slider"></span>
                                </label>
                                <p class="description"><?php esc_html_e('Enable Two-Factor Authentication for WordPress login.', 'upshield-waf'); ?></p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><?php esc_html_e('Require for Admins', 'upshield-waf'); ?></th>
                            <td>
                                <label class="upshield-switch">
                                    <input type="checkbox" name="upshield_options[two_factor_require_admins]" value="1" 
                                           <?php checked($vswaf_options['two_factor_require_admins'] ?? false); ?>>
                                    <span class="slider"></span>
                                </label>
                                <p class="description"><?php esc_html_e('Force all administrators to set up 2FA.', 'upshield-waf'); ?></p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><?php esc_html_e('User Setup', 'upshield-waf'); ?></th>
                            <td>
                                <p class="description">
                                    <?php esc_html_e('Users can set up 2FA from their Profile page in WordPress admin.', 'upshield-waf'); ?>
                                    <br>
                                    <a href="<?php echo admin_url('profile.php'); ?>" class="button" style="margin-top: 10px;">
                                        <span class="dashicons dashicons-admin-users" style="vertical-align: text-bottom;"></span>
                                        <?php esc_html_e('Go to Profile', 'upshield-waf'); ?>
                                    </a>
                                </p>
                            </td>
                        </tr>
                    </table>
                </div>
            </div>
        </div>

        <!-- Security Headers (NEW) -->
        <div class="upshield-tab-content" id="security-headers">
            <div class="upshield-card">
                <div class="card-header">
                    <h2>
                        <span class="dashicons dashicons-admin-network"></span>
                        <?php esc_html_e('Security Headers', 'upshield-waf'); ?>
                        <span class="badge badge-new" style="margin-left: 10px;">NEW in v1.1</span>
                    </h2>
                </div>
                <div class="card-body">
                    <div class="notice notice-warning inline" style="margin: 0 0 20px;">
                        <p>
                            <strong><?php esc_html_e('Warning:', 'upshield-waf'); ?></strong>
                            <?php esc_html_e('Incorrect header configuration may break your site. Test carefully before enabling on production.', 'upshield-waf'); ?>
                        </p>
                    </div>
                    
                    <table class="form-table">
                        <tr>
                            <th scope="row"><?php esc_html_e('Enable Security Headers', 'upshield-waf'); ?></th>
                            <td>
                                <label class="upshield-switch">
                                    <input type="checkbox" name="upshield_options[security_headers_enabled]" value="1" 
                                           <?php checked($vswaf_options['security_headers_enabled'] ?? false); ?>>
                                    <span class="slider"></span>
                                </label>
                                <p class="description"><?php esc_html_e('Add HTTP security headers to protect against common attacks.', 'upshield-waf'); ?></p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><?php esc_html_e('Skip Admin Pages', 'upshield-waf'); ?></th>
                            <td>
                                <label class="upshield-switch">
                                    <input type="checkbox" name="upshield_options[security_headers_skip_admin]" value="1" 
                                           <?php checked($vswaf_options['security_headers_skip_admin'] ?? true); ?>>
                                    <span class="slider"></span>
                                </label>
                                <p class="description"><?php esc_html_e('Do not apply headers to admin and login pages (recommended).', 'upshield-waf'); ?></p>
                            </td>
                        </tr>
                    </table>
                    
                    <hr style="margin: 25px 0;">
                    <h3 style="margin-top: 0;"><?php esc_html_e('Basic Headers', 'upshield-waf'); ?></h3>
                    
                    <table class="form-table">
                        <tr>
                            <th scope="row"><?php esc_html_e('X-Frame-Options', 'upshield-waf'); ?></th>
                            <td>
                                <label class="upshield-switch">
                                    <input type="checkbox" name="upshield_options[header_x_frame_options]" value="1" 
                                           <?php checked($vswaf_options['header_x_frame_options'] ?? true); ?>>
                                    <span class="slider"></span>
                                </label>
                                <select name="upshield_options[header_x_frame_options_value]" style="margin-left: 10px;">
                                    <option value="DENY" <?php selected($vswaf_options['header_x_frame_options_value'] ?? 'SAMEORIGIN', 'DENY'); ?>>DENY</option>
                                    <option value="SAMEORIGIN" <?php selected($vswaf_options['header_x_frame_options_value'] ?? 'SAMEORIGIN', 'SAMEORIGIN'); ?>>SAMEORIGIN</option>
                                </select>
                                <p class="description"><?php esc_html_e('Prevents clickjacking attacks by controlling iframe embedding.', 'upshield-waf'); ?></p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><?php esc_html_e('X-Content-Type-Options', 'upshield-waf'); ?></th>
                            <td>
                                <label class="upshield-switch">
                                    <input type="checkbox" name="upshield_options[header_x_content_type]" value="1" 
                                           <?php checked($vswaf_options['header_x_content_type'] ?? true); ?>>
                                    <span class="slider"></span>
                                </label>
                                <p class="description"><?php esc_html_e('Prevents MIME type sniffing (nosniff).', 'upshield-waf'); ?></p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><?php esc_html_e('X-XSS-Protection', 'upshield-waf'); ?></th>
                            <td>
                                <label class="upshield-switch">
                                    <input type="checkbox" name="upshield_options[header_x_xss_protection]" value="1" 
                                           <?php checked($vswaf_options['header_x_xss_protection'] ?? true); ?>>
                                    <span class="slider"></span>
                                </label>
                                <p class="description"><?php esc_html_e('Legacy XSS protection for older browsers.', 'upshield-waf'); ?></p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><?php esc_html_e('Referrer-Policy', 'upshield-waf'); ?></th>
                            <td>
                                <label class="upshield-switch">
                                    <input type="checkbox" name="upshield_options[header_referrer_policy]" value="1" 
                                           <?php checked($vswaf_options['header_referrer_policy'] ?? true); ?>>
                                    <span class="slider"></span>
                                </label>
                                <select name="upshield_options[header_referrer_policy_value]" style="margin-left: 10px;">
                                    <option value="no-referrer" <?php selected($vswaf_options['header_referrer_policy_value'] ?? 'strict-origin-when-cross-origin', 'no-referrer'); ?>>no-referrer</option>
                                    <option value="no-referrer-when-downgrade" <?php selected($vswaf_options['header_referrer_policy_value'] ?? 'strict-origin-when-cross-origin', 'no-referrer-when-downgrade'); ?>>no-referrer-when-downgrade</option>
                                    <option value="same-origin" <?php selected($vswaf_options['header_referrer_policy_value'] ?? 'strict-origin-when-cross-origin', 'same-origin'); ?>>same-origin</option>
                                    <option value="strict-origin" <?php selected($vswaf_options['header_referrer_policy_value'] ?? 'strict-origin-when-cross-origin', 'strict-origin'); ?>>strict-origin</option>
                                    <option value="strict-origin-when-cross-origin" <?php selected($vswaf_options['header_referrer_policy_value'] ?? 'strict-origin-when-cross-origin', 'strict-origin-when-cross-origin'); ?>>strict-origin-when-cross-origin</option>
                                </select>
                                <p class="description"><?php esc_html_e('Controls referrer information sent with requests.', 'upshield-waf'); ?></p>
                            </td>
                        </tr>
                    </table>
                    
                    <hr style="margin: 25px 0;">
                    <h3 style="margin-top: 0;"><?php esc_html_e('HSTS (HTTPS Only)', 'upshield-waf'); ?></h3>
                    
                    <table class="form-table">
                        <tr>
                            <th scope="row"><?php esc_html_e('Enable HSTS', 'upshield-waf'); ?></th>
                            <td>
                                <label class="upshield-switch">
                                    <input type="checkbox" name="upshield_options[header_hsts_enabled]" value="1" 
                                           <?php checked($vswaf_options['header_hsts_enabled'] ?? false); ?>>
                                    <span class="slider"></span>
                                </label>
                                <p class="description"><?php esc_html_e('Force HTTPS connections. Only enable if your site has SSL!', 'upshield-waf'); ?></p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><?php esc_html_e('Max Age', 'upshield-waf'); ?></th>
                            <td>
                                <select name="upshield_options[header_hsts_max_age]">
                                    <option value="86400" <?php selected($vswaf_options['header_hsts_max_age'] ?? 31536000, 86400); ?>>1 day</option>
                                    <option value="604800" <?php selected($vswaf_options['header_hsts_max_age'] ?? 31536000, 604800); ?>>1 week</option>
                                    <option value="2592000" <?php selected($vswaf_options['header_hsts_max_age'] ?? 31536000, 2592000); ?>>1 month</option>
                                    <option value="31536000" <?php selected($vswaf_options['header_hsts_max_age'] ?? 31536000, 31536000); ?>>1 year</option>
                                </select>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><?php esc_html_e('Include Subdomains', 'upshield-waf'); ?></th>
                            <td>
                                <label class="upshield-switch">
                                    <input type="checkbox" name="upshield_options[header_hsts_subdomains]" value="1" 
                                           <?php checked($vswaf_options['header_hsts_subdomains'] ?? false); ?>>
                                    <span class="slider"></span>
                                </label>
                            </td>
                        </tr>
                    </table>
                </div>
            </div>
        </div>

        <?php submit_button(__('Save Settings', 'upshield-waf'), 'primary', 'submit', true); ?>
    </form>
    
    <?php include UPSHIELD_PLUGIN_DIR . 'admin/views/partials/footer.php'; ?>
</div>


