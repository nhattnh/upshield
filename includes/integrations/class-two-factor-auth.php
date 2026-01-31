<?php
/**
 * Two-Factor Authentication for UpShield WAF
 * 
 * TOTP-based 2FA compatible with Google Authenticator, Authy, etc.
 * 
 * @package UpShield_WAF
 * @since 1.1.0
 */

namespace UpShield\Integrations;

if (!defined('ABSPATH')) {
    exit;
}

class TwoFactorAuth {
    
    /**
     * Secret key length
     */
    private const SECRET_LENGTH = 16;
    
    /**
     * OTP valid period (seconds)
     */
    private const OTP_PERIOD = 30;
    
    /**
     * OTP digits
     */
    private const OTP_DIGITS = 6;
    
    /**
     * Base32 alphabet
     */
    private const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    
    /**
     * Options
     */
    private $options;
    
    /**
     * Constructor
     */
    public function __construct() {
        $this->options = get_option('upshield_options', []);
        
        if ($this->is_enabled()) {
            // Add 2FA to login process
            add_action('wp_login', [$this, 'check_2fa_required'], 10, 2);
            add_filter('authenticate', [$this, 'validate_2fa_code'], 100, 3);
            
            // Add 2FA setup to user profile
            add_action('show_user_profile', [$this, 'render_2fa_setup']);
            add_action('edit_user_profile', [$this, 'render_2fa_setup']);
            add_action('personal_options_update', [$this, 'save_2fa_settings']);
            add_action('edit_user_profile_update', [$this, 'save_2fa_settings']);
            
            // AJAX handlers
            add_action('wp_ajax_upshield_generate_2fa_secret', [$this, 'ajax_generate_secret']);
            add_action('wp_ajax_upshield_verify_2fa_setup', [$this, 'ajax_verify_setup']);
            add_action('wp_ajax_upshield_disable_2fa', [$this, 'ajax_disable_2fa']);
            
            // Custom login form
            add_action('login_form', [$this, 'add_2fa_field']);
        }
    }
    
    /**
     * Check if 2FA is enabled globally
     */
    public function is_enabled() {
        return !empty($this->options['two_factor_enabled']);
    }
    
    /**
     * Check if user has 2FA enabled
     */
    public function user_has_2fa($user_id) {
        return (bool) get_user_meta($user_id, 'upshield_2fa_enabled', true);
    }
    
    /**
     * Get user's secret key
     */
    public function get_user_secret($user_id) {
        return get_user_meta($user_id, 'upshield_2fa_secret', true);
    }
    
    /**
     * Generate a new secret key
     */
    public function generate_secret() {
        $secret = '';
        for ($i = 0; $i < self::SECRET_LENGTH; $i++) {
            $secret .= self::BASE32_ALPHABET[random_int(0, 31)];
        }
        return $secret;
    }
    
    /**
     * Generate TOTP code
     */
    public function get_code($secret, $time = null) {
        if ($time === null) {
            $time = time();
        }
        
        $time = floor($time / self::OTP_PERIOD);
        
        // Decode base32 secret
        $secret_decoded = $this->base32_decode($secret);
        
        // Pack time into binary string
        $time_packed = pack('N*', 0) . pack('N*', $time);
        
        // HMAC-SHA1
        $hash = hash_hmac('sha1', $time_packed, $secret_decoded, true);
        
        // Dynamic truncation
        $offset = ord(substr($hash, -1)) & 0x0F;
        $code = (
            ((ord($hash[$offset]) & 0x7F) << 24) |
            ((ord($hash[$offset + 1]) & 0xFF) << 16) |
            ((ord($hash[$offset + 2]) & 0xFF) << 8) |
            (ord($hash[$offset + 3]) & 0xFF)
        ) % pow(10, self::OTP_DIGITS);
        
        return str_pad($code, self::OTP_DIGITS, '0', STR_PAD_LEFT);
    }
    
    /**
     * Verify TOTP code
     */
    public function verify_code($secret, $code, $window = 1) {
        $code = preg_replace('/\s+/', '', $code);
        
        if (strlen($code) !== self::OTP_DIGITS) {
            return false;
        }
        
        $time = time();
        
        // Check current and adjacent time windows
        for ($i = -$window; $i <= $window; $i++) {
            $check_time = $time + ($i * self::OTP_PERIOD);
            if (hash_equals($this->get_code($secret, $check_time), $code)) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Generate QR code URL for authenticator apps
     */
    public function get_qr_code_url($secret, $user_email) {
        $site_name = rawurlencode(get_bloginfo('name') . ' (UpShield)');
        $email = rawurlencode($user_email);
        
        $otpauth = "otpauth://totp/{$site_name}:{$email}?secret={$secret}&issuer={$site_name}";
        
        // Use Google Chart API for QR code
        return 'https://chart.googleapis.com/chart?chs=200x200&chld=M|0&cht=qr&chl=' . urlencode($otpauth);
    }
    
    /**
     * Base32 decode
     */
    private function base32_decode($input) {
        $input = strtoupper($input);
        $output = '';
        $v = 0;
        $vbits = 0;
        
        for ($i = 0, $length = strlen($input); $i < $length; $i++) {
            $pos = strpos(self::BASE32_ALPHABET, $input[$i]);
            if ($pos === false) {
                continue;
            }
            
            $v = ($v << 5) | $pos;
            $vbits += 5;
            
            if ($vbits >= 8) {
                $output .= chr(($v >> ($vbits - 8)) & 0xFF);
                $vbits -= 8;
            }
        }
        
        return $output;
    }
    
    /**
     * Add 2FA field to login form
     */
    public function add_2fa_field() {
        ?>
        <p id="upshield-2fa-field" style="display:none;">
            <label for="upshield_2fa_code"><?php esc_html_e('Authentication Code', 'upshield-waf'); ?></label>
            <input type="text" name="upshield_2fa_code" id="upshield_2fa_code" 
                   class="input" size="6" autocomplete="off" 
                   placeholder="<?php esc_attr_e('Enter 6-digit code', 'upshield-waf'); ?>">
            <small><?php esc_html_e('Enter the code from your authenticator app', 'upshield-waf'); ?></small>
        </p>
        <script>
        (function() {
            var field = document.getElementById('upshield-2fa-field');
            var userField = document.getElementById('user_login');
            if (userField) {
                userField.addEventListener('blur', function() {
                    // Show 2FA field after username is entered
                    // In production, this would check via AJAX if user has 2FA
                    field.style.display = 'block';
                });
            }
        })();
        </script>
        <?php
    }
    
    /**
     * Validate 2FA during authentication
     */
    public function validate_2fa_code($user, $username, $password) {
        if (is_wp_error($user)) {
            return $user;
        }
        
        if (!($user instanceof \WP_User)) {
            return $user;
        }
        
        // Check if user has 2FA enabled
        if (!$this->user_has_2fa($user->ID)) {
            return $user;
        }
        
        $code = isset($_POST['upshield_2fa_code']) ? sanitize_text_field($_POST['upshield_2fa_code']) : '';
        
        if (empty($code)) {
            return new \WP_Error(
                'upshield_2fa_required',
                __('Authentication code is required.', 'upshield-waf')
            );
        }
        
        $secret = $this->get_user_secret($user->ID);
        
        if (!$this->verify_code($secret, $code)) {
            // Log failed 2FA attempt
            do_action('upshield_2fa_failed', $user->ID, $code);
            
            return new \WP_Error(
                'upshield_2fa_invalid',
                __('Invalid authentication code. Please try again.', 'upshield-waf')
            );
        }
        
        return $user;
    }
    
    /**
     * Render 2FA setup in user profile
     */
    public function render_2fa_setup($user) {
        // Only show for users who can manage options or their own profile
        if (!current_user_can('edit_user', $user->ID)) {
            return;
        }
        
        $is_enabled = $this->user_has_2fa($user->ID);
        $secret = $this->get_user_secret($user->ID);
        
        ?>
        <h2><?php esc_html_e('Two-Factor Authentication (UpShield)', 'upshield-waf'); ?></h2>
        <table class="form-table" role="presentation">
            <tr>
                <th><?php esc_html_e('Status', 'upshield-waf'); ?></th>
                <td>
                    <?php if ($is_enabled): ?>
                        <span style="color: green;">✓ <?php esc_html_e('Enabled', 'upshield-waf'); ?></span>
                        <p>
                            <button type="button" class="button" id="upshield-disable-2fa">
                                <?php esc_html_e('Disable 2FA', 'upshield-waf'); ?>
                            </button>
                        </p>
                    <?php else: ?>
                        <span style="color: gray;">✗ <?php esc_html_e('Not enabled', 'upshield-waf'); ?></span>
                        <p>
                            <button type="button" class="button button-primary" id="upshield-setup-2fa">
                                <?php esc_html_e('Set up 2FA', 'upshield-waf'); ?>
                            </button>
                        </p>
                        <div id="upshield-2fa-setup" style="display:none; margin-top:20px;">
                            <p><?php esc_html_e('Scan this QR code with your authenticator app:', 'upshield-waf'); ?></p>
                            <img id="upshield-2fa-qr" src="" alt="QR Code">
                            <p><?php esc_html_e('Or enter this secret manually:', 'upshield-waf'); ?> <code id="upshield-2fa-secret"></code></p>
                            <p>
                                <label for="upshield-verify-code"><?php esc_html_e('Verify with code from app:', 'upshield-waf'); ?></label><br>
                                <input type="text" id="upshield-verify-code" class="regular-text" placeholder="123456">
                                <button type="button" class="button button-primary" id="upshield-verify-2fa">
                                    <?php esc_html_e('Verify & Enable', 'upshield-waf'); ?>
                                </button>
                            </p>
                        </div>
                    <?php endif; ?>
                </td>
            </tr>
        </table>
        <script>
        jQuery(function($) {
            $('#upshield-setup-2fa').on('click', function() {
                $.post(ajaxurl, {
                    action: 'upshield_generate_2fa_secret',
                    user_id: <?php echo (int) $user->ID; ?>,
                    nonce: '<?php echo wp_create_nonce('upshield_2fa'); ?>'
                }, function(response) {
                    if (response.success) {
                        $('#upshield-2fa-qr').attr('src', response.data.qr_url);
                        $('#upshield-2fa-secret').text(response.data.secret);
                        $('#upshield-2fa-setup').slideDown();
                    }
                });
            });
            
            $('#upshield-verify-2fa').on('click', function() {
                var code = $('#upshield-verify-code').val();
                $.post(ajaxurl, {
                    action: 'upshield_verify_2fa_setup',
                    user_id: <?php echo (int) $user->ID; ?>,
                    code: code,
                    nonce: '<?php echo wp_create_nonce('upshield_2fa'); ?>'
                }, function(response) {
                    if (response.success) {
                        alert('2FA enabled successfully!');
                        location.reload();
                    } else {
                        alert('Invalid code. Please try again.');
                    }
                });
            });
            
            $('#upshield-disable-2fa').on('click', function() {
                if (confirm('Are you sure you want to disable 2FA?')) {
                    $.post(ajaxurl, {
                        action: 'upshield_disable_2fa',
                        user_id: <?php echo (int) $user->ID; ?>,
                        nonce: '<?php echo wp_create_nonce('upshield_2fa'); ?>'
                    }, function(response) {
                        if (response.success) {
                            alert('2FA disabled.');
                            location.reload();
                        }
                    });
                }
            });
        });
        </script>
        <?php
    }
    
    /**
     * AJAX: Generate new secret
     */
    public function ajax_generate_secret() {
        check_ajax_referer('upshield_2fa', 'nonce');
        
        $user_id = isset($_POST['user_id']) ? absint($_POST['user_id']) : 0;
        
        if (!current_user_can('edit_user', $user_id)) {
            wp_send_json_error('Unauthorized');
        }
        
        $user = get_user_by('id', $user_id);
        $secret = $this->generate_secret();
        
        // Store temporarily
        set_transient('upshield_2fa_temp_' . $user_id, $secret, HOUR_IN_SECONDS);
        
        wp_send_json_success([
            'secret' => $secret,
            'qr_url' => $this->get_qr_code_url($secret, $user->user_email),
        ]);
    }
    
    /**
     * AJAX: Verify setup
     */
    public function ajax_verify_setup() {
        check_ajax_referer('upshield_2fa', 'nonce');
        
        $user_id = isset($_POST['user_id']) ? absint($_POST['user_id']) : 0;
        $code = isset($_POST['code']) ? sanitize_text_field($_POST['code']) : '';
        
        if (!current_user_can('edit_user', $user_id)) {
            wp_send_json_error('Unauthorized');
        }
        
        $secret = get_transient('upshield_2fa_temp_' . $user_id);
        
        if (!$secret || !$this->verify_code($secret, $code)) {
            wp_send_json_error('Invalid code');
        }
        
        // Save secret and enable 2FA
        update_user_meta($user_id, 'upshield_2fa_secret', $secret);
        update_user_meta($user_id, 'upshield_2fa_enabled', 1);
        delete_transient('upshield_2fa_temp_' . $user_id);
        
        wp_send_json_success();
    }
    
    /**
     * AJAX: Disable 2FA
     */
    public function ajax_disable_2fa() {
        check_ajax_referer('upshield_2fa', 'nonce');
        
        $user_id = isset($_POST['user_id']) ? absint($_POST['user_id']) : 0;
        
        if (!current_user_can('edit_user', $user_id)) {
            wp_send_json_error('Unauthorized');
        }
        
        delete_user_meta($user_id, 'upshield_2fa_secret');
        delete_user_meta($user_id, 'upshield_2fa_enabled');
        
        wp_send_json_success();
    }
}
