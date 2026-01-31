<?php
/**
 * Telegram Integration for UpShield WAF
 * 
 * Sends real-time security alerts via Telegram bot
 * 
 * @package UpShield_WAF
 * @since 1.1.0
 */

namespace UpShield\Integrations;

if (!defined('ABSPATH')) {
    exit;
}

class TelegramAlerts {
    
    /**
     * Telegram Bot API URL
     */
    private const API_URL = 'https://api.telegram.org/bot';
    
    /**
     * Bot token
     */
    private $bot_token;
    
    /**
     * Chat ID
     */
    private $chat_id;
    
    /**
     * Options
     */
    private $options;
    
    /**
     * Constructor
     */
    public function __construct() {
        $this->options = get_option('upshield_options', []);
        $this->bot_token = $this->options['telegram_bot_token'] ?? '';
        $this->chat_id = $this->options['telegram_chat_id'] ?? '';
        
        if ($this->is_enabled()) {
            add_action('upshield_attack_blocked', [$this, 'send_attack_alert'], 10, 2);
            add_action('upshield_login_failed', [$this, 'send_login_alert'], 10, 2);
            add_action('upshield_malware_detected', [$this, 'send_malware_alert'], 10, 1);
        }
    }
    
    /**
     * Check if Telegram alerts are enabled
     */
    public function is_enabled() {
        return !empty($this->options['telegram_enabled']) 
            && !empty($this->bot_token) 
            && !empty($this->chat_id);
    }
    
    /**
     * Send message via Telegram
     */
    public function send_message($message, $parse_mode = 'HTML') {
        if (!$this->is_enabled()) {
            return false;
        }
        
        $url = self::API_URL . $this->bot_token . '/sendMessage';
        
        $data = [
            'chat_id' => $this->chat_id,
            'text' => $message,
            'parse_mode' => $parse_mode,
            'disable_web_page_preview' => true,
        ];
        
        $response = wp_remote_post($url, [
            'body' => $data,
            'timeout' => 10,
        ]);
        
        if (is_wp_error($response)) {
            error_log('UpShield Telegram Error: ' . $response->get_error_message());
            return false;
        }
        
        $body = json_decode(wp_remote_retrieve_body($response), true);
        
        return $body['ok'] ?? false;
    }
    
    /**
     * Send attack blocked alert
     */
    public function send_attack_alert($attack_data, $request_data) {
        $site_name = get_bloginfo('name');
        $site_url = home_url();
        
        $severity_emoji = $this->get_severity_emoji($attack_data['severity'] ?? 'medium');
        $attack_type = strtoupper($attack_data['type'] ?? 'UNKNOWN');
        
        $message = "{$severity_emoji} <b>Attack Blocked!</b>\n\n";
        $message .= "🌐 <b>Site:</b> {$site_name}\n";
        $message .= "🎯 <b>Type:</b> {$attack_type}\n";
        $message .= "📍 <b>IP:</b> <code>{$request_data['ip']}</code>\n";
        
        if (!empty($request_data['country'])) {
            $message .= "🌍 <b>Country:</b> {$request_data['country']}\n";
        }
        
        $message .= "🔗 <b>URI:</b> <code>" . esc_html(substr($request_data['uri'] ?? '/', 0, 100)) . "</code>\n";
        $message .= "⏰ <b>Time:</b> " . current_time('Y-m-d H:i:s') . "\n\n";
        $message .= "🔒 <a href=\"{$site_url}/wp-admin/admin.php?page=upshield-waf\">View Dashboard</a>";
        
        $this->send_message($message);
    }
    
    /**
     * Send failed login alert
     */
    public function send_login_alert($username, $ip) {
        // Rate limit: max 1 alert per IP per 5 minutes
        $cache_key = 'upshield_tg_login_' . md5($ip);
        if (get_transient($cache_key)) {
            return;
        }
        set_transient($cache_key, 1, 5 * MINUTE_IN_SECONDS);
        
        $site_name = get_bloginfo('name');
        $site_url = home_url();
        
        $message = "⚠️ <b>Failed Login Attempt!</b>\n\n";
        $message .= "🌐 <b>Site:</b> {$site_name}\n";
        $message .= "👤 <b>Username:</b> <code>{$username}</code>\n";
        $message .= "📍 <b>IP:</b> <code>{$ip}</code>\n";
        $message .= "⏰ <b>Time:</b> " . current_time('Y-m-d H:i:s') . "\n\n";
        $message .= "🔒 <a href=\"{$site_url}/wp-admin/admin.php?page=upshield-login\">View Login Security</a>";
        
        $this->send_message($message);
    }
    
    /**
     * Send malware detected alert
     */
    public function send_malware_alert($scan_result) {
        $site_name = get_bloginfo('name');
        $site_url = home_url();
        
        $infected_count = $scan_result['infected_count'] ?? 0;
        
        $message = "🦠 <b>Malware Detected!</b>\n\n";
        $message .= "🌐 <b>Site:</b> {$site_name}\n";
        $message .= "📁 <b>Infected Files:</b> {$infected_count}\n";
        $message .= "⏰ <b>Time:</b> " . current_time('Y-m-d H:i:s') . "\n\n";
        $message .= "🔒 <a href=\"{$site_url}/wp-admin/admin.php?page=upshield-malware-scanner\">View Scan Results</a>";
        
        $this->send_message($message);
    }
    
    /**
     * Get emoji for severity level
     */
    private function get_severity_emoji($severity) {
        $emojis = [
            'critical' => '🔴',
            'high' => '🟠',
            'medium' => '🟡',
            'low' => '🟢',
        ];
        
        return $emojis[$severity] ?? '⚪';
    }
    
    /**
     * Test connection
     */
    public function test_connection() {
        $site_name = get_bloginfo('name');
        
        $message = "✅ <b>UpShield WAF Connected!</b>\n\n";
        $message .= "🌐 <b>Site:</b> {$site_name}\n";
        $message .= "⏰ <b>Time:</b> " . current_time('Y-m-d H:i:s') . "\n\n";
        $message .= "You will now receive security alerts from this site.";
        
        return $this->send_message($message);
    }
    
    /**
     * Validate bot token format
     */
    public static function validate_token($token) {
        return preg_match('/^\d+:[A-Za-z0-9_-]+$/', $token);
    }
    
    /**
     * Validate chat ID format
     */
    public static function validate_chat_id($chat_id) {
        return preg_match('/^-?\d+$/', $chat_id);
    }
}
