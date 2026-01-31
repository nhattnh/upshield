<?php
/**
 * Security Headers for UpShield WAF
 * 
 * Adds HTTP security headers to protect against common attacks
 * 
 * @package UpShield_WAF
 * @since 1.1.0
 */

namespace UpShield\Firewall;

if (!defined('ABSPATH')) {
    exit;
}

class SecurityHeaders {
    
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
            add_action('send_headers', [$this, 'send_security_headers'], 1);
        }
    }
    
    /**
     * Check if security headers are enabled
     */
    public function is_enabled() {
        return !empty($this->options['security_headers_enabled']);
    }
    
    /**
     * Send security headers
     */
    public function send_security_headers() {
        // Don't send headers for admin or login pages if option is set
        if (!empty($this->options['security_headers_skip_admin'])) {
            if (is_admin() || $this->is_login_page()) {
                return;
            }
        }
        
        // X-Frame-Options - Prevents clickjacking
        if (!empty($this->options['header_x_frame_options'])) {
            $value = $this->options['header_x_frame_options_value'] ?? 'SAMEORIGIN';
            header('X-Frame-Options: ' . $value);
        }
        
        // X-Content-Type-Options - Prevents MIME type sniffing
        if (!empty($this->options['header_x_content_type'])) {
            header('X-Content-Type-Options: nosniff');
        }
        
        // X-XSS-Protection - Legacy XSS protection
        if (!empty($this->options['header_x_xss_protection'])) {
            header('X-XSS-Protection: 1; mode=block');
        }
        
        // Referrer-Policy - Controls referrer information
        if (!empty($this->options['header_referrer_policy'])) {
            $value = $this->options['header_referrer_policy_value'] ?? 'strict-origin-when-cross-origin';
            header('Referrer-Policy: ' . $value);
        }
        
        // Permissions-Policy (Feature-Policy) - Controls browser features
        if (!empty($this->options['header_permissions_policy'])) {
            $policy = $this->build_permissions_policy();
            if (!empty($policy)) {
                header('Permissions-Policy: ' . $policy);
            }
        }
        
        // Content-Security-Policy
        if (!empty($this->options['header_csp_enabled'])) {
            $csp = $this->build_csp();
            if (!empty($csp)) {
                $header_name = !empty($this->options['header_csp_report_only']) 
                    ? 'Content-Security-Policy-Report-Only' 
                    : 'Content-Security-Policy';
                header($header_name . ': ' . $csp);
            }
        }
        
        // Strict-Transport-Security (HSTS)
        if (!empty($this->options['header_hsts_enabled']) && is_ssl()) {
            $max_age = $this->options['header_hsts_max_age'] ?? 31536000; // 1 year
            $hsts = 'max-age=' . absint($max_age);
            
            if (!empty($this->options['header_hsts_subdomains'])) {
                $hsts .= '; includeSubDomains';
            }
            
            if (!empty($this->options['header_hsts_preload'])) {
                $hsts .= '; preload';
            }
            
            header('Strict-Transport-Security: ' . $hsts);
        }
        
        // Cross-Origin-Embedder-Policy
        if (!empty($this->options['header_coep'])) {
            header('Cross-Origin-Embedder-Policy: require-corp');
        }
        
        // Cross-Origin-Opener-Policy
        if (!empty($this->options['header_coop'])) {
            header('Cross-Origin-Opener-Policy: same-origin');
        }
        
        // Cross-Origin-Resource-Policy
        if (!empty($this->options['header_corp'])) {
            $value = $this->options['header_corp_value'] ?? 'same-origin';
            header('Cross-Origin-Resource-Policy: ' . $value);
        }
    }
    
    /**
     * Build Content-Security-Policy header
     */
    private function build_csp() {
        $directives = [];
        
        // Default-src
        $default_src = $this->options['csp_default_src'] ?? "'self'";
        if (!empty($default_src)) {
            $directives[] = "default-src {$default_src}";
        }
        
        // Script-src
        $script_src = $this->options['csp_script_src'] ?? "'self' 'unsafe-inline' 'unsafe-eval'";
        if (!empty($script_src)) {
            $directives[] = "script-src {$script_src}";
        }
        
        // Style-src
        $style_src = $this->options['csp_style_src'] ?? "'self' 'unsafe-inline'";
        if (!empty($style_src)) {
            $directives[] = "style-src {$style_src}";
        }
        
        // Img-src
        $img_src = $this->options['csp_img_src'] ?? "'self' data: https:";
        if (!empty($img_src)) {
            $directives[] = "img-src {$img_src}";
        }
        
        // Font-src
        $font_src = $this->options['csp_font_src'] ?? "'self' data:";
        if (!empty($font_src)) {
            $directives[] = "font-src {$font_src}";
        }
        
        // Connect-src
        $connect_src = $this->options['csp_connect_src'] ?? "'self'";
        if (!empty($connect_src)) {
            $directives[] = "connect-src {$connect_src}";
        }
        
        // Frame-src
        $frame_src = $this->options['csp_frame_src'] ?? "'self'";
        if (!empty($frame_src)) {
            $directives[] = "frame-src {$frame_src}";
        }
        
        // Frame-ancestors
        $frame_ancestors = $this->options['csp_frame_ancestors'] ?? "'self'";
        if (!empty($frame_ancestors)) {
            $directives[] = "frame-ancestors {$frame_ancestors}";
        }
        
        // Object-src
        $directives[] = "object-src 'none'";
        
        // Base-uri
        $directives[] = "base-uri 'self'";
        
        // Form-action
        $form_action = $this->options['csp_form_action'] ?? "'self'";
        if (!empty($form_action)) {
            $directives[] = "form-action {$form_action}";
        }
        
        // Upgrade-insecure-requests
        if (!empty($this->options['csp_upgrade_insecure'])) {
            $directives[] = "upgrade-insecure-requests";
        }
        
        return implode('; ', $directives);
    }
    
    /**
     * Build Permissions-Policy header
     */
    private function build_permissions_policy() {
        $policies = [];
        
        // Camera
        if (!empty($this->options['pp_camera_disabled'])) {
            $policies[] = 'camera=()';
        }
        
        // Microphone
        if (!empty($this->options['pp_microphone_disabled'])) {
            $policies[] = 'microphone=()';
        }
        
        // Geolocation
        if (!empty($this->options['pp_geolocation_disabled'])) {
            $policies[] = 'geolocation=()';
        }
        
        // Payment
        if (!empty($this->options['pp_payment_disabled'])) {
            $policies[] = 'payment=()';
        }
        
        // USB
        if (!empty($this->options['pp_usb_disabled'])) {
            $policies[] = 'usb=()';
        }
        
        // Interest-cohort (FLoC)
        $policies[] = 'interest-cohort=()';
        
        return implode(', ', $policies);
    }
    
    /**
     * Check if current page is login
     */
    private function is_login_page() {
        return in_array($GLOBALS['pagenow'], ['wp-login.php', 'wp-register.php'], true);
    }
    
    /**
     * Get default options for security headers
     */
    public static function get_defaults() {
        return [
            'security_headers_enabled' => false,
            'security_headers_skip_admin' => true,
            'header_x_frame_options' => true,
            'header_x_frame_options_value' => 'SAMEORIGIN',
            'header_x_content_type' => true,
            'header_x_xss_protection' => true,
            'header_referrer_policy' => true,
            'header_referrer_policy_value' => 'strict-origin-when-cross-origin',
            'header_permissions_policy' => true,
            'header_hsts_enabled' => false,
            'header_hsts_max_age' => 31536000,
            'header_hsts_subdomains' => false,
            'header_hsts_preload' => false,
            'header_csp_enabled' => false,
            'header_csp_report_only' => true,
            'csp_default_src' => "'self'",
            'csp_script_src' => "'self' 'unsafe-inline' 'unsafe-eval'",
            'csp_style_src' => "'self' 'unsafe-inline'",
            'csp_img_src' => "'self' data: https:",
            'csp_font_src' => "'self' data:",
            'csp_connect_src' => "'self'",
            'csp_frame_src' => "'self'",
            'csp_frame_ancestors' => "'self'",
            'csp_form_action' => "'self'",
            'csp_upgrade_insecure' => false,
            'pp_camera_disabled' => true,
            'pp_microphone_disabled' => true,
            'pp_geolocation_disabled' => false,
            'pp_payment_disabled' => false,
            'pp_usb_disabled' => true,
        ];
    }
}
