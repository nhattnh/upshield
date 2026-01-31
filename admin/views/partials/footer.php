<?php
/**
 * Footer partial for admin pages
 * 
 * @package UpShield_WAF
 */

if (!defined('ABSPATH')) {
    exit;
}
?>
<div class="upshield-footer">
    <p class="upshield-copyright">
        <?php
        $vswaf_current_year = wp_date('Y');
        printf(
            /* translators: %1$s: Current year, %2$s: Link to UpShield website */
            esc_html__('Copyright © %1$s %2$s', 'upshield-waf'),
            esc_html($vswaf_current_year),
            '<a href="' . esc_url('https://upshield.org') . '" target="_blank" rel="noopener noreferrer">UpShield WAF</a>'
        );
        ?>
    </p>
    <p class="upshield-version">
        Version: <?php echo esc_html(UPSHIELD_VERSION); ?>
    </p>
</div>
