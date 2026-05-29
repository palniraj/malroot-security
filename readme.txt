=== Malroot Security ===
Contributors: nirajpal
Tags: security, malware, scanner, backdoor, firewall
Requires at least: 6.0
Tested up to: 7.0
Requires PHP: 7.4
Stable tag: 1.0.2
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Catches database-resident backdoors, rogue admins, malicious MySQL triggers and self-healing rootkits other scanners miss.

== Description ==

Malroot Security is a WordPress malware scanner built specifically to catch the threats that file-based scanners miss. It was created after a real-world investigation of compromised WordPress sites where Wordfence and similar tools failed to detect database-resident malware, rogue REST API endpoints, malicious MySQL triggers, and self-healing rootkit patterns.

= What makes Malroot different =

Most security plugins only scan files on disk. Malroot also looks at:

* **Database content** — `wp_options`, `wp_posts`, `wp_postmeta` for injected PHP/JS payloads
* **MySQL triggers and events** — catches rootkits that recreate fake admins on every spam comment
* **REST API routes** — flags non-standard namespaces with dangerous capabilities
* **mu-plugins** — detects self-healing loaders that reinstall malware after deletion
* **Bot-cloaked content** — compares Googlebot vs human page output to detect SEO spam
* **Outbound connections** — logs every external HTTP request and alerts on known C2 hosts

= Core features =

* Eight independent scanner modules with severity-based findings
* One-click incident response that replays a complete malware cleanup
* Auto-quarantine with full restore for files, options, postmeta, users, triggers, events
* Real-time hooks block rogue admin creation and eval-based option injection
* WordPress.org checksum verification — official files auto-accept silently
* Login security with IP throttling, automated-tool detection, geo-aware new-origin alerts
* Built-in 2FA (TOTP, RFC 6238 — works with Google Authenticator, Authy, 1Password)
* Spam registration shield with honeypot, pattern blocklist, and bulk subscriber cleanup
* Email and Slack alerting with deduplication
* CSV export of findings for audit trails
* Self-integrity check — Malroot detects tampering with its own code

= Plain-language Simple View =

Findings are translated from technical rule IDs into plain English with clear actions:

* "Hidden trap found in your database" instead of "TR-005: Trigger after_insert_comment"
* "Fake admin account found" instead of "UA-010: Known malware admin name"
* "Hacker tool found on your site" instead of "MAL-005: WSO/FilesMan webshell signature"

Each finding card answers three questions: what happened, why it matters, what to do.

= How verified-safe checking works =

When a file changes, Malroot looks up its MD5 hash in:

1. The official WordPress.org core checksums API
2. The official plugin checksums at downloads.wordpress.org
3. A recent plugin/theme update window from the operator's own update history

Files that match an official checksum auto-accept silently — the user never sees them. Files that match a malware signature get flagged as critical regardless of any update window. Custom files and theme edits surface for manual review.

= Real-world validation =

Malroot was developed during the cleanup of compromised WordPress sites, including sites where the rogue plugin had embedded a MySQL trigger that recreated a `newsfeed` admin user every time a spam comment was posted. That attack pattern is now a built-in detection.

== Installation ==

1. Upload the `malroot-security` folder to `/wp-content/plugins/` or install via the Plugins menu.
2. Activate Malroot Security from the Plugins screen.
3. Open the **Malroot** menu in your admin sidebar.
4. Click **Run Full Scan Now** — the first scan builds an integrity baseline.
5. Visit **Settings** to configure email alerts and (optionally) require 2FA for administrators.

== Frequently Asked Questions ==

= Does this replace Wordfence or Sucuri? =

No — Malroot is designed to complement file-based scanners, not replace them. It catches the database-resident, REST-based, and trigger-based threats that file scanners typically miss. Run both for layered protection.

= What happens when I click "Quarantine"? =

Files are moved to a private folder under `wp-content/uploads/malroot-quarantine/` (protected by `.htaccess`). Database options, postmeta, users, and triggers are backed up to a quarantine table and then removed. Every action is reversible from the Quarantine page.

= Will normal plugin updates create false alarms? =

No. Malroot verifies changed files against official WordPress.org checksums. Files that match are auto-accepted silently — you only see findings when something genuinely doesn't match.

= How does the 2FA work? =

Standard TOTP (RFC 6238). Each user enables 2FA from their profile, scans a QR code with Google Authenticator, Authy, 1Password, or any compatible app, and confirms with a 6-digit code. Eight one-time recovery codes are generated during setup. Site administrators can require 2FA for all admin accounts in Settings.

= Does Malroot send my data anywhere? =

Malroot makes outbound requests only to the services described in the "External services" section below. No site content, credentials, or scan results are sent to any third party.

= Does the plugin work on multisite? =

Single-site only in v1.0. Multisite support is on the roadmap.

== External services ==

This plugin connects to the following external services. Each is documented below with what is sent, when, and why.

**WordPress.org core checksums API** (`api.wordpress.org`)
Used to verify whether changed core files match official WordPress release checksums. The plugin sends only the WordPress version string and locale (e.g. `6.5.4` / `en_US`) to fetch the public checksum manifest. No site content is sent. This is the same API WordPress core uses for its built-in checksum tool.
Provider: WordPress Foundation. Privacy policy: https://wordpress.org/about/privacy/. Terms: https://wordpress.org/about/

**WordPress.org plugin checksums** (`downloads.wordpress.org`)
Used to verify whether changed plugin files match the checksums of the version installed from the WordPress.org plugin directory. The plugin sends the plugin slug and version to fetch the public checksum manifest. No site content is sent.
Provider: WordPress Foundation. Privacy policy: https://wordpress.org/about/privacy/. Terms: https://wordpress.org/about/

**ipapi.co GeoIP lookup** (`ipapi.co`)
Used to display a human-readable country and city for IP addresses recorded on the Login Activity page. The plugin sends only the IP address being looked up. Results are cached locally for 30 days so each unique IP is queried at most once per month. Lookups happen only when an administrator opens the Login Activity admin page, never during normal site traffic. This service is optional — if the API is unreachable, login records still display the raw IP.
Provider: ipapi. Privacy policy: https://ipapi.co/privacy/. Terms: https://ipapi.co/terms/

**QR Server QR-code image** (`api.qrserver.com`)
Used to render the QR code shown when a user enables Two-Factor Authentication on their profile. The plugin sends only an `otpauth://` URL containing the user's TOTP secret, the site name, and the user login. The image is requested only when an administrator clicks "Enable 2FA" on their own profile. Users who do not want to use this service can read the secret string displayed below the QR code and type it manually into their authenticator app instead — the QR is purely a convenience.
Provider: GoQR.me. Privacy policy: https://goqr.me/privacy/. Terms: https://goqr.me/api/

**Slack incoming webhook** (URL configured by the site administrator, optional)
If the site administrator enters a Slack incoming webhook URL on the Settings page, critical and high-severity alerts are POSTed to that URL as a short notification payload (event type, severity, summary, and site host). No site content, credentials, or scan results are sent. This service is opt-in and only active when a webhook URL has been configured.
Provider: Slack. Privacy policy: https://slack.com/trust/privacy/privacy-policy. Terms: https://slack.com/terms-of-service

== Screenshots ==

1. The Findings dashboard with the security score and severity tiles.
2. The Simple View showing plain-language cards with one-click action buttons.
3. The Quarantine page with restore controls for safely-removed items.
4. The Login Activity page with location lookup and automated-tool flagging.
5. The one-click Incident Response runbook.
6. The Settings page with real-time protection toggles and custom blocklists.

== Changelog ==

= 1.0.2 =
* Added an "External services" section to readme documenting every outbound request the plugin makes and linking to each provider's privacy policy and terms.
* Replaced inline `<style>` and `<script>` blocks on the 2FA login and setup screens with `wp_register_style` / `wp_register_script` and `wp_add_inline_style` / `wp_add_inline_script`.
* Quarantine directory moved to `wp_upload_dir()['basedir'] . '/malroot-security/quarantine'` instead of a hardcoded `WP_CONTENT_DIR` path.
* Incident-response cleanup no longer changes the activation status of other plugins. It now only detects a malicious `system-control` plugin and reports it so the administrator can deactivate it manually from the Plugins screen.
* Admin top-level menu repositioned from position 3 to 80 to integrate cleanly with the standard WordPress admin hierarchy.
* `wp_verify_nonce()` calls now run their input through `sanitize_text_field( wp_unslash() )` for defence-in-depth (the function is pluggable).
* `$_SERVER` array values are sanitised before being passed to `explode()`.

= 1.0.0 =
* First public release.
* Auto-accept of files matching official WordPress.org and plugin checksums.
* Simple View as the default dashboard.
* Eight scanner modules: files, database, users, triggers, REST API, mu-plugins, bot-cloak, file integrity.
* Built-in TOTP 2FA with QR code setup and recovery codes.
* GeoIP enrichment of login records with 30-day caching.
* CSV export, "Ignore finding" workflow, and self-integrity check.

== Upgrade Notice ==

= 1.0.2 =
Documents external services in the readme; refactors inline JS/CSS to use proper enqueue functions; moves the quarantine folder under `uploads/malroot-security/`.

= 1.0.0 =
First public release.
