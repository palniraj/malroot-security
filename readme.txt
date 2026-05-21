=== Malroot Security – Malware Scanner, Backdoor Detector & Database Cleanup ===
Contributors: nirajpal
Tags: security, malware, scanner, backdoor, firewall
Requires at least: 6.0
Tested up to: 6.6
Requires PHP: 7.4
Stable tag: 1.0.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

WordPress malware scanner that catches database-resident backdoors, rogue admins, malicious MySQL triggers and self-healing rootkits other scanners miss.

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

Malroot makes outbound requests only to:

* `api.wordpress.org` for WordPress core checksums
* `downloads.wordpress.org` for plugin checksums
* `ipapi.co` for GeoIP lookups (with 30-day caching per IP)
* `api.qrserver.com` to render the 2FA QR code (PNG image only)
* Your configured Slack webhook, if you set one

No site content, credentials, or scan results are sent to any third party.

= Does the plugin work on multisite? =

Single-site only in v1.0. Multisite support is on the roadmap.

== Screenshots ==

1. The Findings dashboard with the security score and severity tiles.
2. The Simple View showing plain-language cards with one-click action buttons.
3. The Quarantine page with restore controls for safely-removed items.
4. The Login Activity page with location lookup and automated-tool flagging.
5. The one-click Incident Response runbook.
6. The Settings page with real-time protection toggles and custom blocklists.

== Changelog ==

= 1.0.0 =
* First public release.
* Auto-accept of files matching official WordPress.org and plugin checksums.
* Simple View as the default dashboard.
* Eight scanner modules: files, database, users, triggers, REST API, mu-plugins, bot-cloak, file integrity.
* Built-in TOTP 2FA with QR code setup and recovery codes.
* GeoIP enrichment of login records with 30-day caching.
* CSV export, "Ignore finding" workflow, and self-integrity check.

== Upgrade Notice ==

= 1.0.0 =
First public release.
