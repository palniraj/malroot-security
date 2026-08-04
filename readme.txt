=== Malroot Security ===
Contributors: nirajpal
Tags: security, malware, scanner, backdoor, firewall
Requires at least: 6.0
Tested up to: 7.0
Requires PHP: 7.4
Stable tag: 1.0.9
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

By default, Malroot only contacts the official WordPress.org checksum APIs to verify your core and plugin files. Everything else is opt-in: IP geolocation is OFF until you enable it, and Slack alerts only fire if you configure a webhook. No site content, credentials, or scan results are sent to any third party. See the "External services" section below for full details.

= How does Two-Factor Authentication show the setup key? =

Malroot does not generate a scannable QR code, because doing so would mean sending your secret key to an outside image service. Instead it shows the setup key as text, which you type into your authenticator app using its "Enter a setup key" option. Nothing about your 2FA secret ever leaves your server.

= Does the plugin work on multisite? =

Single-site only in v1.0. Multisite support is on the roadmap.

== External services ==

This plugin connects to the external services listed below. By default only the WordPress.org checksum APIs are used; the rest are opt-in. Each is documented with what is sent, when, and why.

**WordPress.org core checksums API** (`api.wordpress.org`)
Used to verify whether changed core files match official WordPress release checksums. The plugin sends only the WordPress version string and locale (e.g. `6.5.4` / `en_US`) to fetch the public checksum manifest. No site content is sent. This is the same API WordPress core uses for its built-in checksum tool.
Provider: WordPress Foundation. Privacy policy: https://wordpress.org/about/privacy/. Terms: https://wordpress.org/about/

**WordPress.org plugin checksums** (`downloads.wordpress.org`)
Used to verify whether changed plugin files match the checksums of the version installed from the WordPress.org plugin directory. The plugin sends the plugin slug and version to fetch the public checksum manifest. No site content is sent.
Provider: WordPress Foundation. Privacy policy: https://wordpress.org/about/privacy/. Terms: https://wordpress.org/about/

**ipapi.co GeoIP lookup** (`ipapi.co`) — optional, OFF by default
Disabled unless the administrator turns on "IP geolocation" on the Settings page. When enabled, it displays a human-readable country and city for IP addresses recorded on the Login Activity page. The plugin sends only the IP address being looked up, and only when an administrator opens the Login Activity page — never during normal site traffic. Results are cached locally for 30 days so each unique IP is queried at most once per month. If the option is left off (the default), no IP address is ever sent and login records simply show the raw IP.
Provider: ipapi. Privacy policy: https://ipapi.co/privacy/. Terms: https://ipapi.co/terms/

**Slack incoming webhook** (URL configured by the site administrator, optional)
If the site administrator enters a Slack incoming webhook URL on the Settings page, critical and high-severity alerts are POSTed to that URL as a short notification payload (event type, severity, summary, and site host). No site content, credentials, or scan results are sent. This service is opt-in and only active when a webhook URL has been configured.
Provider: Slack. Privacy policy: https://slack.com/trust/privacy/privacy-policy. Terms: https://slack.com/terms-of-service

== Screenshots ==

1. The Findings dashboard with the security score and severity tiles.
2. The Simple View showing plain-language cards with one-click action buttons.
3. The Settings page with Admin Guard, real-time protection toggles, and custom blocklists.
4. The Login Activity page showing successful and failed logins, location, and automated-tool flagging.
5. The Spam Cleanup tool with a dry-run preview before any account is deleted.
6. The Alerts log of real-time security events.
7. The one-click Incident Response runbook.

== Changelog ==

= 1.0.9 =
This release comes out of a live investigation where nine rogue administrators and a full backdoor kit sat on a site for five weeks while Malroot reported only one minor issue. The causes were architectural, so the fixes are too.

Rogue administrators are now found by comparison, not by name:
* The user scanner previously matched a fixed list of login names, registration dates and empty emails. Randomised names such as `w2s_c428304169fc` and `wp_admin_e38341` defeated all of it — `wp_admin_e38341` is not equal to `wp_admin`. Admin Guard already held the answer (an approved-administrator allowlist) but nothing ever compared the live admin list against it.
* New rule UA-001 reports any administrator that is not on the approved list, whatever it is called. UA-003 independently reports any admin created after monitoring began that was never approved. Both caught 9 of 9 accounts in testing, with no false positives.
* Added UA-002 (email on a domain that cannot receive mail, e.g. .local, .invalid, example.com), UA-004 (several admins created in one burst), UA-005 (machine-generated login names), UA-006 (admin that has never logged in and never created content), and UA-014 (the allowlist has never been set up, so this checking is off).
* Administrator roles are now read from usermeta directly. Malware can filter pre_user_query to hide its account from get_users(), and the kit found in this investigation did exactly that.

Unapproved administrators can no longer be used:
* They are refused at login, before any session or auth cookie is issued.
* They hold no administrative capability even if a session already exists, closing the gap between authentication and the existing init watchdog.
* A scan now sweeps idle accounts. The previous door hooks only fired at creation time and the watchdog only fired for an account that was actively signed in — eight of the nine had never logged in, so nothing ever looked at them.

New behavioural backdoor scanner. The file scanner matched literal signatures and detected none of the eight malicious files in this incident: eval('?>' . $remote) slipped past a rule expecting eval(base64_decode, hex escapes hid shell_exec, and a 16 MB shell script was never opened because it was not a .php file. The new scanner describes behaviour instead — creating administrators, hiding rows from the user list, hiding from the Plugins page, running downloaded code, detecting debuggers, or carrying shell scripts and binaries. It found 8 of 8, with no false positives.

New guided cleanup. Removes threats in the order that stops them returning: scheduled jobs first, then the code that recreates accounts, then the accounts, then cloaking rules and spam pages. Everything is backed up and reversible. Cleaning accounts before their cron job is why "we removed it and it came back" is so common.

New hardening options, chosen from the observed attack surface rather than a generic checklist: XML-RPC off (it absorbed over 900 probe requests and allows batched password guessing), PHP execution blocked in uploads, the built-in file editor disabled, anonymous user enumeration blocked via REST and ?author=, and the version number removed.

Fixes:
* REST namespaces are now attributed to the plugin that registered them by reflecting on the route callback. Previously the match was made on name similarity alone, so `wslu/` — which belongs to WP Social — was reported as an unrecognised endpoint. This was a false positive.
* Newly created options were never scanned: the code hooked pre_add_option, which does not exist in WordPress. New options are now checked on added_option and removed if they carry a known payload. Malware normally creates its own option rather than editing an existing one, so this was the common case.
* Admin Guard findings were stamped with their own timestamp instead of the scan id, so its remediation never appeared on the dashboard.
* The approved-admin allowlist can now repair itself. Seeding ran once and never again, so if the email allowlist was lost the loss was permanent and silent — which had disabled one of the user rules entirely. Repair only ever derives emails from already-approved accounts, so it cannot approve an attacker.
* Re-activating the plugin no longer resets an allowlist that is legitimately empty.
* Quarantine can now unschedule WP-Cron jobs. It previously handled MySQL events only, while malware persistence almost always uses WP-Cron.

= 1.0.8 =
* Fewer false positives for must-use plugins: legitimate host and plugin drop-ins (Hostinger auto-updates/preview/onboarding, WP Staging optimizer, Installatron automation, and common WP Engine/Kinsta files) are now recognised and no longer flagged. An unrecognised mu-plugin is now shown as a low-key "review" item, not as "self-reinstalling malware" — that stronger wording is reserved for mu-plugins that actually write files at runtime or are zero-byte stubs.
* Clearer verdict for missing files: when a plugin/theme file is gone, Malroot now distinguishes "removed by an update (expected)" from "a file that should exist is missing — reinstall the plugin/theme to restore it", instead of the ambiguous "origin unknown".
* Comment-spam cleanup now reliably finds pending/classic comments (removed a query filter that could exclude comments stored with an empty type).

= 1.0.7 =
* Far fewer false positives after plugin, theme, and WordPress updates. File-integrity findings are now checked against the component's version: when a plugin, theme, or core version has changed, its file changes are recognised as an expected update and accepted silently instead of asking you to review them.
* Deleted plugin files are now verified authoritatively against the official WordPress.org checksums for the installed version. If the current version no longer ships a file, its removal is accepted automatically — this clears the large lists of "file deleted" notices seen after updating WooCommerce, Google Site Kit, Yoast SEO and similar plugins.
* WordPress-managed paths (`wp-content/languages`, `wp-content/upgrade`) are treated as expected churn, so translation-file updates no longer appear as findings.
* Improved code analysis for files with no official checksum (themes, custom code): the verifier now reads the file and reports in plain language whether it contains suspicious patterns, so clean files are no longer pushed toward deletion. Fixed a `preg_replace` heuristic that misfired on legitimate theme code.
* Authoritative checks now run before content heuristics, fixing false "malware pattern" flags on legitimate plugin files (e.g. LiteSpeed Cache, Jetpack).
* Safer review actions: a modified core/plugin/theme file now recommends reinstalling the official copy instead of deleting it, and already-deleted files no longer show a "remove" button.
* REST endpoints registered by installed, active plugins are correctly attributed and no longer flagged as "unknown" — including WooCommerce family namespaces such as `wc-push-notifications` and `wc-shipstation`, plus Jetpack, LiteSpeed and others.
* Incident Response now also removes dormant injected administrators detected by signature (duplicate login name, no email address, generic wordpress.com profile URL), not just known bad names — with safeguards that never remove you or the last administrator.
* New: block and clean up comment spam. Bot comments (fake "TikTok"/"BBC Post" style) can be blocked before they are stored, and a Spam Cleanup tool moves existing spam comments to Trash. Blocking a spam comment also denies the malicious after_insert_comment trigger its input.
* Alerting is now configurable and written in plain language: choose which severities are emailed, turn routine login-activity notifications on or off (off by default), and receive human-readable emails instead of technical dumps.
* UI: the admin screens now use the full width of the page, and fixed the icon alignment on the "Run cleanup now" button.

= 1.0.6 =
* Privacy: Two-Factor Authentication no longer sends the TOTP secret to an external QR-code image service (api.qrserver.com). The setup key is now shown as text for manual entry into any authenticator app, so the secret never leaves your server.
* Privacy: IP geolocation (ipapi.co) is now strictly opt-in and OFF by default. No IP address is sent anywhere unless an administrator enables "IP geolocation" on the Settings page.
* Quarantine no longer stores removed files in the uploads/plugin folder and no longer writes a PHP stub over files. Removed files are now backed up as inert data in a private database table and deleted from disk with `wp_delete_file()`; restore writes them back via the WordPress filesystem API.
* Use `wp_get_upload_dir()` / `wp_upload_dir()` for the uploads location instead of a hardcoded `WP_CONTENT_DIR/uploads` fallback.
* Removed the dead Terms/Privacy link to goqr.me from the readme (the QR service is no longer used).

= 1.0.5 =
* Important safety fix: the "Remove all" bulk action and automatic quarantine can no longer touch files that belong to WordPress core, an installed plugin, or an installed theme. A heuristic false positive on legitimate code previously could be bulk-removed, blanking a required file and taking the site down. Such findings are now surfaced for deliberate, one-at-a-time review instead of one-click deletion. (mu-plugins stay removable, as self-healing loaders there are a known malware trick.)
* Fewer false positives: `.sql` schema/template files bundled inside a plugin or theme (e.g. LiteSpeed Cache's `data_structure` files) are no longer flagged as public database dumps. PHP files inside recognised plugin-managed uploads folders (Sucuri, WP-Staging, UpdraftPlus, BackWPup) are now listed as low-priority "review" items rather than critical.
* Individual, explicitly-confirmed removals are unchanged and still able to remove a genuine malicious file from anywhere.

= 1.0.4 =
* Removing a finding (file, user, option, trigger) is now instant and in-page — it uses a background request instead of reloading the whole admin screen, so the page no longer hangs while a file is being neutralised. The card fades out and the severity counters update live.
* Added a "Remove all" bulk action to the "Action required" list. It cleans up every auto-removable critical/high finding in one click, processed one at a time with a live progress bar (REST-route findings, which need manual action, are excluded).
* Each removal still backs the item up to Quarantine and is fully reversible.

= 1.0.3 =
* New Admin Guard module: enforces an allowlist of approved administrators on every request. Catches rogue admins injected directly into the database by a MySQL trigger or SQL backdoor (e.g. `wp_feed`, `newsfood`, and duplicate `wppanel` accounts) — accounts that bypass every normal WordPress creation hook and that a login-name blocklist can never keep up with. Unapproved admins are demoted and signed out automatically, and the last approved administrator is never removed.
* Admin Guard allowlist is seeded automatically from the current clean administrators on first run; admins created by an approved admin through wp-admin are approved automatically.
* Redesigned the Incident Response screen in plain language: a clear "what will happen" card with friendly per-step descriptions, a reassurance banner linking to Quarantine, a "when should I run this?" help section, and a readable last-run summary with a threat count.
* Fixed the Incident Response last-run report rendering as unstyled text (the markup used `malroot-ir-*` class names while the stylesheet defined `mr-ir-*`).
* REST scanner: added the official `mailchimp-for-woocommerce/` namespace to the known-safe allowlist (fixes a false-positive RT-001 critical on the Mailchimp for WooCommerce plugin's `sync` routes).
* Expanded the built-in rogue-admin name list (`wp_feed`, `newsfood`, `wppanel`) used by the real-time and login-security blocklists as a secondary layer.
* Annotated four Plugin Check `WriteFile.ABSPATHDetected` warnings in the quarantine module. These writes intentionally target a file at its real webroot location — neutralising a malware file in place, and restoring a quarantined file to its original path — so they cannot use `wp_upload_dir()`. Each is now documented with a sniff-specific `phpcs:ignore` and a justification.
* Annotated five Plugin Check `SlowDBQuery` (meta_key/meta_value) warnings in the incident-response and quarantine modules. None is a slow `WP_Query` meta lookup — one is a plain report-array key, and the database operations are INSERT/DELETE on the already-indexed `meta_key` column — so each is documented with a sniff-specific `phpcs:ignore` and a justification.

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

= 1.0.8 =
Recognises legitimate host/plugin must-use plugins (Hostinger, WP Staging, Installatron, etc.) so they are no longer flagged as malware, gives clearer guidance for missing files, and fixes comment-spam cleanup so it reliably finds pending comments.

= 1.0.7 =
Far fewer false positives after updates: integrity checks now use plugin/theme/core versions and official WordPress.org checksums. Adds comment-spam blocking and cleanup, configurable plain-language alerts, and safer review actions.

= 1.0.6 =
Privacy fixes for WordPress.org compliance: 2FA setup no longer sends your secret to an external QR service, IP geolocation is now opt-in and off by default, and quarantined files are backed up to the database instead of the uploads folder.

= 1.0.5 =
Safety fix: one-click "Remove all" and auto-quarantine can no longer delete WordPress core, plugin, or theme files, preventing a false positive from breaking your site. Also removes common false positives for plugin-bundled .sql files and plugin-managed PHP in uploads.

= 1.0.4 =
Removing findings no longer reloads the page and adds a one-click "Remove all" bulk cleanup with a progress bar. Every removal remains reversible from Quarantine.

= 1.0.3 =
Adds Admin Guard, which stops database-injected rogue administrators (MySQL trigger / SQL backdoors) by enforcing an approved-admin allowlist on every request. Fixes a Mailchimp for WooCommerce REST false positive.

= 1.0.2 =
Documents external services in the readme; refactors inline JS/CSS to use proper enqueue functions; moves the quarantine folder under `uploads/malroot-security/`.

= 1.0.0 =
First public release.
