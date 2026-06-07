/**
 * Malroot Security — Admin JS
 * Handles async scan progress, live status updates, and UI polish.
 */
/* global malrootAdmin, jQuery */
(function ($) {
    'use strict';

    /* ------------------------------------------------------------------ */
    /*  Async scan                                                          */
    /* ------------------------------------------------------------------ */

    var scanInProgress = false;

    function startScan() {
        if (scanInProgress) return;
        scanInProgress = true;

        var $btn     = $('#malroot-scan-btn');
        var $status  = $('#malroot-scan-status');
        var $bar     = $('#malroot-progress-bar-inner');
        var $wrap    = $('#malroot-progress-wrap');
        var $results = $('#malroot-results-wrap');

        $btn.prop('disabled', true).text(malrootAdmin.i18n.scanning);
        $wrap.show();
        $results.html('<p style="color:#666;padding:20px">' + malrootAdmin.i18n.pleaseWait + '</p>');

        var steps = [
            { key: 'files',     label: malrootAdmin.i18n.stepFiles,     pct: 15 },
            { key: 'database',  label: malrootAdmin.i18n.stepDatabase,  pct: 30 },
            { key: 'users',     label: malrootAdmin.i18n.stepUsers,     pct: 45 },
            { key: 'triggers',  label: malrootAdmin.i18n.stepTriggers,  pct: 55 },
            { key: 'rest',      label: malrootAdmin.i18n.stepRest,      pct: 65 },
            { key: 'muplugins', label: malrootAdmin.i18n.stepMuPlugins, pct: 75 },
            { key: 'botcloak',  label: malrootAdmin.i18n.stepBotCloak,  pct: 85 },
            { key: 'integrity', label: malrootAdmin.i18n.stepIntegrity, pct: 95 },
        ];

        var stepIndex = 0;

        function runNextStep() {
            if (stepIndex >= steps.length) {
                finaliseScan();
                return;
            }
            var step = steps[stepIndex++];
            $status.text(step.label);
            $bar.css('width', step.pct + '%');

            $.post(malrootAdmin.ajaxUrl, {
                action:   'malroot_scan_step',
                step:     step.key,
                scan_id:  malrootAdmin.scanId,
                nonce:    malrootAdmin.nonce,
            }).done(function (resp) {
                if (resp && resp.success) {
                    malrootAdmin.scanId = resp.data.scan_id;
                    setTimeout(runNextStep, 200);
                } else {
                    showError(resp && resp.data ? resp.data : malrootAdmin.i18n.error);
                }
            }).fail(function () {
                showError(malrootAdmin.i18n.error);
            });
        }

        function finaliseScan() {
            $bar.css('width', '100%');
            $status.text(malrootAdmin.i18n.finalising);

            $.post(malrootAdmin.ajaxUrl, {
                action:  'malroot_scan_finalise',
                scan_id: malrootAdmin.scanId,
                nonce:   malrootAdmin.nonce,
            }).done(function (resp) {
                if (resp && resp.success) {
                    $wrap.hide();
                    $btn.prop('disabled', false).text(malrootAdmin.i18n.runScan);
                    scanInProgress = false;
                    renderResults(resp.data);
                } else {
                    showError(resp && resp.data ? resp.data : malrootAdmin.i18n.error);
                }
            }).fail(function () {
                showError(malrootAdmin.i18n.error);
            });
        }

        function showError(msg) {
            $wrap.hide();
            $btn.prop('disabled', false).text(malrootAdmin.i18n.runScan);
            scanInProgress = false;
            $results.html('<div class="notice notice-error"><p>' + $('<span>').text(msg).html() + '</p></div>');
        }

        runNextStep();
    }

    /* ------------------------------------------------------------------ */
    /*  Results renderer                                                    */
    /* ------------------------------------------------------------------ */

    function renderResults(data) {
        var $wrap = $('#malroot-results-wrap');
        var counts = data.counts || {};
        var findings = data.findings || [];
        var score = data.score || 0;

        // Score + tiles
        var scoreColor = score >= 90 ? '#46b450' : (score >= 70 ? '#ffb900' : '#dc3232');
        var html = '<div class="malroot-tiles">';
        html += '<div class="malroot-tile malroot-tile-score"><div class="malroot-tile-label">Security Score</div><div class="malroot-tile-value" style="color:' + scoreColor + '">' + score + '</div></div>';

        var sevColors = { critical: '#dc3232', high: '#dc3232', medium: '#ffb900', low: '#888', info: '#888' };
        $.each(['critical','high','medium','low','info'], function(i, sev) {
            var c = counts[sev] || 0;
            var color = c > 0 ? sevColors[sev] : '#1d2327';
            html += '<div class="malroot-tile"><div class="malroot-tile-label">' + sev.charAt(0).toUpperCase() + sev.slice(1) + '</div>';
            html += '<div class="malroot-tile-value" style="color:' + color + '">' + c + '</div></div>';
        });
        html += '</div>';

        // Filter to open findings only
        var openFindings = findings.filter(function(f) { return f.status === 'open' && f.severity !== 'info'; });

        if (!openFindings.length) {
            html += '<div class="malroot-clean-notice"><span class="dashicons dashicons-yes-alt"></span> ' + malrootAdmin.i18n.clean + '</div>';
        } else {
            // Simple view: show summary + link to reload page for full view
            var critHigh = openFindings.filter(function(f) { return f.severity === 'critical' || f.severity === 'high'; });
            var medium = openFindings.filter(function(f) { return f.severity === 'medium' || f.severity === 'low'; });

            if (critHigh.length) {
                html += '<h2 style="color:#dc3232;margin-top:24px">Action required (' + critHigh.length + ')</h2>';
                html += '<p style="color:#555">These issues need your attention. <a href="' + window.location.href.split('?')[0] + '?page=malroot-security&view=simple">Reload page</a> for full details and action buttons.</p>';
            }
            if (medium.length) {
                html += '<h2 style="color:#ffb900;margin-top:24px">Worth reviewing (' + medium.length + ')</h2>';
                html += '<p style="color:#555">Lower-priority findings. <a href="' + window.location.href.split('?')[0] + '?page=malroot-security&view=simple">Reload page</a> for details.</p>';
            }
            html += '<p style="margin-top:16px"><a href="' + window.location.href.split('?')[0] + '?page=malroot-security&view=simple" class="button button-primary">View full results</a></p>';
        }

        $wrap.html(html);
    }

    /* ------------------------------------------------------------------ */
    /*  Async removal (single + bulk)                                       */
    /* ------------------------------------------------------------------ */

    // Decrement the matching severity tile + the score reaction.
    function decrementTile(sev) {
        var $tiles = $('.malroot-tiles .malroot-tile');
        $tiles.each(function () {
            var $tile = $(this);
            var label = $tile.find('.malroot-tile-label').text().trim().toLowerCase();
            if (label === sev) {
                var $val = $tile.find('.malroot-tile-value');
                var n = parseInt($val.text(), 10) || 0;
                if (n > 0) { n -= 1; $val.text(n); if (n === 0) { $val.css('color', '#1d2327'); } }
            }
        });
    }

    // Remove one finding by id. Returns a jQuery promise.
    // allowProtected=true marks a single, individually-confirmed removal that
    // may act on a file inside installed software. The bulk loop omits it.
    function removeFinding(id, nonce, allowProtected) {
        return $.post(malrootAdmin.ajaxUrl, {
            action:          'malroot_quarantine_finding',
            finding_id:      id,
            nonce:           nonce || malrootAdmin.quarantineNonce,
            allow_protected: allowProtected ? 1 : 0,
        });
    }

    // Visually retire a finding card/row once removed.
    function retireFinding(id, sev) {
        var $card = $('.mr-finding-card[data-id="' + id + '"]');
        var $row  = $('tr[data-id="' + id + '"]');
        decrementTile(sev);
        var $target = $card.length ? $card : $row;
        $target.stop(true, true).animate({ opacity: 0.25 }, 250, function () {
            if ($card.length) {
                $card.slideUp(250, function () { $card.remove(); maybeAllClear(); });
            }
        });
        if ($row.length) {
            $row.find('.mr-remove-form').replaceWith('<span class="malroot-fixed">\u2713 ' + esc(malrootAdmin.i18n.removed) + '</span>');
        }
    }

    // If every action-required card is gone, show the clean banner.
    function maybeAllClear() {
        if ($('.mr-finding-card').length === 0 && $('.mr-bulk-bar').length) {
            $('.mr-bulk-bar').slideUp(200);
            if (!$('.mr-allclear-notice').length) {
                $('.mr-bulk-bar').after(
                    '<div class="malroot-clean-notice mr-allclear-notice"><span class="dashicons dashicons-yes-alt"></span> ' +
                    esc(malrootAdmin.i18n.bulkDone) + '</div>'
                );
            }
        }
    }

    // Single-card / single-row removal (intercept the form submit).
    $(document).on('submit', '.mr-remove-form', function (e) {
        e.preventDefault();
        var $form = $(this);
        var id    = $form.data('id');
        var sev   = String($form.data('sev') || '');
        var nonce = $form.find('input[name="_wpnonce"]').val();
        var $btn  = $form.find('.mr-remove-btn');
        var orig  = $btn.html();

        $btn.prop('disabled', true).text(malrootAdmin.i18n.removing);

        removeFinding(id, nonce, true).done(function (resp) {
            if (resp && resp.success) {
                retireFinding(id, sev);
            } else {
                alert(resp && resp.data ? resp.data : malrootAdmin.i18n.removeFailed);
                $btn.prop('disabled', false).html(orig);
            }
        }).fail(function () {
            alert(malrootAdmin.i18n.removeFailed);
            $btn.prop('disabled', false).html(orig);
        });
    });

    // Bulk removal — process sequentially so a slow filesystem can't stack
    // requests, with a live progress bar.
    $(document).on('click', '.mr-bulk-btn', function () {
        var $bar    = $(this).closest('.mr-bulk-bar');
        var ids     = String($bar.data('ids') || '').split(',').filter(Boolean);
        var nonce   = $bar.data('nonce');
        if (!ids.length) return;
        if (!confirm(malrootAdmin.i18n.confirmBulk)) return;

        var $btn      = $(this);
        var $progress = $bar.find('.mr-bulk-progress');
        var $inner    = $bar.find('.mr-bulk-progress-inner');
        var $text     = $bar.find('.mr-bulk-progress-text');
        var total     = ids.length;
        var i         = 0;
        var failed    = 0;

        $btn.prop('disabled', true);
        $progress.show();

        function next() {
            if (i >= total) {
                $text.text(malrootAdmin.i18n.bulkDone);
                $btn.slideUp(200);
                maybeAllClear();
                return;
            }
            var id = parseInt(ids[i], 10);
            i += 1;
            $text.text(
                malrootAdmin.i18n.bulkProgress.replace('%1$d', i).replace('%2$d', total)
            );
            $inner.css('width', Math.round((i / total) * 100) + '%');

            var $card = $('.mr-finding-card[data-id="' + id + '"]');
            var sev   = String($card.data('sev') || '');

            removeFinding(id, nonce).done(function (resp) {
                if (resp && resp.success) {
                    retireFinding(id, sev);
                } else {
                    failed += 1;
                }
            }).fail(function () {
                failed += 1;
            }).always(function () {
                setTimeout(next, 150);
            });
        }

        next();
    });

    function esc(str) {
        return $('<span>').text(str || '').html();
    }

    /* ------------------------------------------------------------------ */
    /*  Async snapshot (Update Snapshot button)                           */
    /* ------------------------------------------------------------------ */

    $(function () {
        $(document).on('click', '#malroot-snapshot-btn', function (e) {
            e.preventDefault();
            var $btn = $(this);
            $btn.prop('disabled', true).text(malrootAdmin.i18n.snapshotting);

            $.post(malrootAdmin.ajaxUrl, {
                action: 'malroot_rebuild_baseline',
                nonce:  malrootAdmin.nonce,
            }).done(function (resp) {
                $btn.prop('disabled', false).text(malrootAdmin.i18n.updateSnapshot);
                if (resp && resp.success) {
                    var msg = malrootAdmin.i18n.snapshotDone.replace('%d', resp.data.count);
                    var $notice = $('<div class="notice notice-success is-dismissible"><p>' + msg + '</p></div>');
                    $('.wrap h1').after($notice);
                    // Trigger a fresh scan automatically so results reflect the new baseline
                    setTimeout(function () {
                        malrootAdmin.scanId = 0;
                        startScan();
                    }, 800);
                } else {
                    alert(resp && resp.data ? resp.data : malrootAdmin.i18n.error);
                }
            }).fail(function () {
                $btn.prop('disabled', false).text(malrootAdmin.i18n.updateSnapshot);
                alert(malrootAdmin.i18n.error);
            });
        });
    });

    /* ------------------------------------------------------------------ */
    /*  Boot                                                                */
    /* ------------------------------------------------------------------ */

    $(function () {
        $(document).on('click', '#malroot-scan-btn', function (e) {
            e.preventDefault();
            malrootAdmin.scanId = 0;
            startScan();
        });
    });

}(jQuery));
