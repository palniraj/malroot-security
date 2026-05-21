<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

/**
 * Bot-cloak detector.
 *
 * Fetches the homepage twice: once with a Googlebot user-agent and once
 * with a normal browser user-agent, then diffs the output. Flags the
 * difference if the bot version contains <a href="..."> tags or scripts
 * that the human version doesn't, which is the textbook bot-cloak SEO
 * spam pattern (system-control's SC_Display_Links did this).
 */
class Malroot_Scanner_BotCloak extends Malroot_Scanner_Base {

	protected $module = 'botcloak';

	private $bot_ua    = 'Mozilla/5.0 (Linux; Android 10; Pixel 4 XL Build/QQ3A.200805.001) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)';
	private $human_ua  = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15';

	public function run() {
		$home = home_url( '/' );

		$bot   = $this->fetch( $home, $this->bot_ua );
		$human = $this->fetch( $home, $this->human_ua );

		if ( ! $bot || ! $human ) {
			Malroot_Logger::warning( 'BotCloak: fetch failed; skipping diff' );
			return;
		}

		$diff = $this->extract_extra_links( $bot, $human );
		if ( $diff ) {
			$this->record(
				'BC-001',
				'critical',
				'home:' . $home,
				'Page returns extra links to search engine bots that real users don\'t see',
				wp_json_encode( $diff )
			);
		}

		// 302 to attacker URL when fetched as Googlebot
		$bot_response = wp_remote_get( $home, [
			'user-agent' => $this->bot_ua,
			'redirection' => 0,
			'timeout' => 8,
			'sslverify' => false,
		] );
		if ( ! is_wp_error( $bot_response ) ) {
			$code = wp_remote_retrieve_response_code( $bot_response );
			$loc  = wp_remote_retrieve_header( $bot_response, 'location' );
			if ( $code >= 300 && $code < 400 && $loc ) {
				$loc_host = wp_parse_url( $loc, PHP_URL_HOST );
				$home_host = wp_parse_url( $home, PHP_URL_HOST );
				if ( $loc_host && $loc_host !== $home_host ) {
					$this->record(
						'BC-002',
						'critical',
						'home:' . $home,
						"Googlebot fetch is redirected to a different host ({$loc_host})",
						"location: {$loc}"
					);
				}
			}
		}
	}

	private function fetch( $url, $ua ) {
		$resp = wp_remote_get( $url, [
			'user-agent' => $ua,
			'timeout'    => 12,
			'sslverify'  => false,
			'redirection'=> 5,
		] );
		if ( is_wp_error( $resp ) ) return null;
		return (string) wp_remote_retrieve_body( $resp );
	}

	private function extract_extra_links( $bot_html, $human_html ) {
		preg_match_all( '/<a\s[^>]*href=["\']([^"\']+)["\']/i', $bot_html,   $b );
		preg_match_all( '/<a\s[^>]*href=["\']([^"\']+)["\']/i', $human_html, $h );

		$bot_links   = array_unique( $b[1] ?? [] );
		$human_links = array_unique( $h[1] ?? [] );
		$home_host   = wp_parse_url( home_url(), PHP_URL_HOST );

		$extra = array_diff( $bot_links, $human_links );
		// Keep only external-domain links (the spam pattern)
		$extra = array_filter( $extra, function( $link ) use ( $home_host ) {
			$h = wp_parse_url( $link, PHP_URL_HOST );
			return $h && $h !== $home_host;
		} );
		return array_values( $extra );
	}
}
