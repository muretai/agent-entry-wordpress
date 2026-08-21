<?php
/**
 * WooCommerce.php — the catalogue, answerable by an agent that arrived alone.
 *
 * WHY THIS IS THE INTERESTING HALF. A door that only says "thanks, a human will read it"
 * is reachable but not useful. A shop's agent-facing value is its CATALOGUE: what do you
 * sell, is it in stock, what does it cost, where do I send a buyer. Shopify merchants got
 * exactly that in 2026 as a platform feature — a catalogue agents can query. WooCommerce
 * stores, which outnumber them, got nothing: WooCommerce's own MCP endpoint is
 * AUTHENTICATED (a REST consumer key plus `manage_woocommerce`), so it serves the
 * merchant's own tooling, not a stranger's shopping agent. This file closes that gap
 * without a platform in the middle.
 *
 * WHAT AN AGENT MAY SEE, and what it may not. Only published, catalogue-visible products,
 * and only the fields a shopper would read off the page anyway: name, price, stock status,
 * a short description and the URL. No customer data, no orders, no drafts, no private or
 * password-protected products, no meta. The door is unauthenticated by design — the sender
 * proved control of a key, not that they are anyone in particular — so everything reachable
 * through it must be something the site already shows the public.
 *
 * WHY THE ANSWER IS TEXT. The signed payload has exactly six fields and `text` is the only
 * one carrying content; adding a structured field would change the signed bytes and break
 * the contract with the other implementations. So the answer is text laid out in a stable,
 * line-oriented shape that an agent can parse and a human can read — which is also what
 * makes it safe to show in an inbox.
 *
 * @package Muretai\AgentEntry
 */

namespace Muretai\AgentEntry;

if (!defined('ABSPATH')) {
    exit;
}

final class WooCommerce
{
    /** Most products named in one answer. Enough to choose from, short enough to read. */
    private const MAX_RESULTS = 5;

    /** Characters of product description carried per result. */
    private const SNIPPET = 160;

    /** Is WooCommerce active on this site? */
    public static function isActive(): bool
    {
        return class_exists('WooCommerce') && function_exists('wc_get_products');
    }

    /**
     * The A2A skills this site advertises on its card.
     *
     * A skill is a promise, so this returns none at all when WooCommerce is inactive: a
     * card claiming a catalogue the door cannot search would send agents away with a wrong
     * answer, which is worse than sending them away with no answer.
     */
    public static function skills(): array
    {
        if (!self::isActive()) {
            return [];
        }
        return [
            [
                'id' => 'product-search',
                'name' => 'Search the catalogue',
                'description' => 'Ask in plain language for products this shop sells. '
                    . 'The reply names matching products with their price, stock status '
                    . 'and page URL.',
                'tags' => ['shopping', 'catalogue', 'products'],
                'examples' => [
                    'Do you have anything in blue?',
                    'What running shoes do you sell?',
                    'Is the walnut desk lamp in stock, and what does it cost?',
                ],
                'inputModes' => ['text/plain'],
                'outputModes' => ['text/plain'],
            ],
        ];
    }

    /**
     * Answer a catalogue question, or return null to let the site's default reply stand.
     *
     * Null is the important return value. Every inbound message reaches this first, and
     * most of them are not shopping questions; answering "no products matched" to
     * "what are your opening hours?" would be worse than not answering at all.
     *
     * @param array $env the VERIFIED envelope.
     */
    public static function answer(array $env): ?string
    {
        if (!self::isActive()) {
            return null;
        }
        $text = trim((string) ($env['text'] ?? ''));
        if ($text === '') {
            return null;
        }
        $terms = self::searchTerms($text);
        if ($terms === '') {
            return null;
        }
        $products = self::search($terms);
        if ($products === []) {
            return null;
        }
        return self::format($products, $terms);
    }

    /**
     * Reduce a sentence to the words worth searching for.
     *
     * WooCommerce's search matches titles and content, so feeding it a whole question
     * ("do you have any blue running shoes in stock?") matches nothing while "blue running
     * shoes" matches. Dropping a fixed list of question and filler words is crude, and it
     * is deliberately crude: the alternative is a language model, and calling one per
     * inbound message would hand a stranger the site's bill.
     */
    private static function searchTerms(string $text): string
    {
        $text = strtolower(wp_strip_all_tags($text));
        $text = preg_replace('/[^\p{L}\p{N}\s-]+/u', ' ', $text) ?? '';
        static $stop = [
            'do', 'does', 'did', 'you', 'your', 'yours', 'have', 'has', 'is', 'are', 'was',
            'the', 'a', 'an', 'any', 'some', 'i', 'we', 'me', 'my', 'am', 'looking', 'for',
            'want', 'need', 'buy', 'sell', 'sells', 'selling', 'get', 'got', 'can', 'could',
            'would', 'please', 'hello', 'hi', 'there', 'what', 'which', 'where', 'when',
            'how', 'much', 'many', 'in', 'stock', 'price', 'cost', 'costs', 'available',
            'availability', 'and', 'or', 'of', 'to', 'at', 'on', 'it', 'this', 'that',
            'about', 'tell', 'show', 'me', 'list', 'anything', 'something', 'thanks',
        ];
        $words = [];
        foreach (preg_split('/\s+/', $text) ?: [] as $w) {
            $w = trim($w, "-");
            if ($w === '' || strlen($w) < 2 || in_array($w, $stop, true)) {
                continue;
            }
            $words[] = $w;
        }
        // BOUND WHAT A STRANGER CAN MAKE THE DATABASE DO. `s` becomes an unindexed LIKE
        // over wp_posts, and this door answers anyone who can sign a message — which is
        // anyone, since a did:key is free to mint. So the search term is capped in BOTH
        // directions: at most 6 words and 64 characters (a longer LIKE is slower and no
        // more useful), and at least 3 characters, because a one- or two-character LIKE
        // matches most of a catalogue and is pure cost.
        $terms = implode(' ', array_slice($words, 0, 6));
        if (strlen($terms) > 64) {
            $terms = rtrim(substr($terms, 0, 64));
        }
        return strlen($terms) < 3 ? '' : $terms;
    }

    /**
     * @return \WC_Product[] published, catalogue-visible products matching `$terms`.
     */
    private static function search(string $terms): array
    {
        $args = [
            's' => $terms,
            'limit' => self::MAX_RESULTS,
            'status' => 'publish',
            'catalog_visibility' => 'visible',
            'orderby' => 'relevance',
            'return' => 'objects',
        ];
        /**
         * Filter the catalogue query an agent's question produces.
         *
         * @param array  $args  wc_get_products() arguments.
         * @param string $terms the extracted search terms.
         */
        $args = apply_filters('muretai_agent_entry_product_query', $args, $terms);
        $found = wc_get_products($args);
        if (!is_array($found)) {
            return [];
        }
        // Belt and braces: never surface a product the public cannot already see, whatever
        // a filter did to the query above.
        return array_values(array_filter($found, static function ($p): bool {
            if (!is_object($p) || !method_exists($p, 'get_status')) {
                return false;
            }
            if ($p->get_status() !== 'publish') {
                return false;
            }
            $post = get_post($p->get_id());
            return !($post && $post->post_password !== '');
        }));
    }

    /**
     * Lay the results out so an agent can parse them and a person can read them.
     *
     * One product per block, one `field: value` per line, in a fixed order. No table, no
     * JSON: a table needs alignment nobody agrees on, and JSON inside a signed text field
     * reads as machine noise in the human inbox that same text lands in.
     */
    private static function format(array $products, string $terms): string
    {
        $currency = function_exists('get_woocommerce_currency') ? get_woocommerce_currency() : '';
        $n = count($products);
        $lines = [];
        $lines[] = sprintf(
            '%d %s matching "%s" at %s:',
            $n,
            $n === 1 ? 'product' : 'products',
            $terms,
            get_bloginfo('name')
        );

        foreach ($products as $p) {
            $price = $p->get_price();
            $lines[] = '';
            $lines[] = '- ' . wp_strip_all_tags((string) $p->get_name());
            $lines[] = '  price: ' . ($price === '' || $price === null
                ? 'on request'
                : trim(sprintf('%s %s', (string) $price, $currency)));
            $lines[] = '  in stock: ' . ($p->is_in_stock() ? 'yes' : 'no');
            $snippet = trim(wp_strip_all_tags((string) $p->get_short_description()));
            if ($snippet === '') {
                $snippet = trim(wp_strip_all_tags((string) $p->get_description()));
            }
            if ($snippet !== '') {
                $lines[] = '  about: ' . self::truncate($snippet, self::SNIPPET);
            }
            $lines[] = '  url: ' . $p->get_permalink();
        }

        $lines[] = '';
        $lines[] = 'Ask again with a different word to search for something else.';
        return implode("\n", $lines);
    }

    private static function truncate(string $s, int $n): string
    {
        $s = preg_replace('/\s+/u', ' ', $s) ?? $s;
        if (function_exists('mb_strlen') && mb_strlen($s) > $n) {
            return rtrim(mb_substr($s, 0, $n)) . '...';
        }
        if (strlen($s) > $n) {
            return rtrim(substr($s, 0, $n)) . '...';
        }
        return $s;
    }
}
