# Agent Entry for WordPress

Let AI agents talk to your WordPress site directly — no account, no API key, no third
party in the middle.

The plugin gives your site a cryptographic identity and four HTTP routes. An agent that
has nothing but your URL can then prove **who it is talking to**, send you a signed
message, and get a signed answer back in the same request.

```
GET  /.well-known/agent-card.json      who this site is (name, DID, how to reach it)
GET  /.well-known/agent.json           the same bytes, at the older path
GET  /.well-known/agent-card.sig.json  proof: this key owns this origin
POST /                                 the door — send a signed message, get a signed reply
```

Your home page stays exactly where it is. `GET /` is still your site, and so is every POST
your site makes to itself — WooCommerce's checkout, coupons, add-to-cart and payment
webhooks all keep working, because the door only answers a POST that arrives with
`Content-Type: application/json` **and no query string**. Everything else — including
query-multiplexed routes like `?wc-ajax=`, `?wc-api=` and `?rest_route=` — falls straight
through to WordPress, exactly as if this plugin were deactivated.

## Install

1. Upload the plugin and activate it. A key is generated on activation and stays on your
   server.
2. Open **Settings → Agent Entry**. It shows your address, tells you whether the door is
   really answering, and warns you if another plugin has claimed the same card path.

That is the whole setup. There is nothing to register and no account to create.

### Keep the key out of your database (recommended)

By default the key lives in the `wp_options` table, which means it travels in every
database dump, staging clone and backup. To keep it out, put it in `wp-config.php`
instead:

```php
define( 'MURETAI_AGENT_ENTRY_SEED', 'your-64-character-hex-seed' );
```

The constant wins over the stored option. Copy the existing seed before you switch, or the
site's identity changes and peers who recorded the old one will be talking to a stranger.

## What your site says back

By default it sends a short acknowledgement. To answer properly — a price, an availability,
a lookup in your own data — filter the reply:

```php
add_filter( 'muretai_agent_entry_reply', function ( $reply, $env ) {
    // $env['peer_did']  who is asking (verified — the signature already checked out)
    // $env['text']      what they asked
    // $env['account']   their row in your ledger: messages, first_seen, last_seen
    if ( stripos( $env['text'], 'hours' ) !== false ) {
        return 'We are open 10:00-18:00, Tuesday to Sunday.';
    }
    return $reply;
}, 10, 2 );
```

Note what is **not** here: a model call. A plugin that reached for an LLM on every inbound
message would hand a stranger your API bill. If you want a generated answer, call your own
model inside this filter, where you decide the budget.

## WooCommerce: your catalogue becomes answerable

With WooCommerce active, the site advertises a `product-search` skill on its card and
answers catalogue questions from your own products — no extra setup:

```
Agent: Do you have any blue running shoes?

Site:  1 product matching "blue running shoes" at Example Studio:

       - Blue Running Shoes
         price: 89.50 USD
         in stock: yes
         about: Lightweight road runners in cobalt blue.
         url: https://shop.example/?product=blue-running-shoes
```

Signed by your site, in one request, to an agent with no account.

**What an agent can see** is exactly what a shopper already sees on your pages: published,
catalogue-visible products only — name, price, stock, short description, URL. Drafts,
private and password-protected products, customer data and orders are never reachable
through the door, which is unauthenticated by design.

WooCommerce's own MCP endpoint is a different thing for a different audience: it needs a
REST consumer key and `manage_woocommerce`, so it serves *your* tooling. This serves a
stranger's shopping agent.

To change what gets searched:

```php
add_filter( 'muretai_agent_entry_product_query', function ( $args, $terms ) {
    $args['category'] = [ 'in-stock-now' ];
    return $args;
}, 10, 2 );
```

## Every visitor gets an account, without signing up

The first signed message from a stranger **is** their account. There is no signup form to
fill in, because the sender already proved control of a key — which is strictly more than
an email link proves. Settings → Agent Entry lists them: who has visited, how many times,
and when they were last here.

## If you use a CDN

A CDN can serve humans perfectly while refusing every agent, and you will see nothing
wrong. On Cloudflare the setting is **Browser Integrity Check** (on by default on the free
plan): it rejects clients whose user agent looks automated, which is all of them. Add an
exception matching on **host, method and path only** — never on user agent, which is the
thing being wrongly judged.

**Do not test with `curl`.** It sends its own user agent and sails through checks that
block a real agent, so a green `curl` proves nothing.

## What this does not do

It makes your site **reachable**, not **findable**. Agents still arrive the way they do
today — a search result, a link, a person telling them where to go. Anyone promising that
a file on your server brings agent traffic is selling something.

## Requirements

- WordPress 5.8+, PHP 7.4+
- The `sodium` extension (bundled with PHP since 7.2). Without it the plugin stays inert
  and says so, rather than serving a card it cannot back with a signature.
- `/.well-known/` must reach WordPress. Some hosts and security plugins intercept it; the
  admin screen tells you if that is happening.

## For developers: the wire contract

This is a third implementation of a contract two others already speak (Node and Python).
It is not a new protocol and it does not get to invent bytes:

- **Signature**: Ed25519 over canonical JSON of exactly six fields — `contextId`, `from`,
  `messageId`, `text`, `timestamp`, `to`.
- **Canonical JSON**: keys sorted by code point, separators `,` and `:`, non-ASCII
  **literal** (never `\uXXXX`), UTF-8.
- **Identity**: `did:key:z` + base58btc(`0xed01` ‖ 32-byte Ed25519 public key). The DID is
  the key, so there is no resolver to be poisoned.
- **Card freshness**: the signed envelope is re-minted hourly and a visitor rejects one
  older than six hours. This is why a static file cannot be an Agent Entry: the bytes
  expire and something holding the key has to replace them. WP-Cron does it here.

### Verifying it yourself

Three checks, all of which ship here:

```bash
# 1. the bytes match the golden vectors the other implementations are held to
php tests/conformance.php tests/wire_vectors.json

# 2. the bugs found before release stay fixed
php tests/regression.php

# 3. a LIVE site obeys the contract, asked over HTTP
php tests/check-live.php --handshake https://your-site.example
```

All three ship in this repo and need no account, no dependency and nothing to obtain.
`check-live.php` is read-only without `--handshake`; with it, it sends a real signed message
and the full battery of refusals a door owes, so point that at a site you own.

**Do not check with `curl`.** It sends its own user agent and sails through a CDN bot check
that would 403 a real agent, so a green `curl` tells you nothing.

To run the door with no WordPress at all — useful when you are debugging the contract
rather than the CMS:

```bash
AGENT_ENTRY_BASE_URL=http://127.0.0.1:8099 php -S 127.0.0.1:8099 tests/serve.php
```

## Layout

| file | what it is |
|---|---|
| `includes/class-wire.php` | canonical JSON, Ed25519, did:key, the signed envelopes. No WordPress in it. |
| `includes/class-entry.php` | the routes and the verification ladder, as a pure function. No WordPress in it. |
| `includes/class-store.php` | the state seam + an in-memory implementation |
| `includes/class-wpdb-store.php` | that state in the site's database |
| `includes/class-plugin.php` | the WordPress half: routing, key custody, cron, admin |
| `includes/class-woocommerce.php` | the catalogue an agent can ask about |
| `uninstall.php` | what deleting the plugin removes — including the key |
| `tests/` | the three checks above. Command-line only; they refuse to run over the web. |

The first two files have no WordPress symbol in them on purpose: it lets the contract be
tested without booting a CMS, and it keeps the WordPress adapter small enough to audit.

## Licence

GPL-2.0-or-later.
