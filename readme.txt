=== Agent Entry ===
Contributors: muretai
Tags: ai, agents, ai-agents, woocommerce, automation
Requires at least: 5.8
Tested up to: 6.9
Requires PHP: 7.4
Stable tag: 0.1.4
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Let AI agents talk to your site directly. Your site gets a verifiable identity and answers signed messages — no account, no API key, no middleman.

== Description ==

Most "AI" plugins help a robot **read** your pages. This one lets an agent **talk to your
site** and get a real answer back, signed by your site, in a single request.

It gives your site a cryptographic identity (an Ed25519 key, generated on your server and
never sent anywhere) and four routes:

* `/.well-known/agent-card.json` — who this site is
* `/.well-known/agent.json` — the same bytes, at the older path
* `/.well-known/agent-card.sig.json` — proof that this key owns this domain
* `POST /` — the door: send a signed message, get a signed reply

Your home page is untouched, and so is your checkout: the door answers a POST only when it
carries `Content-Type: application/json` and no query string, so WooCommerce's form-encoded
AJAX, its `?wc-api=` payment webhooks and every other query-multiplexed route fall straight
through to WordPress. Tagged links (`/?utm_source=...`) arrive with GET, which is always
your site's, so analytics are untouched too.

**Every visitor gets an account, with no signup.** The first signed message from a
stranger *is* their account, because they already proved control of a key — more than an
email link proves. The settings screen shows who has visited, how often, and when.

**WooCommerce shops answer from their catalogue.** With WooCommerce active the site
advertises a product-search skill and answers questions like "do you have any blue running
shoes?" with real products — name, price, stock status and URL — signed, in one request, to
an agent with no account. Only published, catalogue-visible products are reachable: drafts,
private products, customer data and orders are not.

**You choose what your site says back.** The default is a short acknowledgement. Developers
replace it per message with the `muretai_agent_entry_reply` filter — answer from your own
data, your own catalogue, your own booking system.

**No model is called.** A plugin that reached for an LLM on every inbound message would
hand a stranger your API bill. If you want a generated answer, call your own model inside
the filter, where you set the budget.

= What this does not do =

It makes your site **reachable**, not **findable**. Agents still arrive the way they do
today — a search result, a link, a person telling them where to go. Anyone promising that
a file on your server brings agent traffic is selling something.

= Open standard, not a lock-in =

The wire format is an open contract already implemented in Node and Python. This plugin is
a third implementation, held to the same golden test vectors, and it works with any client
that speaks the format. Nothing here phones home; no service registration is required, and
none is offered.

== Installation ==

1. Install and activate. A key is generated on activation.
2. Open **Settings → Agent Entry** to see your address and confirm the door is answering.

For better key hygiene, move the key out of the database by defining it in `wp-config.php`:

`define( 'MURETAI_AGENT_ENTRY_SEED', 'your-64-character-hex-seed' );`

Copy the existing seed first — otherwise your site's identity changes.

== Frequently Asked Questions ==

= Does this slow down my site? =

No. The plugin checks the request path once on `init` and returns immediately for any path
it does not own — well before WordPress renders anything — and it adds one HTTP header and
one link tag to normal pages. Nothing is fetched from anywhere.

= Do I need an account with anyone? =

No. There is nothing to sign up for. The key is yours and stays on your server.

= I use Cloudflare and agents cannot reach me. =

Check **Browser Integrity Check** (a zone setting, on by default on the free plan). It
rejects clients whose user agent looks automated, which is all agents, while letting
browsers through — so the site looks fine to you. Add an exception matching on host, method
and path only, never on user agent.

Do not test with `curl`: it sends its own user agent and passes checks that block real
agents.

= How do I check it actually works? =

The settings screen fetches your own card over HTTP and confirms the card served at that
URL is really yours — which also catches another plugin claiming the same path.

For a full check, the plugin ships one: run `php tests/check-live.php --handshake
https://your-site.example` from the plugin directory. It verifies the card and its
signature, the CORS and method rules, that your site's own form posts still reach the site,
and — with `--handshake` — that a real signed message earns a correctly signed reply and
every forged one is refused.

= Will this break my WooCommerce checkout? =

No. The door answers a POST only when it arrives with `Content-Type: application/json`
AND no query string. WooCommerce's classic checkout, add-to-cart and coupon requests are
form-encoded, and every route WordPress multiplexes over the front page — `?wc-ajax=`,
`?wc-api=` payment webhooks, `?rest_route=` — carries a query string, so all of them fall
straight through to WordPress and behave exactly as they would with this plugin
deactivated. There is a test for each shape (`php tests/regression.php`).

= Will this interfere with referral links, UTM tags or my analytics? =

No. A visitor clicking a tagged link (`/?utm_source=...`, `/?ref=...`) arrives with GET,
and the door never touches a GET — every GET is your site's, tags and all, so your
analytics see exactly what they saw before.

The reverse also holds: an agent's POST can never carry a query string, because an agent
does not post to the link it was handed — it fetches your signed card first and posts to
the card's own `url`, byte-exact, which never contains one. That is why "any query string
means the request is not ours" is a safe rule and not a heuristic. (Attribution for agent
visits does not ride URL tags either way: the visitor list records each caller by their
cryptographic identity.)

= What happens if I delete the plugin? =

Deactivating keeps everything, because your site's identity has to survive being switched
off and on again — deleting the key there would silently give your site a NEW identity, and
every agent that recorded the old one would be talking to a stranger.

DELETING the plugin removes it all: the key, the visitor list, the plugin's tables and its
settings. That is deliberate — leaving a private key in the database of a site that removed
the plugin is a liability you did not agree to keep.

= Another AI plugin also serves an agent card. =

Then two plugins claim one path and a visitor cannot tell which answer is authoritative.
The settings screen detects this and names the conflicting identity; deactivate one.

== Screenshots ==

1. Settings → Agent Entry: your DID, your card URL, and whether the door is answering.
2. The agents that have visited, and how often.

== Changelog ==

= 0.1.4 =
* Order of your ways in (spec AE-30): a new optional setting publishes `agentEntry.prefer` on the
  card — which way into your site a visiting agent should try first, e.g. read on the page if it
  holds no key, otherwise the door. Published verbatim on the signed card; an invalid list is not
  saved, and an unset field publishes no key at all, so existing cards do not change.

= 0.1.3 =
* Discovery: the door pointer is now also an in-body `<a rel="https://muretai.net/rel/agent-entry">`,
  so a snapshot / ARIA / `a[href]` client (the shape a stealth agent browser uses) can still
  find the card. The HTTP `Link` header and the `<head>` tag were already there; those vanish
  in that view. Hooked on `wp_body_open`, with `wp_footer` as a fallback for themes that never
  call it. No change to verification, accounts, or refusals.

= 0.1.2 =
* Documentation: why the query-string rule costs nothing — tagged referral/UTM links are
  GETs and always the site's; an agent posts to the signed card's `url` byte-exact, which
  never carries a query. New FAQ entry, and regression pins for both behaviours (a tagged
  GET falls through; a cache-busted card fetch serves identical bytes). No behavioural
  change.

= 0.1.1 =
* Fix: the door no longer claims a POST that carries a query string. WordPress multiplexes
  whole APIs over the root path by query string, and some take JSON — WooCommerce Stripe's
  webhook endpoint (`/?wc-api=wc_stripe`) is one, and the door was answering it with an
  HTTP 200 error, which Stripe records as delivered and never retries. Update immediately
  if you run WooCommerce with a payment gateway that uses `?wc-api=` webhooks.

= 0.1.0 =
* First release: signed Agent Card, signed card envelope with hourly re-signing, the
  message door with full verification, per-visitor accounts, and the discovery signposts.
* WooCommerce: a product-search skill on the card, answered from the store's published
  catalogue.
