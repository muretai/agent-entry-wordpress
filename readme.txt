=== Agent Entry ===
Contributors: muretai
Tags: ai, agents, ai-agents, api, automation
Requires at least: 5.8
Tested up to: 6.6
Requires PHP: 7.4
Stable tag: 0.1.0
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

Your home page is untouched. `GET /` is still your site; only `POST /` is the door.

**Every visitor gets an account, with no signup.** The first signed message from a
stranger *is* their account, because they already proved control of a key — more than an
email link proves. The settings screen shows who has visited, how often, and when.

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

No. Requests to paths the plugin does not own return immediately, before WordPress does any
page work, and the plugin adds one HTTP header to normal pages.

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
URL is really yours — which also catches another plugin claiming the same path. For an
independent check, run `receptor_check.py` from the muretai core repository against your
URL.

= Another AI plugin also serves an agent card. =

Then two plugins claim one path and a visitor cannot tell which answer is authoritative.
The settings screen detects this and names the conflicting identity; deactivate one.

== Screenshots ==

1. Settings → Agent Entry: your DID, your card URL, and whether the door is answering.
2. The agents that have visited, and how often.

== Changelog ==

= 0.1.0 =
* First release: signed Agent Card, signed card envelope with hourly re-signing, the
  message door with full verification, per-visitor accounts, and the discovery signposts.
