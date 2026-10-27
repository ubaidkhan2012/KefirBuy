=== KefirBuy App Connect ===
Requires at least: 6.2
Requires PHP: 7.4
Stable tag: 1.2.0

Lets the KefirBuy Android app sign customers in and show their orders, addresses and profile inside the app.

== Installation ==
1. In WordPress admin go to Plugins → Add New Plugin → Upload Plugin.
2. Choose kefirbuy-app-connect.zip, click Install Now, then Activate.
3. Go to WooCommerce → KefirBuy App. Check the delivery prices and advance, and type your JazzCash / EasyPaisa numbers (shown to customers after they order). Bank details come from WooCommerce → Settings → Payments → Direct bank transfer.
4. Done. The app detects the plugin automatically.

== What it adds ==
REST API under /wp-json/kefirbuy-app/v1/ :
ping, config, reviews, login, register, password/lost, logout, me, me/password, me/address, me/delete, orders, orders/{id}, track.

== Changelog ==
= 1.2.0 =
* Paying the full amount in advance by bank transfer gets the same discount as JazzCash / EasyPaisa (5% up to Rs 150; can be switched off under WooCommerce → KefirBuy App). Works on the website checkout and in the app.
* The app shows your bank account (from Direct bank transfer settings) and Raast QR at checkout and after the order.
= 1.1.0 =
* WooCommerce → KefirBuy App settings page: delivery prices, COD advance, wallet discount, fresh cut-off hour, JazzCash/EasyPaisa details.
* config endpoint so the app always shows the store's current numbers and payment details.
* Customers can write product reviews in the app (respects WooCommerce review settings and comment moderation).

== Security ==
- Customers sign in with their normal kefirbuy.com email/username and password (checked by WordPress itself, so security plugins still apply).
- The app receives a random token; only a keyed hash is stored. Tokens expire after 90 days, at most 10 devices per customer, and all are revoked when the password changes.
- Login, sign-up, password reset, order tracking and reviews are rate limited per IP address.
- Account deletion uses WordPress's built-in privacy request (customer confirms by email; you complete it in Tools → Erase Personal Data).
- Deleting the plugin removes all app tokens.
