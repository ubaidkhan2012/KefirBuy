=== KefirBuy App Connect ===
Requires at least: 6.2
Requires PHP: 7.4
Stable tag: 1.0.0

Lets the KefirBuy Android app sign customers in and show their orders, addresses and profile inside the app.

== Installation ==
1. In WordPress admin go to Plugins → Add New Plugin → Upload Plugin.
2. Choose kefirbuy-app-connect.zip, click Install Now, then Activate.
3. Done. The app detects the plugin automatically (open Account in the app).

== What it adds ==
REST API under /wp-json/kefirbuy-app/v1/ :
ping, login, register, password/lost, logout, me, me/password, me/address, me/delete, orders, orders/{id}, track.

== Security ==
- Customers sign in with their normal kefirbuy.com email/username and password (checked by WordPress itself, so security plugins still apply).
- The app receives a random token; only a keyed hash is stored. Tokens expire after 90 days, at most 10 devices per customer, and all are revoked when the password changes.
- Login, sign-up, password reset and order tracking are rate limited per IP address.
- Account deletion uses WordPress's built-in privacy request (customer confirms by email; you complete it in Tools → Erase Personal Data).
- Deleting the plugin removes all app tokens.
