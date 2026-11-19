# Private payment notifications

Extension 2.1.18 reports a confirmed booking after the payment-tab tracker resolves the same URL used by Copy Payment Link. The existing 15-second redirect fallback still applies. Booking requests, cooldowns and public slot alerts are unchanged.

`POST /payment-notifications` requires the existing licence JWT and an active licence/device. The server looks up the licence username; incoming usernames or Telegram destinations are never used. The message contains country, city, subcategory, measured booking duration and the payment link.

Configuration: existing `TELEGRAM_BOT_TOKEN`; required `TELEGRAM_PAYMENT_CHAT_ID` selects the private admin destination. No Telegram token or destination ships in the extension. The bot needs permission to post in that channel. There is no mirroring to public/legacy/Pro channels.

Startup adds the `payment_notifications` table without modifying existing licence fields. The outbox deduplicates by licence and booking reference, survives server restarts, and claims deliveries atomically. Telegram previews are disabled. A confirmed Telegram rate limit can reschedule up to five attempts; uncertain network results are marked `unconfirmed`, never resent automatically, to avoid duplicate messages. Delivery text is removed after success/failure/uncertainty or after 24 hours pending. Only hashes/statuses remain; links and bot tokens are not logged or returned in HTTP responses. This provides best-effort delivery, not an exactly-once guarantee from Telegram.

Extension pending events are stored per licence for up to 24 hours, at most 100 pending events, with alarm-based retry for the reporting endpoint. A licence change cannot attribute an old event to the new user. Notification failures never initiate or retry bookings.

Validation: `npm install` then `npm test`. Tests use in-memory PostgreSQL (PGlite) and mocked Telegram, covering authentication, field validation, server-derived identity, concurrent duplicate submission, persistence across service instances, rate limits, uncertain responses and expiry. No live booking is needed.
