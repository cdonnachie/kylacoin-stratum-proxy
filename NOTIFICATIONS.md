# Block Notification Setup Guide

The KCN proxy now supports automatic notifications for blocks mined and miner connections via Discord and Telegram.

## Features

- **Discord Integration**: Rich embeds with color-coded notifications (green for blocks found)
- **Telegram Integration**: Formatted messages with Markdown support
- **Dual Notification**: Both services can run simultaneously for redundancy
- **Automatic Detection**: Services are enabled automatically when credentials are configured
- **Block Notifications**: Get notified when KCN or LCN blocks are mined
- **Connection Notifications**: Get notified when miners connect (🟢) or disconnect (🔴)

## Discord Setup

1. Create a Discord server (or use an existing one)
2. Go to Server Settings → Integrations → Webhooks
3. Click "New Webhook"
4. Choose a channel for notifications (e.g., #mining-alerts)
5. Copy the webhook URL
6. Add to your `.env` file:
   ```
   DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/YOUR_WEBHOOK_ID/YOUR_WEBHOOK_TOKEN
   ```

## Telegram Setup

1. Start a chat with [@BotFather](https://t.me/BotFather) on Telegram
2. Send `/newbot` and follow the prompts
3. Copy the bot token provided
4. Start a chat with your new bot (send any message like `/start`)
5. Get your chat ID:
   - Visit: `https://api.telegram.org/bot<YOUR_BOT_TOKEN>/getUpdates` (replace `<YOUR_BOT_TOKEN>` with your actual token)
   - You'll see a JSON response like this:
   ```json
   {
     "ok": true,
     "result": [
       {
         "update_id": 123456789,
         "message": {
           "message_id": 1,
           "from": {
             "id": 987654321,
             "is_bot": false,
             "first_name": "Your",
             "last_name": "Name",
             "username": "your_username",
             "language_code": "en"
           },
           "chat": {
             "id": 987654321,
             "first_name": "Your",
             "last_name": "Name",
             "username": "your_username",
             "type": "private"
           },
           "date": 1234567890,
           "text": "/start"
         }
       }
     ]
   }
   ```
   - Your chat ID is the `"id"` value in the `"chat"` object (in this example: `987654321`)
   - Note: Group chat IDs are often negative numbers
6. Add to your `.env` file:
   ```
   TELEGRAM_BOT_TOKEN=123456789:ABCdefGHIjklMNOpqrsTUVwxyz
   TELEGRAM_CHAT_ID=987654321
   ```

## Configuration

Edit your `.env` file to enable notifications:

```env
# Discord Notifications (optional)
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/YOUR_WEBHOOK_ID/YOUR_WEBHOOK_TOKEN

# Telegram Notifications (optional)
TELEGRAM_BOT_TOKEN=123456789:ABCdefGHIjklMNOpqrsTUVwxyz
TELEGRAM_CHAT_ID=123456789
```

You can enable:

- **Discord only**: Set only `DISCORD_WEBHOOK_URL`
- **Telegram only**: Set both `TELEGRAM_BOT_TOKEN` and `TELEGRAM_CHAT_ID`
- **Both services**: Set all three variables for redundant notifications

If no credentials are configured, the notification system will simply log that notifications are disabled.

## Notification Content

### Block Find Notifications

Each block notification includes:

- **Chain**: KCN or LCN
- **Block Height**: The height of the mined block
- **Block Hash**: The hash of the parent block
- **Worker**: The worker name/address
- **Difficulty**: The share difficulty when the block was found
- **Miner Software**: The miner software/version (if detected)
- **Timestamp**: When the block was found

### Miner Connection Notifications

Each connection/disconnection notification includes:

- **Status**: Connected (🟢) or Disconnected (🔴)
- **Worker**: The worker name/address
- **Miner Software**: The miner software/version (if detected)
- **Timestamp**: When the connection status changed

## Testing

After configuring your credentials:

1. Restart the KCN proxy
2. Look for startup logs:
   ```
   Discord notifications enabled
   Telegram notifications enabled
   ```
3. Connect a miner - you should receive a connection notification (🟢)
4. Disconnect the miner - you should receive a disconnection notification (🔴)
5. Mine until you find a block - you should receive a block find notification (🎉)
6. Check your Discord channel or Telegram chat for all notifications

## Troubleshooting

- **No notifications received**: Check your `.env` file is in the correct location and properly formatted
- **Discord webhook invalid**: Verify the webhook URL is complete and hasn't been revoked
- **Telegram not working**: Ensure you've started a chat with your bot before trying to receive messages
- **Wrong chat ID**: Visit the getUpdates URL again to verify your chat ID

## Log Messages

The notification system logs its activity:

- `Discord notifications enabled` - Discord webhook configured
- `Telegram notifications enabled` - Telegram bot configured
- `Block notifications disabled (no services configured)` - No credentials provided
- `Failed to send Discord notification: <error>` - Discord API error
- `Failed to send Telegram notification: <error>` - Telegram API error
