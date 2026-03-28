#!/bin/bash
# Example usage script - demonstrates how to use the checker

set -e

echo "============================================================"
echo "MTProto Proxy Checker - Setup Example"
echo "============================================================"
echo ""

# Check if .env exists
if [ ! -f .env ]; then
    echo "Step 1: Creating .env file from template..."
    cp .env.example .env
    echo "✓ Created .env file"
    echo ""
    echo "⚠️  Please edit .env and add your values:"
    echo "   - BOT_TOKEN (from @BotFather)"
    echo "   - PROXY_HOST, PROXY_PORT, PROXY_SECRET"
    echo "   - Then run this script again to get CHAT_ID"
    echo ""
    exit 0
fi

# Source .env
source .env

# Check if BOT_TOKEN is set
if [ -z "$BOT_TOKEN" ] || [ "$BOT_TOKEN" = "your_bot_token_here" ]; then
    echo "❌ BOT_TOKEN not configured in .env"
    echo ""
    echo "To get a bot token:"
    echo "1. Open Telegram and search for @BotFather"
    echo "2. Send /newbot and follow instructions"
    echo "3. Copy the token to .env file"
    exit 1
fi

# Check if CHAT_ID is set
if [ -z "$CHAT_ID" ] || [ "$CHAT_ID" = "your_chat_id_here" ]; then
    echo "Step 2: Getting CHAT_ID..."
    echo ""
    echo "Please send a message to your bot in Telegram first!"
    echo "Then press Enter to retrieve the chat ID..."
    read -r
    
    python3 checker.py --get-chat-id
    
    echo ""
    echo "⚠️  Copy the CHAT_ID from above and add it to .env"
    echo "   Then run this script again to start the checker"
    exit 0
fi

# Check if proxy is configured
if [ "$PROXY_HOST" = "your_proxy_host" ]; then
    echo "❌ Proxy not configured in .env"
    echo ""
    echo "Please set PROXY_HOST, PROXY_PORT, and PROXY_SECRET in .env"
    exit 1
fi

echo "✓ Configuration looks good!"
echo ""
echo "Configuration:"
echo "  Bot Token: ${BOT_TOKEN:0:10}..."
echo "  Chat ID: $CHAT_ID"
echo "  Proxy: $PROXY_HOST:$PROXY_PORT"
echo "  Check Interval: ${CHECK_INTERVAL:-300}s"
echo ""

# Ask how to run
echo "How do you want to run the checker?"
echo "1) Docker Compose (recommended)"
echo "2) Python directly"
echo "3) Exit"
read -p "Choose [1-3]: " choice

case $choice in
    1)
        echo ""
        echo "Starting with Docker Compose..."
        docker-compose up -d
        echo ""
        echo "✓ Checker started!"
        echo ""
        echo "Useful commands:"
        echo "  docker-compose logs -f    # View logs"
        echo "  docker-compose stop       # Stop checker"
        echo "  docker-compose restart    # Restart checker"
        ;;
    2)
        echo ""
        echo "Starting with Python..."
        echo "Press Ctrl+C to stop"
        echo ""
        python3 checker.py
        ;;
    3)
        echo "Exiting..."
        exit 0
        ;;
    *)
        echo "Invalid choice"
        exit 1
        ;;
esac
