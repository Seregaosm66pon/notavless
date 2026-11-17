"""
Helper script to generate a Telethon String Session for Telegram channel parsing.
Run this script interactively to log in with your phone number and get TG_SESSION_STRING.
"""

import asyncio
from telethon import TelegramClient
from telethon.sessions import StringSession


async def main() -> None:
    print("=" * 60)
    print("Nota Vless - Telegram Session String Generator")
    print("=" * 60)
    api_id_input = input("Enter your TG_API_ID (from my.telegram.org): ").strip()
    api_hash_input = input("Enter your TG_API_HASH: ").strip()

    if not api_id_input or not api_hash_input:
        print("[ERROR] TG_API_ID and TG_API_HASH cannot be empty.")
        return

    try:
        api_id = int(api_id_input)
    except ValueError:
        print("[ERROR] TG_API_ID must be an integer.")
        return

    client = TelegramClient(StringSession(), api_id, api_hash_input)
    await client.start()

    session_str = client.session.save()
    print("\n" + "=" * 60)
    print("SUCCESS! Your TG_SESSION_STRING is:")
    print("=" * 60)
    print(session_str)
    print("=" * 60)
    print("Copy this string and paste it into your .env or GitHub Secrets:")
    print(f"TG_SESSION_STRING={session_str}\n")

    await client.disconnect()


if __name__ == "__main__":
    asyncio.run(main())
