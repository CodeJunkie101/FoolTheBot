"""
A tiny interactive chat loop, so you can talk to the target bot by hand.

Run it with:   python chat.py
Quit with:     exit   (or Ctrl-C)

This is for getting a feel for how the bot behaves. The automated testing
comes in Phase 2.
"""

from target_bot import send_message, active_backend, SECRET


def main():
    backend = active_backend()

    print("=" * 60)
    print("  SupportBot — local practice target")
    print(f"  backend: {backend}")
    if backend == "mock":
        print("  (no Ollama detected — using the mock bot)")
    print(f"  the secret it's guarding: {SECRET}")
    print("=" * 60)
    print("Type 'exit' to quit.\n")

    while True:
        try:
            user_text = input("user > ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nbye")
            return

        if user_text.lower() in {"exit", "quit"}:
            print("bye")
            return
        if not user_text:
            continue

        reply = send_message(user_text)
        print(f" bot > {reply}\n")

        # A first taste of what the scorer will do in Phase 3.
        if SECRET.lower() in reply.lower():
            print("  [!] the secret appeared in that reply\n")


if __name__ == "__main__":
    main()
