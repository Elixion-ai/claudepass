# ClaudePass has its own Vault and no adapters to other password managers

The Broker must read values from somewhere. We chose an encrypted local file owned by ClaudePass, and rejected adapters to 1Password, Bitwarden, `pass`, or OS keychains as sources. Reasons: a dead first run for developers without those tools installed (neither `op` nor `bw` was present on the reference machine), and a product identity that stays whole rather than becoming a plugin to someone else's vault. Expect the adapter request to recur; this is the deliberate answer.
