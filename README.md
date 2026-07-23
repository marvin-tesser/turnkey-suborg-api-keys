Followed these instructions to setup root org: https://docs.turnkey.com/sdks/react/getting-started


Quickstart:

```
# Setup env vars
cp .env.example .env

# Install dependencies
bun install

# Run
bun dev
```

Then log in, then generate API keys. Two login modes:

- **Existing sub-org**: enter a sub-organization ID + email to log in to that specific sub-org.
- **Email only**: leave the sub-org ID blank. If a sub-org already exists for the email, you're logged into it; otherwise a new sub-org is created and you're logged in.