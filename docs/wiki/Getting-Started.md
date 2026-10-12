# Getting Started

This guide walks you through the initial setup of Veyport for the first time. This only needs to be done once - by the first admin. Your administrator should have already deployed the Veyport Hub (typically via Docker) before you begin.

> **What You'll Need**
>
> - A modern web browser (Chrome, Firefox, Edge, or Safari)
> - The Veyport URL provided by whoever deployed the Hub
> - A phone with an authenticator app (Google Authenticator, Authy, 1Password, etc.)

---

## Deploying the Hub

Veyport Hub is distributed as a Docker image. The default deployment path uses the published Docker Hub image:

```yaml
services:
  veyport:
    image: yiucloud/veyport:latest
    ports:
      - "8081:8081"
      - "127.0.0.1:9090:9090"
    volumes:
      - veyport-data:/data
    restart: unless-stopped

volumes:
  veyport-data:
```

Start the Hub:

```bash
docker compose up -d
```

The Hub listens on port `8081` for the web UI and REST API, and on port `9090` for agent gRPC connections. If you are exposing agents over TLS or through a reverse proxy, follow [[Deployment]] and [[Proxy Configuration]] for the correct `9443` external gRPC setup.

The Standard profile needs only the Hub, its SQLite data volume, and connected
agents; no external audit service is required. Enhanced command evidence is an
optional prototype and needs its separately qualified receipt and encrypted
archive services. Do not enable it by supplying an arbitrary archive URL. See
[[Architecture]] for the prototype's guarantees and limits. Its identity is
version `2.0.50-prototype.4` and immutable tag `prototype-ssh-passthrough.4`;
stable `2.0.49` does not include this feature. Before installing, check the
[prototype release page](https://github.com/lorconksu/veyport/releases/tag/prototype-ssh-passthrough.4)
for an actually published release and its required assets. If they are absent,
the prototype is unavailable. Use the Hub and CLI from the same source revision
with a compatible agent. Resolve the immutable OCI tag to its published digest
and verify the source revision.

For later maintenance, use `vey update` for the operator CLI and
`vey servers update <node>` for a supported enrolled Linux agent. Do not rerun
the enrollment installer for an ordinary agent upgrade; see [[Deployment]] for
the identity-preserving update and older-agent bootstrap steps.

---

## Step 1: Open Veyport in Your Browser

Navigate to the Veyport URL your administrator provided (for example, `https://veyport.example.com`).

If no accounts have been created yet, you will see the setup page instead of the login screen.

> **Note:** This setup page is only available once. After the first admin account is created, it is permanently disabled. Additional accounts must be created by an admin through the Settings page.

---

## Step 2: Create Your Admin Account

Fill in the setup form:

- **Username** - Choose a username. It must be 3-32 characters, letters and numbers only (no spaces).
- **Email** - Enter your email address.
- **Password** - Your password must be at least 12 characters long and include at least one uppercase letter, one lowercase letter, one number, and one special character.

Click **Create Admin Account** to continue.

---

## Step 3: Set Up Two-Factor Authentication

After creating your account, you will be taken directly to the TOTP (two-factor authentication) setup screen. This step is mandatory - you cannot skip it.

**Using an authenticator app (recommended):**

1. Open your authenticator app on your phone. Common choices are Google Authenticator, Authy, or 1Password.
2. Tap the "+" or "Add account" button.
3. Choose "Scan a QR code" and point your camera at the QR code on screen.
4. The app will add an "Veyport" entry and start showing a 6-digit code that changes every 30 seconds.
5. Type the current 6-digit code into the verification box on screen.
6. Click **Enable Two-Factor Authentication**.

**If you can't scan the QR code:**

Below the QR code there is a manual entry key (a long string of letters and numbers). In your authenticator app, choose "Enter a setup key" or "Manual entry" and type this key in. The account name can be anything you like (e.g. "Veyport").

> **Tip:** Save your manual key. Write it down or store it in a password manager. If you lose access to your authenticator app, you will need an admin to reset your 2FA using the server command line.

---

## Step 4: You're In

After verifying your TOTP code, you will be taken to the Fleet Dashboard.

![Fleet Dashboard](screenshots/dashboard-veyport.png)

From here you can start adding servers, creating user accounts, and exploring the rest of Veyport.

**Next steps:**
- [[Fleet Dashboard]] - Add your first server
- [[Settings]] - Create accounts for your team, configure email notifications
