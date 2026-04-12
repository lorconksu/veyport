# Troubleshooting

This page lists common issues and their solutions, organised by category.

---

## Login Issues

### I forgot my password

AeroDocs does not have a "forgot password" email flow. Ask an admin to delete your account and create a new one, or (if the admin has server access) use the CLI break-glass command to reset your credentials.

### My TOTP code isn't working

- Make sure you are entering the code for the **AeroDocs** entry in your authenticator app, not a different service.
- Check that your phone's clock is set to automatic/network time. TOTP codes are time-based and will fail if the clock is skewed.
- If you added the account manually (not via QR code), verify you entered the setup key correctly.
- Ask an admin to disable your 2FA from Settings > Users so you can re-enroll.

### I'm locked out after too many attempts

AeroDocs enforces separate auth rate limits per IP address:

- Login and registration: 10 attempts per minute
- TOTP verification: 3 attempts per minute

Wait one minute and try again. These limits are IP-based, not per-account.

### I'm the only admin and lost my authenticator

Someone with shell access to the AeroDocs server must run the CLI break-glass command:

```bash
./bin/aerodocs admin reset-totp --username <your-username> --db aerodocs.db
```

This resets your TOTP and prints a temporary password to the terminal. Log in with the temporary password and you will be prompted to set up a new authenticator.

---

## Dashboard Issues

### My server shows as Pending

The agent has not registered with the Hub yet. Check the following:

- Was the install command actually run on the target server?
- Can the target server reach the Hub URL? Test with `curl https://your-hub-url/health` from the target server.
- Is a firewall blocking outbound connections from the target server?
- Has the registration token expired? If so, delete the server and add it again to get a fresh token.

### My server shows as Offline

The agent was previously connected but has lost its connection. Check:

- Is the agent service running? `systemctl status aerodocs-agent`
- Can the server reach the Hub? Check network connectivity.
- Is the Hub's gRPC endpoint reachable from the agent? This is usually port `9090` directly, or the external address configured via `--grpc-external-addr` when using a proxy or load balancer.
- Restart the agent: `sudo systemctl restart aerodocs-agent`

### Server status isn't updating

The Fleet Dashboard auto-refreshes every 10 seconds. If you're not seeing updates:

- Try a hard refresh of the page (Ctrl+Shift+R or Cmd+Shift+R).
- Open your browser's developer console and check for JavaScript errors.
- Verify you are not on a cached/stale page.

---

## File Browser Issues

### I can't see any files

Viewers need to be granted path access by an admin before they can see any files. Ask an admin to grant you access to the paths you need via the Admin Tools panel on the Server Detail page.

### Files are greyed out

Binary files or permission-restricted paths are visible in the directory listing but cannot be read. This is by design - the file tree shows an "honest" view of the directory structure rather than hiding files that exist but aren't readable.

### File content won't load

- Check that the server is online (green status on the Fleet Dashboard).
- The agent may have disconnected. Wait for reconnection or check the agent service on the remote server.
- Try navigating away and back to the file.

### File explorer sidebar or content viewer won't scroll

This was a layout bug fixed in v1.2.16. Update your Hub to v1.2.16 or later. After upgrading, do a hard refresh of the page (Ctrl+Shift+R or Cmd+Shift+R) to ensure you are loading the latest frontend assets.

### A path I expect is not visible

The path may be on the sensitive path blocklist. AeroDocs prevents agents from exposing certain restricted filesystem paths (e.g. `/etc/shadow`, private key directories). If you need access to a blocked path, check the Hub's blocklist configuration. This is a security feature and cannot be overridden from the UI.

---

## Log Tailing Issues

### No log lines appearing

- The file may not be receiving new writes. Try tailing an active log like `/var/log/syslog` to confirm the feature works.
- Check that the server is online and the agent is connected.
- Verify you have path access to the log file.

### Grep filter isn't matching

The grep filter is a **case-insensitive substring match**, not a regex. Check:

- Your spelling is correct.
- The text you are filtering for actually appears in the log output.
- Clear the filter field and verify that unfiltered lines are appearing.

---

## Upload / Dropzone Issues

### Upload fails

- The Dropzone is an **admin-only** feature. Check your role in Settings > Profile.
- Verify the server is online and the agent is connected.
- If the error mentions "no upload path configured," ask an admin to set an upload path for the server.

### I don't see the Dropzone tab

The Dropzone tab is only visible to admin users. Viewers cannot upload files. If you are an admin and still don't see it, try refreshing the page.

---

## Email Notification Issues

### Notifications are not being sent

- Verify that SMTP is configured in Settings > Notifications.
- Click **Send Test Email** to check that the SMTP configuration is valid.
- Check the notification log in Settings > Notifications for delivery errors.
- Ensure the recipient has enabled the relevant alert in Settings > Alerts.

### Test email succeeds but real notifications fail

- Check that the event type is toggled on in the recipient's Alerts tab.
- Some SMTP providers rate-limit outbound messages. Check your provider's sending limits.
- Review the notification log for specific error messages from the SMTP server.

---

## Agent Issues

### Install script fails

- Check that `curl` can reach the Hub URL from the target server: `curl -I https://your-hub-url`
- Verify the registration token hasn't expired (tokens are single-use and time-limited).
- Ensure you are running the install command as root or with `sudo`.
- Check DNS resolution on the target server.

### Agent won't connect after install

- Check that the firewall allows outbound connections to the Hub's gRPC endpoint. This is usually `9090` directly, or the external address configured via `--grpc-external-addr` (often `9443` behind a proxy).
- Verify the Hub gRPC address in the agent configuration file (`/etc/aerodocs/agent.conf`).
- Check agent logs: `journalctl -u aerodocs-agent -f`
- If mTLS is enabled, ensure the agent's certificate is valid and not expired.

### Agent shows proxy IP instead of real IP

The IP shown for an agent comes from the gRPC registration and heartbeat data, not from HTTP proxy headers like `X-Forwarded-For`. If the displayed IP looks wrong, restart the agent so it re-registers and sends a fresh heartbeat, then verify the host itself reports the expected primary IP. For proxy/TLS-passthrough setups, see the notes in `Proxy-Configuration.md`.

### Agent keeps reconnecting

- The Hub may be restarting or under heavy load. Check Hub service logs: `journalctl -u aerodocs -f`
- Network instability between the agent and Hub can cause repeated disconnects.
- Check if the Hub is running out of memory or file descriptors.
- The agent refreshes its reported IP on reconnect, so IP changes should be handled once the connection stabilizes.

### mTLS certificate errors

- Verify the agent's certificate has not expired: `openssl x509 -in /etc/aerodocs/agent.crt -noout -dates`
- Ensure the CA certificate on the Hub matches the one that signed the agent's certificate.
- Check that the system clock on both the agent and Hub is correct (certificate validation is time-sensitive).

---

## Admin Issues

### Can't create users

Only users with the **admin** role can create new accounts. Check your role in Settings > Profile.

### Can't change my own role

This is by design. You cannot change your own role - another admin must do it for you. This prevents accidental self-demotion.

### Can't delete my own account

This is by design. You cannot delete your own account - another admin must do it for you. This prevents the last admin from accidentally removing all admin access.

---

## Getting Help

If none of the above solves your issue:

1. Check the Hub logs: `journalctl -u aerodocs -f`
2. Check the agent logs on the affected server: `journalctl -u aerodocs-agent -f`
3. File an issue on GitHub with the relevant log output and a description of what you expected to happen.
