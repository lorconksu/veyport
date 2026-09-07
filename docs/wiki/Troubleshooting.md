# Troubleshooting

This page lists common issues and their solutions, organised by category.

---

## Login Issues

### I forgot my password

Veyport does not have a "forgot password" email flow. Ask an admin to delete your account and create a new one, or (if the admin has server access) use the CLI break-glass command to reset your credentials.

### My TOTP code isn't working

- Make sure you are entering the code for the **Veyport** entry in your authenticator app, not a different service.
- Check that your phone's clock is set to automatic/network time. TOTP codes are time-based and will fail if the clock is skewed.
- If you added the account manually (not via QR code), verify you entered the setup key correctly.
- Ask an admin to disable your 2FA from Settings > Users so you can re-enroll.

### I'm locked out after too many attempts

There are two independent controls that can produce a "too many attempts" style block. Check
which one applies:

**Per-IP rate limits.** Veyport enforces separate auth rate limits per IP address:

- Login and registration: 10 attempts per minute
- TOTP verification: 3 attempts per minute

Wait one minute and try again. These limits are IP-based, not per-account, so they clear whether
or not you used the right credentials.

**Per-account lockout.** Separately, after 5 consecutive failed sign-in attempts against the same
account within a 15-minute window (the default policy), that account locks for 15 minutes. Both
wrong passwords and wrong 2FA codes count toward the same limit. The error message is **"account
temporarily locked — try again later"**, shown in place of the usual invalid-credentials message,
and a correct password does not bypass it.

- Wait for the lock to expire (15 minutes by default), then sign in normally.
- Administrators can see whether an account is locked, and its unlock time, in **Settings → Users**
  (see [[Settings]]), and can clear the lock immediately with the **Unlock** action instead of
  waiting it out.
- If your account is directory-backed (LDAP) and your directory enforces its own lockout policy,
  you may need to wait out both locks — Veyport's lock and the directory's are independent.

### I see "account disabled"

An administrator has turned your account off — usually an offboarding, a suspected compromise, or
a contractor whose engagement ended. Sign-in, existing browser sessions, API tokens, SSH
certificate issuance, and SSH gateway shells are all refused with **"account disabled — contact an
administrator"** until an administrator uses **Enable** on your row in **Settings → Users** (see
[[Settings]]). There is nothing you can do yourself to clear this — waiting does not help, and
neither does a correct password.

### I see "account dormant"

Your account has gone unused — no interactive sign-in and no API-token use — for longer than the
hub's dormancy policy (35 days by default), so Veyport treats it as dormant until reviewed. This is
not a punishment or a suspicion of compromise; it is the same inactivity control most compliance
frameworks require. An administrator can restore access with **Enable** in **Settings → Users**
(see [[Settings]]), which also restarts your activity clock. If you expect to go unused for a long
stretch on purpose (a break, a long-lived automation account whose token nobody has touched
recently), ask an administrator to note the account or, for a recovery administrator specifically,
consider the dormancy exemption described next.

### Our only administrator hasn't signed in for weeks

By default, the very first administrator account ever created on this hub carries a "never
dormant" exemption, so it cannot lock everyone out simply by going quiet — it stays **Active**
indefinitely and always shows the **"Never dormant"** marker in the user list. If that
administrator has since left or you would rather a different account be the recovery path, have
any administrator assign the exemption to another admin account in **Settings → Users** using
**Exempt from dormancy** (see [[Settings]]); only administrator accounts can carry it.

### I was signed out unexpectedly

As of feature 009, every sign-in creates a server-side session with two independent limits (both
configurable in **Settings → Users → Account policy**, see [[Settings]]):

- **Idle timeout** (default **15 minutes**) - no request was made for that long. Ordinary use
  resets this clock, so it only fires when you actually stop using Veyport.
- **Maximum session** (default **12 hours**) - the session's absolute lifetime, set at sign-in and
  never extended, regardless of activity.

Either one ends the session the same way: the next request gets **"session expired — sign in
again"**, and a browser lands back on the sign-in page. Two other causes produce the same
"signed out" experience but a different message, **"session ended — sign in again"**: an
administrator ended your session (one specific session, or "Log out everywhere" - see
**Sessions** in [[Settings]]), or you yourself used **Sign out other sessions** on your Profile tab
from a different session. If your account was disabled rather than a session simply ending, see
"I see 'account disabled'" above instead. `vey` reports the same messages verbatim and exits with
its authentication-failure status (`3`) - run `vey login` again either way.

### Everyone had to sign in again after upgrading

The first time a hub is upgraded to a release with server-side session records (feature 009 and
later), every session that existed before the upgrade has no server-side record to validate
against, so it is refused - **"session expired — sign in again"** for browsers, the same message
and exit code `3` for `vey`. This is expected and one-time: every user, web and CLI, signs in once
more after that specific upgrade, and normal session behaviour applies from then on. There is
nothing to configure or recover - just sign in again.

### An open dashboard tab never seems to go idle

The Fleet Dashboard polls the Hub in the background roughly every 10 seconds, and each request
counts as activity, so a tab left open and visible can outlast the idle timeout indefinitely. This
is a known, documented limitation, not a bug: the **absolute session limit** (default 12 hours)
still applies regardless, so a tab open longer than that is eventually signed out anyway. Client-
side "the user actually walked away" detection (mouse/keyboard inactivity in the browser itself)
is out of scope for this release. If you need a tab to genuinely time out sooner, close it, or
ask an administrator to lower the maximum session limit.

### I'm the only admin and lost my authenticator

Someone with shell access to the Veyport server must run the CLI break-glass command:

```bash
./bin/veyport admin reset-totp --username <your-username> --db veyport.db
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

- Is the agent service running? `systemctl status veyport-agent`
- Can the server reach the Hub? Check network connectivity.
- Is the Hub's gRPC endpoint reachable from the agent? This is usually port `9090` directly, or the external address configured via `--grpc-external-addr` when using a proxy or load balancer.
- Restart the agent: `sudo systemctl restart veyport-agent`

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

The path may be on the sensitive path blocklist. Veyport prevents agents from exposing certain restricted filesystem paths (e.g. `/etc/shadow`, private key directories). If you need access to a blocked path, check the Hub's blocklist configuration. This is a security feature and cannot be overridden from the UI.

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

## Terminal Issues

### I do not see the Terminal button

- The server must be online. Terminal access is hidden while the agent is offline.
- Admins can open terminal sessions on any online server.
- LDAP users must be in the configured terminal access group (`veyport-terminal-users` by default) and must have a root (`/`) path assignment on that server.
- Local non-admin users cannot open terminal sessions.

### Terminal says "terminal execution user not available"

The Hub could not map the logged-in LDAP identity to a Linux account name for the agent to run as. Check that LDAP login is returning a username attribute, that the user's `ldap_username` is populated in Veyport, and that the same account is resolvable on the target server through NSS, SSSD, or the local account database.

### Terminal says "root server assignment required"

LDAP terminal access requires both the terminal LDAP group and a root (`/`) assignment on the target server. Ask an admin to open the server's Admin Tools panel and grant that user `/`.

### Terminal connects and immediately closes

- Check that the agent service is still online: `systemctl status veyport-agent`
- Confirm the target account has a valid shell and home directory on the agent host.
- Review agent logs: `journalctl -u veyport-agent -f`
- If a working directory was requested, confirm that path exists and is accessible by the execution user.

### API tokens cannot use terminal endpoints

Terminal endpoints require an interactive browser session. CLI-created API tokens are intentionally rejected so long-lived automation tokens cannot be used for interactive shell access.

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
- Verify the Hub gRPC address in the agent configuration file (`/etc/veyport/agent.conf`).
- Check agent logs: `journalctl -u veyport-agent -f`
- If mTLS is enabled, ensure the agent's certificate is valid and not expired.

### Agent shows proxy IP instead of real IP

The IP shown for an agent comes from the gRPC registration and heartbeat data, not from HTTP proxy headers like `X-Forwarded-For`. If the displayed IP looks wrong, restart the agent so it re-registers and sends a fresh heartbeat, then verify the host itself reports the expected primary IP. For proxy/TLS-passthrough setups, see the notes in `Proxy-Configuration.md`.

### Agent keeps reconnecting

- The Hub may be restarting or under heavy load. Check Hub service logs: `journalctl -u veyport -f`
- Network instability between the agent and Hub can cause repeated disconnects.
- Check if the Hub is running out of memory or file descriptors.
- The agent refreshes its reported IP on reconnect, so IP changes should be handled once the connection stabilizes.

### mTLS certificate errors

- Verify the agent's certificate has not expired: `openssl x509 -in /etc/veyport/agent.crt -noout -dates`
- Ensure the CA certificate on the Hub matches the one that signed the agent's certificate.
- Check that the system clock on both the agent and Hub is correct (certificate validation is time-sensitive).

### A node went offline after an outage and won't reconnect

Its mTLS client certificate probably expired while the node was down. When the node comes back online it phones home and the Hub shows the server as **Pending re-enrollment** on the Fleet Dashboard and the Server Detail page.

To recover:

1. Open the server's detail page and locate the **Pending re-enrollment** banner.
2. Review any **"possible clone"** warning (if present, verify you recognise this hardware before approving).
3. Click **Approve** and enter your TOTP code when prompted.

The node reconnects automatically within seconds, keeping the same serverID, history, and path assignments.

If the approval returns **"re-register required,"** the node predates transport-key support. Re-register it once using the standard install command; the node will have transport-key support after that and can use re-enrollment in future.

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

1. Check the Hub logs: `journalctl -u veyport -f`
2. Check the agent logs on the affected server: `journalctl -u veyport-agent -f`
3. File an issue on GitHub with the relevant log output and a description of what you expected to happen.
