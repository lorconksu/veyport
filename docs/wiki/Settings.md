# Settings

The Settings page is accessible from the sidebar. The available tabs depend on your role:

- **Profile** - available to every user
- **Alerts** - available to every user
- **Users** - admin only
- **Directory** - admin only
- **Notifications** - admin only

Auditors do not get the admin-only Settings tabs, but they do have access to the [[Audit Logs]] page in the main sidebar.

---

## Profile Tab (All Users)

![Settings Profile](screenshots/settings-profile.png)

The Profile tab is available to every user: admin, auditor, and viewer.

### Changing Your Avatar

Click the avatar circle at the top of the profile section. You can upload an image from your computer. The image is stored as part of your account and shown next to your name throughout the interface.

### Changing Your Password

In the **Change Password** section:

1. Enter your **current password**
2. Enter your **new password** (must be at least 12 characters and include uppercase, lowercase, digit, and special characters)
3. Confirm the new password
4. Click **Update Password**

You will remain logged in on the current device after changing your password. All other existing sessions (on other devices) are immediately invalidated and those users will need to log in again.

### Your Sessions

The **Your sessions** card lists every server-side session you currently hold: which browser or
CLI it is, its source address, when it started, and when it was last seen, plus any SSH shells
you have open (with the target server). The row for the session you're using right now is marked
**This session**.

- Click **Sign out** on any other row to end just that session or shell - a confirmation dialog
  appears first.
- Click **Sign out other sessions** to end everything except the session you're using right now
  (all other web sessions, CLI sessions, and your own open SSH shells) - useful after using a
  shared machine or forgetting to sign out somewhere. Confirm to proceed.
- If this is your only active session, the card shows "This is your only active session." instead
  of a **Sign out other sessions** button.

A signed-out browser session is returned to the sign-in page on its next request; a signed-out CLI
session shows the hub's message on its next command; a closed SSH shell receives an explanatory
message and exits. Every action here is audited as self-initiated (reason `revoked_self`). See
`GET /api/auth/sessions`, `DELETE /api/auth/sessions/{sid}`, and `POST
/api/auth/sessions/sign-out-others` in [[API Reference]].

Idle and absolute session limits apply the same way to your own sessions as to anyone else's - see
**Account Policy** below and [[Logging In]].

---

## Users Tab (Admin Only)

The Users tab lists all accounts registered in Veyport. This tab is only visible to admins.

![Settings Users](screenshots/settings-users.png)

LDAP-backed users are created or updated when they successfully log in through LDAP. Their role and terminal eligibility come from LDAP group mapping rather than manual local-user creation.

The table includes two columns covering sign-in activity:

- **Last login** - the account's most recent successful sign-in, shown as a relative time ("just now", "5 minutes ago", "3 hours ago", "2 days ago", or a date once it's further back). Hover for the exact local date and time. Shows **Never** (muted) for an account that has not yet signed in.
- **Status** - one badge per row, following the precedence **Disabled > Dormant > Locked > Active**:
  - **Active** - muted text; the account is usable.
  - **Locked until HH:MM** (warning badge) - the account's consecutive sign-in failures reached the lockout threshold; **Locked (no auto-unlock)** if the lockout policy has no automatic expiry. Hover for the current failure count.
  - **Disabled** (grey badge) - an admin turned the account off; the row is shown muted. Hover for when and by whom.
  - **Dormant** - the account has had no interactive sign-in and no API-token use for longer than the dormancy policy. Hover for its last activity.

  An administrator account carrying the dormancy exemption shows a small **"Never dormant"** marker next to its status, whatever that status is - hover it for "Exempt from dormancy."

### Row Actions: Disable, Enable, Unlock, Exempt from Dormancy

Alongside the existing role dropdown, Disable 2FA, and Delete, each row (never your own) offers
the actions that apply to its current state, each behind a confirmation dialog:

| Action | Shown when | What it does |
|---|---|---|
| **Disable** | account is not disabled | Immediately turns the account off: every one of the account's web and CLI sessions is ended and any open SSH shell is closed within seconds (feature 009 - same effect as **Log out everywhere** in **Sessions** below), every API token the account holds is revoked, and sign-in and SSH certificate issuance are refused. The row switches to **Disabled**. |
| **Enable** | account is disabled | Turns the account back on: clears any lock and the failure count, restarts the dormancy clock, and lets the account sign in again. Its API tokens stay revoked - the user must mint new ones. |
| **Unlock** | account is locked | Clears the lock and the consecutive-failure count immediately, without waiting for the lock to expire. Restarts the dormancy clock. |
| **Exempt from dormancy** / **Remove exemption** | account's role is Admin | Marks (or unmarks) the account as "never dormant" - see **Dormant accounts** below. Only administrator accounts can carry the exemption; it has no effect on locking or disabling. |
| **Sessions** | always (every row, including your own) | Opens the **Sessions** panel for that account - see **Sessions** below. |

Two guards apply to Disable, enforced by the server as well as the UI: you cannot disable your
own account, and you cannot disable the last remaining enabled administrator - an administrator
who is already disabled does not count toward that minimum. Both are refused with an explanatory
message rather than silently ignored. Every Disable, Enable, Unlock, and exemption change writes
an audit entry naming the acting administrator and the target account (see [[Audit Logs]]).

LDAP-backed (directory) accounts are governed identically to local accounts: an admin can
disable, enable, unlock, or exempt them, and a later directory sync cannot re-enable, unlock, or
clear the dormancy state of an account the hub has acted on.

### Sessions

Clicking **Sessions** on a row opens **"Sessions — &lt;username&gt;"**, a table of every
server-side session that account currently holds: kind (Web, CLI, SSH shell, Web terminal),
source address, when it started, when it was last seen, and the target server for a shell. If the
row belongs to your own account, your current session carries a **This session** tag.

- Each row offers **Log out** (web/CLI sessions) or **Terminate** (SSH/web-terminal shells),
  behind a confirmation dialog. The affected browser is sent to the sign-in page on its next
  request; a CLI session gets the hub's message on its next command; a shell receives an
  explanatory message and closes within seconds.
- The footer's **Log out everywhere** button ends every one of that account's web and CLI
  sessions and closes every one of its open SSH shells in one action, after confirming "Log out
  &lt;username&gt; everywhere? All web and CLI sessions end now and any open SSH shells are
  closed."
- An account with nothing open shows "No active sessions."

Disabling an account (above) does the equivalent of Log out everywhere automatically, as one of
its side effects. Every action here is audited with the acting administrator, the target account,
the session, and the reason (see [[Audit Logs]]). Underlying endpoints: `GET
/api/users/{id}/sessions`, `DELETE /api/users/{id}/sessions/{sid}`, `DELETE
/api/users/{id}/sessions` in [[API Reference]].

### Account Policy

An "Account policy" card above the table lets administrators read and edit six values in one
place, replacing the API-only configuration from the previous release:

| Field | Default | `0` means |
|---|---|---|
| Lockout threshold | 5 | Locking is disabled (failures are still counted and shown) |
| Lockout window (minutes) | 15 | - (not zero-able; the window a failure counts toward the threshold) |
| Lock duration (minutes) | 15 | A lock never expires on its own - only an admin's **Unlock** or **Enable** clears it |
| Dormant after (days) | 35 | Dormancy is disabled entirely - no account is ever evaluated as dormant |
| Idle timeout (minutes) | 15 | The idle limit is disabled - a session never times out from inactivity alone |
| Maximum session (hours) | 12 | The absolute limit is disabled - a session can run indefinitely as long as it stays active |

The card shows the effective values on load, validates each field as a non-negative integer with
an inline error on a bad entry (nothing is saved until every field is valid), and confirms with
"Account policy saved." on success. See `PUT /api/settings/hub` in [[API Reference]] for the
underlying fields (`lockout_threshold`, `lockout_window_minutes`, `lockout_duration_minutes`,
`dormant_days`, `session_idle_minutes`, `session_max_hours`).

**Idle timeout** and **maximum session** (feature 009) govern every server-side session - see
[[Logging In]] for what a user actually sees when one expires. An idle-timeout change takes effect
on every session's very next check; a maximum-session change only affects sessions created after
the save - a session already running keeps the absolute expiry it was issued with, even if the
policy is later lowered or raised.

### Dormant Accounts

An account is **dormant** when it has had no interactive sign-in and no API-token use for longer
than the "Dormant after" policy above. The clock is the latest of: the account's last sign-in,
its last API-token use, its last admin enable or unlock, or its creation - whichever happened
most recently. Using a token, not just signing in, counts as activity, so unattended automation
that runs regularly does not go dormant while it is in use.

Dormancy is evaluated when the account is actually used - at sign-in, at token authentication, at
SSH certificate issuance, and at SSH shell establishment - not by a background schedule, so there
is nothing to run and nothing to wait for. Between uses, the badge in the user list reflects the
same rule computed live each time the list is loaded.

To review a dormant account, look at its status badge and, if appropriate, click **Enable** -
this restarts its activity clock and restores access exactly like re-enabling a disabled account.
There is no separate "un-dormant" action.

**The dormancy exemption** exists so a hub is never left with an unusable administrator: mark one
administrator account (typically a dedicated recovery admin) **"never dormant"** in **Exempt from
dormancy** above, and it will keep signing in no matter how long it goes unused - the list shows
**Active** with the "Never dormant" marker instead of **Dormant**. The exemption affects only
dormancy; an exempt account can still be locked or manually disabled. The very first administrator
account created (on a fresh install, or the earliest-created admin on a hub upgraded from an
earlier release) carries the exemption by default, so an upgrade never locks an owner out of
their own hub. Changing an exempt account's role away from Admin removes the exemption
automatically.

Directory (LDAP) accounts are subject to dormancy exactly like local accounts, including the
exemption if one is assigned to an LDAP-backed admin.

Note: as of feature 009, disabling an account also closes any SSH shells it already has open (see
**Sessions** above) - new shells, new certificate requests, and existing sign-in attempts were
already refused before that. Going dormant on its own does not close open shells; a dormant
account's existing sessions and shells keep working until they time out or an admin acts on them.

### Creating a New User

1. Click **Create User**
2. Fill in the **Username**, **Email**, and **Role** (Admin, Auditor, or Viewer)
3. Click **Create**

Veyport generates a temporary password and shows it to you once. Copy it and share it securely with the new user. They will be required to change their password and set up TOTP on their first login.

New users cannot choose their own password during account creation - they must use the temporary password you provide.

### Changing a User's Role

In the user list, click the role badge next to a user's name. A dropdown appears letting you switch between roles. The change takes effect immediately and the user's current session will reflect the new role on their next API request.

**Admin** - Full access. Can add and delete servers, manage users, configure notifications, and manage audit settings.

**Auditor** - Read-only operational access plus access to [[Audit Logs]] for exports, reviews, detections, saved filters, and flagged events.

**Viewer** - Read-only operational access. Can view the fleet dashboard and server details but cannot make changes. Specific per-server and per-path permissions can be configured separately.

> **Note:** You cannot change your own role. Another admin must do it for you.

### Disabling a User's 2FA

If a user has lost access to their authenticator app, an admin can reset their TOTP:

1. Find the user in the list
2. Click the **...** (more options) menu next to their name
3. Choose **Disable 2FA**
4. You will be asked to enter **your own** current TOTP code to confirm the action (this prevents someone with a stolen admin session from locking everyone out)
5. Click **Confirm**

The user's TOTP is cleared. The next time they log in, they will be taken through the TOTP setup flow again before getting access.

### Deleting a User

1. Find the user in the list
2. Click the **...** menu next to their name
3. Choose **Delete User**
4. Confirm the deletion

Deleting a user is permanent and cannot be undone. Their audit log entries are preserved (the entries remain, but the user_id reference becomes orphaned).

> **Note:** You cannot delete your own account. Another admin must do it for you.

### Account Lockout Policy

After too many consecutive failed sign-in attempts, Veyport temporarily locks the account so an attacker cannot keep guessing. This is separate from the per-IP rate limits described in [[Troubleshooting]] - it tracks failures against the *account*, regardless of which IP address they come from.

A few things to know:

- Both a wrong password and a wrong 2FA code count as failures against the same counter - there is no separate counter per sign-in stage.
- The policy applies uniformly to local and LDAP-backed accounts.
- Attempts against a username that doesn't exist never create a lock and are unaffected.
- A lock clears itself automatically once its expiry passes, or immediately if an administrator uses **Unlock** on the row (see **Row Actions** above).
- Existing sessions, refresh tokens, API tokens, and SSH gateway access are unaffected by a lock - lockout only blocks new sign-ins, not a session already in progress.

The threshold, counting window, and lock duration are configured in the **Account policy** card
described above (or via `PUT /api/settings/hub` in [[API Reference]] as `lockout_threshold`,
`lockout_window_minutes`, and `lockout_duration_minutes`). Setting a lock duration of `0` means a
lock never expires on its own - administrator **Unlock** is then the only way back in, which is
fine now that the action exists, but worth knowing before choosing that value.

---

## Directory Tab (Admin Only)

The Directory tab lets admins configure LDAP login without direct database access.

### LDAP Server

Set the LDAP URL, bind DN, bind password, user base DN, and group base DN. The bind password is write-only: Veyport shows whether a password is stored, but never returns the secret to the browser.

Use `ldaps://` for normal deployments. Plain `ldap://` is rejected unless StartTLS is enabled or insecure transport is explicitly allowed.

### Role and Terminal Groups

Map LDAP groups to Veyport access levels:

- **Admin Groups** - users become Veyport admins
- **Auditor Groups** - users can access audit workflows
- **Viewer Groups** - users receive read-only operational access
- **Terminal Groups** - users become eligible for browser terminal sessions

Terminal group membership is not enough by itself. LDAP terminal users also need a root (`/`) path assignment on the target server.

### Search and TLS

FreeIPA-compatible defaults are prefilled for user filters, group filters, and common attributes. Adjust these if your directory uses different object classes or attribute names.

Click **Test Connection** to validate the LDAP URL, TLS settings, and service bind before saving or after changing configuration.

---

## Notifications Tab (Admin Only)

![Settings Notifications](screenshots/settings-notifications.png)

The Notifications tab lets admins configure email notifications for the entire Veyport instance.

### SMTP Configuration

Configure your outbound email settings:

- **SMTP Host** - The hostname of your mail server (e.g. `smtp.gmail.com`)
- **SMTP Port** - The port to connect on (e.g. `587` for STARTTLS, `465` for SSL)
- **Username** - The SMTP authentication username
- **Password** - The SMTP authentication password
- **From Address** - The sender address that will appear on notification emails (e.g. `veyport@example.com`)

Click **Save** to store the SMTP configuration. Credentials are encrypted at rest.

### Test Email

After saving your SMTP settings, click **Send Test Email** to send a test message to your own email address. This verifies that the SMTP configuration is correct and that emails can be delivered. A success or failure message is shown immediately.

### Notification Log

Below the SMTP configuration, a log shows recent notification delivery attempts:

- **Timestamp** - When the notification was sent
- **Recipient** - Who it was sent to
- **Subject** - The email subject line
- **Status** - Whether delivery succeeded or failed
- **Error** - If the delivery failed, the error message from the SMTP server

---

## Agent Tab (Admin Only)

The Agent tab contains settings that control agent certificate behaviour.

### Agent Certificate Validity

| Setting | Default | Description |
|---------|---------|-------------|
| `agent_cert_validity_hours` | `24` | Lifetime (in hours) of issued agent client certificates. Lower values tighten rotation; the value must stay comfortably above the 6-hour renewal margin used by the agent. Applies to newly issued and renewed certificates. |

Agents request renewal approximately 6 hours before their certificate expires. If an agent is offline longer than its certificate lifetime, its cert expires and it can no longer reconnect on its own. It will appear on the dashboard as **Pending re-enrollment** and requires admin approval before it can rejoin. See [[Troubleshooting]] for the recovery steps.

---

## Alerts Tab (All Users)

The Alerts tab lets each user configure their personal notification preferences. Each user controls which events trigger email notifications to their address.

Available event types include:

- **Server Online** - A server's agent connected to the Hub
- **Server Offline** - A server's agent disconnected from the Hub
- **File Uploaded** - A file was uploaded to a server via the Dropzone
- **User Login** - A user logged in to Veyport
- **User Created** - A new user account was created

Toggle each event on or off. Changes are saved automatically.

> **Note:** Email notifications require a working SMTP configuration in the Notifications tab. If SMTP is not configured, alerts will be silently skipped.
