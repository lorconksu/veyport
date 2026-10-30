# Welcome to Veyport

Veyport is a web-based control panel for managing your servers. Instead of opening separate SSH sessions for each machine, you can see all your servers in one place, check their status at a glance, tail logs, browse files, transfer files, and open governed terminal sessions from your browser.

Veyport keeps local audit metadata for supported account, server, and workflow
actions. Local metadata follows the Hub's configured retention and is not a
permanent external evidence store. The optional Enhanced profile preserves
covered command intent and selected originals through a separate receipt and
encrypted archive path; that evidence is limited to the submitted command or
complete supported script, not all remote process activity.

![Fleet Dashboard](screenshots/dashboard-veyport.png)

## What Veyport Does

- Shows you a live dashboard of all your registered servers (online, offline, or pending)
- Lets you onboard a new server with a single copy-paste command
- Manages agents on remote servers - install, register, and monitor from the Hub
- Provides a file tree browser to navigate the remote filesystem from your browser
- Streams live log tailing with grep filtering directly in the browser
- Opens browser-based terminal sessions for admins and authorized LDAP users
- Provides no-PTY command passthrough with `vey ssh <node> -- '<command>'` in the published CLI prototype ([[CLI Automation]])
- Supports drag-and-drop file transfers via the Dropzone uploader
- Records local audit metadata for supported account, server, file, terminal, and governance actions
- Requires two-factor authentication for every account - no exceptions
- Supports multiple user accounts with Admin, Auditor, and Viewer roles
- Signs users in against an existing LDAP directory (FreeIPA, OpenLDAP, Active Directory) with group-based role mapping, configured from the Settings &rarr; Directory tab
- Sends email notifications for key events (server status changes, file uploads, user actions) via configurable SMTP
- Secures agent-to-hub communication with mutual TLS (mTLS) for certificate-based authentication
- Enforces sensitive path blocklists to prevent agents from exposing restricted filesystem paths
- Records terminal open and close events alongside file, login, and server-management activity

Standard mode keeps these local audit features standalone. Enhanced command
evidence is an opt-in prototype with external receipt/archive requirements and
separate operational limits; it is not enabled by installing Veyport alone. See
[[CLI]], [[CLI Automation]], [[SSH Gateway]], [[Audit Logs]], and
[[Architecture]] for the feature boundary and prototype identity. The currently
published command-passthrough prototype is Hub `2.0.50-prototype.9` / tag
`prototype-ssh-passthrough.9`, with CLI and agent prototype 9 artifacts. Older
CLI prototype 6 builds are also compatible with the Hub. These prototype
builds are not a stable
or main-branch release. Check current publication and qualification on the
[release page](https://github.com/lorconksu/veyport/releases), then use
compatible builds and verify target agent support. See [[CLI Automation]] for
safe scripted use.

---

## For Admins

These guides cover features that require an admin role:

- [[Getting Started]] - Initial setup and first admin account
- [[Fleet Dashboard]] - Adding/removing servers, bulk operations
- [[Settings]] - User management, role changes, 2FA reset, LDAP directory integration, email notifications, alert preferences

---

## For Admins and Auditors

These guides cover audit and review workflows:

- [[Audit Logs]] - Activity monitoring, exports, reviews, detections, and compliance

---

## For All Users

These guides cover features available to every user (admin, auditor, and viewer):

- [[Logging In]] - Password + 2FA login
- [[Fleet Dashboard]] - Viewing server status at a glance
- [[Server Detail]] - Browsing files, tailing logs
- [[Settings]] - Profile and password management

---

## Need Help?

Check the [[Troubleshooting]] page for solutions to common issues.

## Security tooling support

Thanks to [Snyk](https://snyk.io/) for supporting Veyport through its
[Secure Developer Program](https://snyk.io/open-source/).
