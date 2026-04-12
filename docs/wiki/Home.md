# Welcome to AeroDocs

AeroDocs is a web-based control panel for managing your servers. Instead of opening a terminal and SSH-ing into each machine individually, you can see all your servers in one place, check their status at a glance, and - once fully set up - tail logs, browse files, and transfer files from your browser.

Everything you do in AeroDocs is tracked. There is a permanent record of who logged in, who added or removed servers, and who changed account settings. This makes AeroDocs suitable for teams where accountability matters.

![Fleet Dashboard](screenshots/dashboard.png)

## What AeroDocs Does

- Shows you a live dashboard of all your registered servers (online, offline, or pending)
- Lets you onboard a new server with a single copy-paste command
- Manages agents on remote servers - install, register, and monitor from the Hub
- Provides a file tree browser to navigate the remote filesystem from your browser
- Streams live log tailing with grep filtering directly in the browser
- Supports drag-and-drop file transfers via the Dropzone uploader
- Records every action in an immutable audit log
- Requires two-factor authentication for every account - no exceptions
- Supports multiple user accounts with Admin, Auditor, and Viewer roles
- Sends email notifications for key events (server status changes, file uploads, user actions) via configurable SMTP
- Secures agent-to-hub communication with mutual TLS (mTLS) for certificate-based authentication
- Enforces sensitive path blocklists to prevent agents from exposing restricted filesystem paths

---

## For Admins

These guides cover features that require an admin role:

- [[Getting Started]] - Initial setup and first admin account
- [[Fleet Dashboard]] - Adding/removing servers, bulk operations
- [[Settings]] - User management, role changes, 2FA reset, email notifications, alert preferences

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
