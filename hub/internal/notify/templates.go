package notify

import (
	"strings"

	"github.com/wyiu/veyport/hub/internal/model"
)

type emailTemplate struct {
	subject string
	body    string
}

var templates = map[string]emailTemplate{
	model.NotifyAgentOffline: {
		subject: "Agent Offline: {{server_name}}",
		body: "Agent {{server_name}} has gone offline.\n\n" +
			"This may indicate a network issue, reboot, or crash.\n\n" +
			"Please investigate the agent at your earliest convenience.",
	},
	model.NotifyAgentOnline: {
		subject: "Agent Online: {{server_name}}",
		body: "Agent {{server_name}} has connected and is now online.\n\n" +
			"The agent is ready to receive commands.",
	},
	model.NotifyAgentRegistered: {
		subject: "New Agent Enrolled: {{server_name}}",
		body: "A new agent has been registered.\n\n" +
			"Agent Name: {{server_name}}\n\n" +
			"The agent is now enrolled and awaiting connection.",
	},
	model.NotifyLoginFailed: {
		subject: "Failed Login Attempt",
		body: "A failed login attempt was detected.\n\n" +
			"Username: {{username}}\n" +
			"IP Address: {{ip}}\n\n" +
			"If this was not you, please review your security settings.",
	},
	model.NotifyUserCreated: {
		subject: "New User Created: {{username}}",
		body: "A new user account has been created.\n\n" +
			"Username: {{username}}\n\n" +
			"If this action was not authorized, please investigate immediately.",
	},
	model.NotifyTOTPChanged: {
		subject: "2FA Configuration Changed",
		body: "Two-factor authentication configuration has been changed.\n\n" +
			"Username: {{username}}\n" +
			"Detail: {{detail}}\n\n" +
			"If you did not make this change, contact your administrator.",
	},
	model.NotifyPasswordChanged: {
		subject: "Password Changed: {{username}}",
		body: "The password for user {{username}} has been changed.\n\n" +
			"If you did not make this change, contact your administrator immediately.",
	},
	model.NotifyAuditDegraded: {
		subject: "Audit Pipeline Degraded",
		body: "Veyport detected an audit logging failure.\n\n" +
			"Failure Count: {{failure_count}}\n" +
			"Last Failure: {{last_failure_at}}\n" +
			"Reason: {{last_failure_reason}}\n",
	},
	model.NotifyAuditRecovered: {
		subject: "Audit Pipeline Recovered",
		body: "Veyport audit logging has recovered.\n\n" +
			"Last Recovery: {{last_recovered_at}}\n" +
			"Failure Count: {{failure_count}}\n",
	},
	model.NotifyFileUploaded: {
		subject: "File Uploaded: {{filename}}",
		body: "A file has been uploaded.\n\n" +
			"File: {{filename}}\n" +
			"Server: {{server_name}}\n" +
			"Uploaded by: {{username}}\n",
	},
}

const fallbackSubject = "Veyport Notification: {{event_type}}"
const fallbackBody = "An event of type {{event_type}} occurred.\n\nPlease check the Veyport dashboard for details."

// RenderEmail returns the subject and body for a given event type, with
// {{key}} placeholders substituted from the provided context map.
// The subject is always prefixed with "[Veyport] ".
func RenderEmail(eventType string, context map[string]string) (subject, body string) {
	tmpl, ok := templates[eventType]
	if !ok {
		tmpl = emailTemplate{
			subject: fallbackSubject,
			body:    fallbackBody,
		}
		if context == nil {
			context = map[string]string{}
		}
		context["event_type"] = eventType
	}

	subject = "[Veyport] " + substitute(tmpl.subject, context)
	body = substitute(tmpl.body, context)
	return subject, body
}

// stripCRLF removes CR and LF characters to prevent SMTP header injection.
// Used by both email header construction (smtp.go) and template substitution.
func stripCRLF(s string) string {
	return strings.NewReplacer("\r", "", "\n", "").Replace(s)
}

// substitute replaces all {{key}} occurrences in s with values from the context map.
func substitute(s string, context map[string]string) string {
	for k, v := range context {
		s = strings.ReplaceAll(s, "{{"+k+"}}", stripCRLF(v))
	}
	return s
}
