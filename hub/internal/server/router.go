package server

import (
	"net/http"
	"time"

	"github.com/wyiu/aerodocs/hub/internal/auth"
)

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()

	loginLimiter := newRateLimiter(10, 60*time.Second)
	totpLimiter := newRateLimiter(3, 60*time.Second)
	refreshLimiter := newRateLimiter(30, 60*time.Second)
	fileOpsLimiter := newRateLimiter(60, 60*time.Second)

	// Public auth endpoints (rate-limited)
	mux.Handle("GET /api/health", loggingMiddleware(http.HandlerFunc(s.handleHealth)))
	mux.Handle("GET /api/auth/status", loggingMiddleware(http.HandlerFunc(s.handleAuthStatus)))
	mux.Handle("POST /api/auth/register", loggingMiddleware(loginLimiter.middleware(http.HandlerFunc(s.handleRegister))))
	mux.Handle("POST /api/auth/login", loggingMiddleware(loginLimiter.middleware(http.HandlerFunc(s.handleLogin))))
	mux.Handle("POST /api/auth/login/totp", loggingMiddleware(totpLimiter.middleware(http.HandlerFunc(s.handleLoginTOTP))))

	// Refresh endpoint (separate, higher-limit rate limiter)
	mux.Handle("POST /api/auth/refresh", loggingMiddleware(refreshLimiter.middleware(http.HandlerFunc(s.handleRefresh))))

	// Logout endpoint (no auth required — just clears cookies)
	mux.Handle("POST /api/auth/logout", loggingMiddleware(http.HandlerFunc(s.handleLogout)))

	// Setup-token-protected endpoints
	mux.Handle("POST /api/auth/totp/setup", loggingMiddleware(s.authMiddleware(auth.TokenTypeSetup, http.HandlerFunc(s.handleTOTPSetup))))
	mux.Handle("POST /api/auth/totp/enable", loggingMiddleware(s.authMiddleware(auth.TokenTypeSetup, http.HandlerFunc(s.handleTOTPEnable))))

	// Access-token-protected endpoints
	mux.Handle("GET /api/auth/me", loggingMiddleware(s.authMiddleware(auth.TokenTypeAccess, http.HandlerFunc(s.handleMe))))
	mux.Handle("PUT /api/auth/password", loggingMiddleware(s.authMiddleware(auth.TokenTypeAccess, s.interactiveOnly(http.HandlerFunc(s.handleChangePassword)))))
	mux.Handle("PUT /api/auth/avatar", loggingMiddleware(s.authMiddleware(auth.TokenTypeAccess, s.interactiveOnly(http.HandlerFunc(s.handleUpdateAvatar)))))
	mux.Handle("POST /api/auth/totp/disable", loggingMiddleware(s.authMiddleware(auth.TokenTypeAccess, s.interactiveOnly(s.adminOnly(http.HandlerFunc(s.handleTOTPDisable))))))

	// Admin endpoints
	mux.Handle("GET /api/users", loggingMiddleware(s.authMiddleware(auth.TokenTypeAccess, s.adminOnly(http.HandlerFunc(s.handleListUsers)))))
	mux.Handle("POST /api/users", loggingMiddleware(s.authMiddleware(auth.TokenTypeAccess, s.adminOnly(http.HandlerFunc(s.handleCreateUser)))))
	mux.Handle("PUT /api/users/{id}/role", loggingMiddleware(s.authMiddleware(auth.TokenTypeAccess, s.adminOnly(http.HandlerFunc(s.handleUpdateUserRole)))))
	mux.Handle("DELETE /api/users/{id}", loggingMiddleware(s.authMiddleware(auth.TokenTypeAccess, s.adminOnly(http.HandlerFunc(s.handleDeleteUser)))))
	mux.Handle("GET /api/audit-logs", loggingMiddleware(s.authMiddleware(auth.TokenTypeAccess, s.auditAccessOnly(http.HandlerFunc(s.handleListAuditLogs)))))
	mux.Handle("GET /api/audit-logs/catalog", loggingMiddleware(s.authMiddleware(auth.TokenTypeAccess, s.auditAccessOnly(http.HandlerFunc(s.handleAuditCatalog)))))
	mux.Handle("GET /api/audit-logs/health", loggingMiddleware(s.authMiddleware(auth.TokenTypeAccess, s.auditAccessOnly(http.HandlerFunc(s.handleAuditHealth)))))
	mux.Handle("GET /api/audit-logs/settings", loggingMiddleware(s.authMiddleware(auth.TokenTypeAccess, s.auditAccessOnly(http.HandlerFunc(s.handleGetAuditSettings)))))
	mux.Handle("PUT /api/audit-logs/settings", loggingMiddleware(s.authMiddleware(auth.TokenTypeAccess, s.adminOnly(http.HandlerFunc(s.handleUpdateAuditSettings)))))
	mux.Handle("GET /api/audit-logs/export", loggingMiddleware(s.authMiddleware(auth.TokenTypeAccess, s.auditAccessOnly(http.HandlerFunc(s.handleExportAuditLogs)))))
	mux.Handle("GET /api/audit-logs/exports", loggingMiddleware(s.authMiddleware(auth.TokenTypeAccess, s.auditAccessOnly(http.HandlerFunc(s.handleListAuditExports)))))
	mux.Handle("POST /api/audit-logs/retention/run", loggingMiddleware(s.authMiddleware(auth.TokenTypeAccess, s.adminOnly(http.HandlerFunc(s.handleRunAuditRetention)))))
	mux.Handle("GET /api/audit-logs/reviews", loggingMiddleware(s.authMiddleware(auth.TokenTypeAccess, s.auditAccessOnly(http.HandlerFunc(s.handleListAuditReviews)))))
	mux.Handle("POST /api/audit-logs/reviews", loggingMiddleware(s.authMiddleware(auth.TokenTypeAccess, s.auditAccessOnly(http.HandlerFunc(s.handleCreateAuditReview)))))
	mux.Handle("GET /api/audit-logs/filters", loggingMiddleware(s.authMiddleware(auth.TokenTypeAccess, s.auditAccessOnly(http.HandlerFunc(s.handleListAuditSavedFilters)))))
	mux.Handle("POST /api/audit-logs/filters", loggingMiddleware(s.authMiddleware(auth.TokenTypeAccess, s.auditAccessOnly(http.HandlerFunc(s.handleCreateAuditSavedFilter)))))
	mux.Handle("DELETE /api/audit-logs/filters/{id}", loggingMiddleware(s.authMiddleware(auth.TokenTypeAccess, s.auditAccessOnly(http.HandlerFunc(s.handleDeleteAuditSavedFilter)))))
	mux.Handle("GET /api/audit-logs/flags", loggingMiddleware(s.authMiddleware(auth.TokenTypeAccess, s.auditAccessOnly(http.HandlerFunc(s.handleListAuditFlags)))))
	mux.Handle("POST /api/audit-logs/flags", loggingMiddleware(s.authMiddleware(auth.TokenTypeAccess, s.auditAccessOnly(http.HandlerFunc(s.handleCreateAuditFlag)))))
	mux.Handle("GET /api/audit-logs/detections", loggingMiddleware(s.authMiddleware(auth.TokenTypeAccess, s.auditAccessOnly(http.HandlerFunc(s.handleAuditDetections)))))
	mux.Handle("GET /api/audit-users", loggingMiddleware(s.authMiddleware(auth.TokenTypeAccess, s.auditAccessOnly(http.HandlerFunc(s.handleListAuditUsers)))))

	// Hub configuration endpoints
	mux.Handle("GET /api/settings/hub", loggingMiddleware(s.authMiddleware(auth.TokenTypeAccess, s.adminOnly(http.HandlerFunc(s.handleGetHubConfig)))))
	mux.Handle("PUT /api/settings/hub", loggingMiddleware(s.authMiddleware(auth.TokenTypeAccess, s.adminOnly(http.HandlerFunc(s.handleUpdateHubConfig)))))

	// Notification endpoints
	mux.Handle("GET /api/settings/smtp", loggingMiddleware(s.authMiddleware(auth.TokenTypeAccess, s.adminOnly(http.HandlerFunc(s.handleGetSMTPConfig)))))
	mux.Handle("PUT /api/settings/smtp", loggingMiddleware(s.authMiddleware(auth.TokenTypeAccess, s.adminOnly(http.HandlerFunc(s.handleUpdateSMTPConfig)))))
	mux.Handle("POST /api/settings/smtp/test", loggingMiddleware(s.authMiddleware(auth.TokenTypeAccess, s.adminOnly(http.HandlerFunc(s.handleTestSMTP)))))
	mux.Handle("GET /api/notifications/preferences", loggingMiddleware(s.authMiddleware(auth.TokenTypeAccess, http.HandlerFunc(s.handleGetNotificationPreferences))))
	mux.Handle("PUT /api/notifications/preferences", loggingMiddleware(s.authMiddleware(auth.TokenTypeAccess, http.HandlerFunc(s.handleUpdateNotificationPreferences))))
	mux.Handle("GET /api/notifications/log", loggingMiddleware(s.authMiddleware(auth.TokenTypeAccess, s.adminOnly(http.HandlerFunc(s.handleListNotificationLog)))))

	// Server endpoints (any authenticated user, role-filtered in handler)
	mux.Handle("GET /api/servers", loggingMiddleware(s.authMiddleware(auth.TokenTypeAccess, http.HandlerFunc(s.handleListServers))))
	mux.Handle("POST /api/servers", loggingMiddleware(s.authMiddleware(auth.TokenTypeAccess, s.adminOnly(http.HandlerFunc(s.handleCreateServer)))))
	// batch-delete must be registered before /{id} routes so Go's ServeMux matches the literal path first
	mux.Handle("POST /api/servers/batch-delete", loggingMiddleware(s.authMiddleware(auth.TokenTypeAccess, s.adminOnly(http.HandlerFunc(s.handleBatchDeleteServers)))))
	mux.Handle("GET /api/servers/{id}", loggingMiddleware(s.authMiddleware(auth.TokenTypeAccess, http.HandlerFunc(s.handleGetServer))))
	mux.Handle("PUT /api/servers/{id}", loggingMiddleware(s.authMiddleware(auth.TokenTypeAccess, s.adminOnly(http.HandlerFunc(s.handleUpdateServer)))))
	mux.Handle("DELETE /api/servers/{id}", loggingMiddleware(s.authMiddleware(auth.TokenTypeAccess, s.adminOnly(http.HandlerFunc(s.handleDeleteServer)))))

	// File access path management (admin)
	mux.Handle("GET /api/servers/{id}/paths", loggingMiddleware(s.authMiddleware(auth.TokenTypeAccess, s.adminOnly(http.HandlerFunc(s.handleListPaths)))))
	mux.Handle("POST /api/servers/{id}/paths", loggingMiddleware(s.authMiddleware(auth.TokenTypeAccess, s.adminOnly(http.HandlerFunc(s.handleCreatePath)))))
	mux.Handle("DELETE /api/servers/{id}/paths/{pathId}", loggingMiddleware(s.authMiddleware(auth.TokenTypeAccess, s.adminOnly(http.HandlerFunc(s.handleDeletePath)))))
	// User's own paths (any authenticated user)
	mux.Handle("GET /api/servers/{id}/my-paths", loggingMiddleware(s.authMiddleware(auth.TokenTypeAccess, http.HandlerFunc(s.handleGetUserPaths))))

	// File browsing endpoints (any authenticated user, permission-checked in handler)
	mux.Handle("GET /api/servers/{id}/files", loggingMiddleware(fileOpsLimiter.middleware(s.authMiddleware(auth.TokenTypeAccess, http.HandlerFunc(s.handleListFiles)))))
	mux.Handle("GET /api/servers/{id}/files/read", loggingMiddleware(fileOpsLimiter.middleware(s.authMiddleware(auth.TokenTypeAccess, http.HandlerFunc(s.handleReadFile)))))

	// Log tailing SSE endpoint (any authenticated user, permission-checked in handler)
	mux.Handle("GET /api/servers/{id}/logs/tail", loggingMiddleware(fileOpsLimiter.middleware(s.authMiddleware(auth.TokenTypeAccess, http.HandlerFunc(s.handleTailLog)))))

	// Dropzone endpoints (admin only)
	mux.Handle("POST /api/servers/{id}/upload", loggingMiddleware(fileOpsLimiter.middleware(s.authMiddleware(auth.TokenTypeAccess, s.adminOnly(http.HandlerFunc(s.handleUploadFile))))))
	mux.Handle("GET /api/servers/{id}/dropzone", loggingMiddleware(fileOpsLimiter.middleware(s.authMiddleware(auth.TokenTypeAccess, s.adminOnly(http.HandlerFunc(s.handleListDropzone))))))
	mux.Handle("DELETE /api/servers/{id}/dropzone", loggingMiddleware(fileOpsLimiter.middleware(s.authMiddleware(auth.TokenTypeAccess, s.adminOnly(http.HandlerFunc(s.handleDeleteDropzoneFile))))))

	// Server unregister (admin only)
	mux.Handle("DELETE /api/servers/{id}/unregister", loggingMiddleware(s.authMiddleware(auth.TokenTypeAccess, s.adminOnly(http.HandlerFunc(s.handleUnregisterServer)))))

	// Public endpoints (no auth required)
	mux.Handle("GET /install.sh", loggingMiddleware(http.HandlerFunc(s.handleInstallScript)))
	mux.Handle("GET /install/{os}/{arch}", loggingMiddleware(http.HandlerFunc(s.handleAgentBinary)))
	mux.Handle("GET /install/{os}/{arch}/sha256", loggingMiddleware(http.HandlerFunc(s.handleAgentBinaryChecksum)))
	mux.Handle("DELETE /api/servers/{id}/self-unregister", loggingMiddleware(http.HandlerFunc(s.handleSelfUnregister)))

	// SPA catch-all — serves embedded frontend, falls back to index.html
	mux.Handle("/", s.spaHandler())

	// Apply CSRF, then CORS, then cache control for API, then security headers as outermost wrapper
	return securityHeaders(apiCacheControl(s.corsMiddleware(s.csrfMiddleware(requestIDMiddleware(mux)))))
}
