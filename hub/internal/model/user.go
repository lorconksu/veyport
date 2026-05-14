package model

import "time"

type Role string

const (
	RoleAdmin   Role = "admin"
	RoleAuditor Role = "auditor"
	RoleViewer  Role = "viewer"
)

type AuthProvider string

const (
	AuthProviderLocal AuthProvider = "local"
	AuthProviderLDAP  AuthProvider = "ldap"
)

func IsValidRole(role Role) bool {
	switch role {
	case RoleAdmin, RoleAuditor, RoleViewer:
		return true
	default:
		return false
	}
}

type User struct {
	ID                    string       `json:"id"`
	Username              string       `json:"username"`
	Email                 string       `json:"email"`
	PasswordHash          string       `json:"-"`
	Role                  Role         `json:"role"`
	AuthProvider          AuthProvider `json:"auth_provider"`
	ExternalID            string       `json:"external_id,omitempty"`
	LDAPDN                string       `json:"ldap_dn,omitempty"`
	LDAPUsername          string       `json:"ldap_username,omitempty"`
	LDAPLastSyncAt        *time.Time   `json:"ldap_last_sync_at,omitempty"`
	TerminalAccess        bool         `json:"terminal_access"`
	TOTPSecret            *string      `json:"-"`
	TOTPEnabled           bool         `json:"totp_enabled"`
	TokenGeneration       int          `json:"-"`
	Avatar                *string      `json:"avatar"`
	MustChangePassword    bool         `json:"must_change_password,omitempty"`
	TempPasswordExpiresAt *time.Time   `json:"temp_password_expires_at,omitempty"`
	CreatedAt             time.Time    `json:"created_at"`
	UpdatedAt             time.Time    `json:"updated_at"`
}

type UpdateAvatarRequest struct {
	Avatar string `json:"avatar"`
}

type CreateUserRequest struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Role     Role   `json:"role"`
}

type RegisterRequest struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type LoginTOTPRequest struct {
	TOTPToken string `json:"totp_token"`
	Code      string `json:"code"`
}

type RefreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type TOTPEnableRequest struct {
	Code        string `json:"code"`
	NewPassword string `json:"new_password,omitempty"`
}

type TOTPDisableRequest struct {
	UserID        string `json:"user_id"`
	AdminTOTPCode string `json:"admin_totp_code"`
}

type ChangePasswordRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

type UpdateRoleRequest struct {
	Role Role `json:"role"`
}

type TokenPair struct {
	AccessToken  string `json:"access_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

type AuthStatusResponse struct {
	Initialized bool   `json:"initialized"`
	Version     string `json:"version,omitempty"`
}

type LoginResponse struct {
	TOTPToken          string `json:"totp_token,omitempty"`
	SetupToken         string `json:"setup_token,omitempty"`
	RequiresTOTPSetup  bool   `json:"requires_totp_setup,omitempty"`
	MustChangePassword bool   `json:"must_change_password,omitempty"`
}

type AuthResponse struct {
	AccessToken  string `json:"access_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	User         User   `json:"user"`
}

type TOTPSetupResponse struct {
	Secret string `json:"secret"`
	QRURL  string `json:"qr_url"`
}

type CreateUserResponse struct {
	User              User   `json:"user"`
	TemporaryPassword string `json:"temporary_password"`
}
