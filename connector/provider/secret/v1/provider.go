// Package secret provides the HTTP server adapter for the Secret Provider v1
// API. Connector authors implement the Provider interface (and any subset of
// the optional attribute provider interfaces) and register the resulting
// Handler with shared.Connector.
package secret

import (
	"context"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/secret/v1"
)

// Provider is the core business contract every Secret Provider connector must
// implement. Methods correspond 1:1 to the Secret Management endpoints in
// secret.json. Generated DTOs from the model package are passed through
// directly — no wrapping, no copying.
//
// Returned errors should be *shared.Error (use the sentinel values in
// errors.go or build with shared.NotFound/Conflict/...). Plain errors are
// rendered as a generic 500 INTERNAL_ERROR by shared.WriteProblem.
type Provider interface {
	// CreateSecret stores a new secret. 201 on success, 409 when the secret
	// already exists (return ErrSecretConflict).
	CreateSecret(ctx context.Context, req *mdl.CreateSecretRequestDto) (*mdl.SecretResponseDto, error)

	// UpdateSecret replaces an existing secret. 200 on success, 404 when the
	// secret does not exist (return ErrSecretNotFound).
	UpdateSecret(ctx context.Context, req *mdl.UpdateSecretRequestDto) (*mdl.SecretResponseDto, error)

	// DeleteSecret removes a secret. Returns nil on success regardless of
	// whether the secret existed (idempotent), or ErrSecretNotFound to surface
	// a 404 when the caller wants strict semantics.
	DeleteSecret(ctx context.Context, req *mdl.SecretRequestDto) error

	// RotateSecret replaces the stored content with a freshly generated value
	// and returns the updated metadata. The implementation chooses how to
	// generate the new content; rotation parameters come via the request's
	// rotate attributes.
	RotateSecret(ctx context.Context, req *mdl.SecretRequestDto) (*mdl.SecretResponseDto, error)

	// GetSecretContent reads the raw secret material. version is the optional
	// "version" query parameter — empty string means "current".
	GetSecretContent(ctx context.Context, req *mdl.SecretRequestDto, version string) (*mdl.SecretContentResponseDto, error)

	// CheckVaultConnection probes the vault backend with the supplied vault
	// attributes (typically connection settings entered in the UI). Returns
	// nil when the vault is reachable and configured correctly; otherwise an
	// *shared.Error (e.g. ErrVaultUnreachable, ErrInvalidAttributes).
	CheckVaultConnection(ctx context.Context, attrs []mdl.RequestAttribute) error
}
