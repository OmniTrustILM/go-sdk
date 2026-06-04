// Package authority provides the HTTP server adapter for the Authority
// Provider v3 API. Connector authors implement the Provider interface (and
// any subset of the optional attribute provider interfaces) and register the
// resulting Handler with shared.Connector.
//
// Authority v3 is stateless: there are no authority-instance CRUD endpoints.
// Every operation carries the authority identity as request attributes
// (authorityAttributes + raProfileAttributes), so a single connector process
// can front any number of upstream CAs without holding instance state.
//
// v3 is a v2-family spec: info is served at /v2/info, health at /v2/health,
// and error responses use the RFC 9457 ProblemDetail shape — the
// shared.Connector defaults (WriteProblem renderer, v2 info/health) apply
// without extra wiring.
//
// Sync vs async: issue, renew, register and revoke may complete synchronously
// (200/204) or be accepted for asynchronous processing (202 with a meta
// tracking handle that Core replays on /status and /cancel calls). The
// Provider signals which happened through the `accepted` return value.
package authority

import (
	"context"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/authority/v3"
)

// Provider is the core business contract every Authority Provider v3
// connector must implement. Methods correspond 1:1 to the operations in
// authority-v3.yaml.
//
// Returned errors should be *shared.Error (use the sentinel values in
// errors.go or build with shared.NotFound/Invalid/...). Plain errors are
// rendered as 500 INTERNAL_ERROR via the problem renderer.
type Provider interface {
	// --- Certificate Management: issue family -----------------------------

	// Issue signs the CSR in req. Synchronous completion returns
	// (resp, false, nil) and renders 200 with the certificate in
	// resp.CertificateData. Asynchronous acceptance returns (resp, true, nil)
	// and renders 202; resp.Meta must carry the tracking handle Core replays
	// on IssueStatus / CancelIssue.
	Issue(ctx context.Context, req *mdl.CertificateSignRequestDtoV3) (resp *mdl.CertificateDataResponseDto, accepted bool, err error)

	// IssueStatus reports the state of an async issue/renew operation
	// identified by req.Meta. Completion returns (resp, false, nil) -> 200
	// with the certificate; still-pending returns (resp, true, nil) -> 202
	// echoing the tracking handle. Unknown handles should return
	// ErrOperationNotFound.
	IssueStatus(ctx context.Context, req *mdl.CertificateOperationStatusRequestDtoV3) (resp *mdl.CertificateDataResponseDto, pending bool, err error)

	// CancelIssue aborts an in-flight async issue/renew operation. Nil error
	// renders 204. Operations past the point of no return should return
	// ErrCancelRefused (422); unknown handles ErrOperationNotFound (404).
	CancelIssue(ctx context.Context, req *mdl.CertificateOperationCancelRequestDtoV3) error

	// Renew signs a renewal for an existing certificate. Same sync/async
	// semantics as Issue. When req.ReuseKey is true the CSR may be absent
	// and proof-of-possession is delegated to the upstream CA's policy.
	Renew(ctx context.Context, req *mdl.CertificateRenewRequestDtoV3) (resp *mdl.CertificateDataResponseDto, accepted bool, err error)

	// --- Certificate Management: register family --------------------------

	// Register pre-registers a certificate identity at the upstream CA
	// (no CSR involved). Synchronous completion returns (resp, false, nil)
	// -> 200 with resp.Meta identifying the registration (no
	// CertificateData); async acceptance returns (resp, true, nil) -> 202.
	Register(ctx context.Context, req *mdl.CertificateRegistrationRequestDtoV3) (resp *mdl.CertificateDataResponseDto, accepted bool, err error)

	// RegisterStatus reports the state of an async register operation.
	// Same semantics as IssueStatus.
	RegisterStatus(ctx context.Context, req *mdl.CertificateOperationStatusRequestDtoV3) (resp *mdl.CertificateDataResponseDto, pending bool, err error)

	// CancelRegister aborts an in-flight async register operation. Same
	// semantics as CancelIssue.
	CancelRegister(ctx context.Context, req *mdl.CertificateOperationCancelRequestDtoV3) error

	// --- Certificate Management: revoke family ----------------------------

	// Revoke revokes the certificate in req. Synchronous completion returns
	// (nil, false, nil) -> bare 204 (revoke carries no response payload).
	// Async acceptance returns (resp, true, nil) -> 202 with resp.Meta as
	// the tracking handle.
	Revoke(ctx context.Context, req *mdl.CertificateRevocationRequestDtoV3) (resp *mdl.CertificateDataResponseDto, accepted bool, err error)

	// RevokeStatus reports the state of an async revoke operation.
	// Completion returns (nil, false, nil) -> bare 204; still-pending
	// returns (resp, true, nil) -> 202 echoing the tracking handle.
	RevokeStatus(ctx context.Context, req *mdl.CertificateOperationStatusRequestDtoV3) (resp *mdl.CertificateDataResponseDto, pending bool, err error)

	// CancelRevoke aborts an in-flight async revoke operation. Same
	// semantics as CancelIssue.
	CancelRevoke(ctx context.Context, req *mdl.CertificateOperationCancelRequestDtoV3) error

	// --- Certificate Management: identify ---------------------------------

	// Identify looks up the certificate in req at the upstream CA. Always
	// synchronous; returns 200 with resp.Meta identifying the certificate.
	// Unknown certificates should return ErrCertificateNotFound.
	Identify(ctx context.Context, req *mdl.CertificateIdentificationRequestDtoV3) (*mdl.CertificateDataResponseDto, error)

	// --- Authority Management ---------------------------------------------

	// CheckAuthorityConnection validates the supplied authority attributes
	// by attempting to reach the upstream CA. Nil renders 204; failures
	// should return ErrConnectionFailed or a validation error.
	CheckAuthorityConnection(ctx context.Context, attrs []mdl.RequestAttribute) error

	// GetCrl returns the latest CRL (delta when req.Delta and supported).
	GetCrl(ctx context.Context, req *mdl.CrlRequestDtoV3) (*mdl.CertificateRevocationListResponseDto, error)

	// GetCaCertificates returns the CA certificate chain for the authority
	// identified by the request attributes.
	GetCaCertificates(ctx context.Context, req *mdl.CaCertificatesRequestDtoV3) (*mdl.CaCertificatesResponseDto, error)
}
