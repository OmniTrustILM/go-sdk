package main

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/authority/v3"
	authority "github.com/OmniTrustILM/go-sdk/connector/provider/authority/v3"
	"github.com/OmniTrustILM/go-sdk/connector/shared"
)

// revocationReasonCodes maps the spec's CertificateRevocationReason enum to
// RFC 5280 CRLReason codes used in the generated CRL.
var revocationReasonCodes = map[mdl.CertificateRevocationReason]int{
	mdl.CERTIFICATEREVOCATIONREASON_UNSPECIFIED:            0,
	mdl.CERTIFICATEREVOCATIONREASON_KEY_COMPROMISE:         1,
	mdl.CERTIFICATEREVOCATIONREASON_C_A_COMPROMISE:         2,
	mdl.CERTIFICATEREVOCATIONREASON_AFFILIATION_CHANGED:    3,
	mdl.CERTIFICATEREVOCATIONREASON_SUPERSEDED:             4,
	mdl.CERTIFICATEREVOCATIONREASON_CESSATION_OF_OPERATION: 5,
	mdl.CERTIFICATEREVOCATIONREASON_CERTIFICATE_HOLD:       6,
	mdl.CERTIFICATEREVOCATIONREASON_PRIVILEGE_WITHDRAWN:    9,
	mdl.CERTIFICATEREVOCATIONREASON_A_A_COMPROMISE:         10,
}

// asyncJob tracks one simulated asynchronous issue/renew operation. The job
// "completes" when wall-clock time passes readyAt — there is no background
// worker; completion is evaluated lazily on each status poll.
//
// regID carries the registration this issue runs against (empty when none).
// The registration is validated at submit but consumed only at completion
// (TakeRegistration in IssueStatus), so canceling the job leaves the
// registration reusable and the registered subject reliably overrides the
// CSR subject in the deferred signing.
type asyncJob struct {
	req      *mdl.CertificateSignRequestDtoV3 // nil for renew jobs
	renewReq *mdl.CertificateRenewRequestDtoV3
	regID    string
	readyAt  time.Time
	done     bool
	canceled bool
	serial   string
	certDER  []byte
}

// Backend implements authority.Provider plus the attribute provider
// interfaces against the in-memory CA. Every operation authenticates the
// request's authorityAttributes (ca_name + api_key) — the mandatory
// attributes published by Attrs.AuthorityAttributes — because v3 is
// stateless and each request must prove its authority context.
type Backend struct {
	cfg *Config
	ca  *CA

	mu   sync.Mutex
	jobs map[string]*asyncJob
}

func NewBackend(cfg *Config, ca *CA) *Backend {
	return &Backend{cfg: cfg, ca: ca, jobs: make(map[string]*asyncJob)}
}

// checkAuth validates the mandatory authority attributes on every request.
//
//   - missing ca_name or api_key  -> 422 VALIDATION_FAILED
//   - unknown ca_name             -> 422 VALIDATION_FAILED (named CA not provisioned)
//   - wrong api_key               -> 401 UNAUTHORIZED
func (b *Backend) checkAuth(authorityAttrs []mdl.RequestAttribute) error {
	caName, haveName := findString(authorityAttrs, caNameAttrUUID)
	if !haveName {
		return shared.Invalid("VALIDATION_FAILED", "authority attribute %q (ca_name) is required", caNameAttrUUID)
	}
	apiKey, haveKey := findString(authorityAttrs, apiKeyAttrUUID)
	if !haveKey {
		return shared.Invalid("VALIDATION_FAILED", "authority attribute %q (api_key) is required", apiKeyAttrUUID)
	}
	if caName != b.cfg.CaName {
		return shared.Invalid("VALIDATION_FAILED", "unknown CA").WithProperty("ca_name", caName)
	}
	if apiKey != b.cfg.ApiKey {
		return shared.Unauthorized("UNAUTHORIZED", "invalid api_key")
	}
	return nil
}

// validityFrom extracts the mandatory validity_days issue attribute.
func validityFrom(attrs []mdl.RequestAttribute) (time.Duration, error) {
	days, ok := findInt(attrs, validityDaysAttrUUID)
	if !ok {
		return 0, shared.Invalid("VALIDATION_FAILED", "issue attribute %q (validity_days) is required", validityDaysAttrUUID)
	}
	if days < 1 || days > 825 {
		return 0, shared.Invalid("VALIDATION_FAILED", "validity_days must be between 1 and 825").
			WithProperty("validity_days", fmt.Sprintf("%d", days))
	}
	return time.Duration(days) * 24 * time.Hour, nil
}

// parseCSR decodes a base64 DER PKCS#10 request.
func parseCSR(b64 string) (*x509.CertificateRequest, error) {
	der, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, shared.Invalid("VALIDATION_FAILED", "request is not valid base64: %s", err.Error())
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, shared.Invalid("VALIDATION_FAILED", "request is not a DER PKCS#10 CSR: %s", err.Error())
	}
	return csr, nil
}

// certResponse assembles the CertificateDataResponseDto for an issued cert.
func certResponse(der []byte, serial string) *mdl.CertificateDataResponseDto {
	resp := mdl.NewCertificateDataResponseDto()
	b64 := base64.StdEncoding.EncodeToString(der)
	resp.CertificateData = &b64
	ct := mdl.CERTIFICATETYPE_X_509
	resp.CertificateType = &ct
	resp.Meta = []mdl.MetadataAttribute{
		newMetaString(metaSerialUUID, "serial", "Certificate Serial", serial),
	}
	return resp
}

// --- issue family ------------------------------------------------------------

// Issue signs the CSR synchronously, or — when APP_ASYNC_ISSUE=true —
// enqueues a simulated async job that completes APP_ASYNC_DELAY after
// acceptance and returns 202 with a job tracking handle in meta.
func (b *Backend) Issue(ctx context.Context, req *mdl.CertificateSignRequestDtoV3) (*mdl.CertificateDataResponseDto, bool, error) {
	if err := b.checkAuth(req.AuthorityAttributes); err != nil {
		return nil, false, err
	}
	validity, err := validityFrom(req.Attributes)
	if err != nil {
		return nil, false, err
	}
	if req.Format != nil && *req.Format != mdl.CERTIFICATEREQUESTFORMAT_PKCS10 {
		return nil, false, shared.Invalid("VALIDATION_FAILED", "only pkcs10 CSRs are supported by this example").
			WithProperty("format", string(*req.Format))
	}
	csr, err := parseCSR(req.Request)
	if err != nil {
		return nil, false, err
	}

	// Issuance against a prior registration: meta carries the registration
	// id; the registered subject overrides the CSR subject. Validate the
	// registration exists up front (fast 404 at submit), but consume it
	// only at signing time — the sync path signs right below; the async
	// path defers both consumption and override to IssueStatus so a
	// canceled job does not burn the registration.
	regID, hasReg := metaString(req.Meta, metaRegistrationUUID)
	if hasReg {
		if reg := b.ca.GetRegistration(regID); reg == nil || reg.consumed {
			return nil, false, authority.ErrOperationNotFound.
				WithProperty("registration_id", regID)
		}
	}

	if b.cfg.AsyncIssue {
		jobID := uuid.NewString()
		b.mu.Lock()
		b.jobs[jobID] = &asyncJob{req: req, regID: regID, readyAt: time.Now().Add(b.cfg.AsyncDelay)}
		b.mu.Unlock()
		resp := mdl.NewCertificateDataResponseDto()
		resp.Meta = []mdl.MetadataAttribute{
			newMetaString(metaJobUUID, "job_id", "Async Job", jobID),
		}
		return resp, true, nil
	}

	subjectOverride, err := b.consumeRegistration(regID)
	if err != nil {
		return nil, false, err
	}
	der, serial, err := b.ca.Sign(csr, validity, subjectOverride)
	if err != nil {
		return nil, false, shared.Invalid("VALIDATION_FAILED", "%s", err.Error())
	}
	return certResponse(der, serial), false, nil
}

// consumeRegistration resolves regID into a subject override, marking the
// registration consumed. Empty regID means no registration: (nil, nil).
// A registration that disappeared (or was consumed by a competing issue
// between validation and signing) returns ErrOperationNotFound — one-shot
// semantics: the first issue to actually sign wins.
func (b *Backend) consumeRegistration(regID string) (*pkix.Name, error) {
	if regID == "" {
		return nil, nil
	}
	reg := b.ca.TakeRegistration(regID)
	if reg == nil {
		return nil, authority.ErrOperationNotFound.
			WithProperty("registration_id", regID)
	}
	return &pkix.Name{CommonName: reg.subjectDn}, nil
}

// IssueStatus resolves an async job by the job_id meta handle. Pending until
// readyAt passes; on first completed poll the CSR is actually signed.
func (b *Backend) IssueStatus(ctx context.Context, req *mdl.CertificateOperationStatusRequestDtoV3) (*mdl.CertificateDataResponseDto, bool, error) {
	if err := b.checkAuth(req.AuthorityAttributes); err != nil {
		return nil, false, err
	}
	jobID, ok := metaString(req.Meta, metaJobUUID)
	if !ok {
		return nil, false, shared.Invalid("VALIDATION_FAILED", "meta attribute %q (job_id) is required", metaJobUUID)
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	job, exists := b.jobs[jobID]
	if !exists || job.canceled {
		return nil, false, authority.ErrOperationNotFound.WithProperty("job_id", jobID)
	}

	if !job.done {
		if time.Now().Before(job.readyAt) {
			// Still pending: echo the tracking handle.
			resp := mdl.NewCertificateDataResponseDto()
			resp.Meta = []mdl.MetadataAttribute{
				newMetaString(metaJobUUID, "job_id", "Async Job", jobID),
			}
			return resp, true, nil
		}
		// Deadline passed: complete the job now (lazy completion).
		var csr *x509.CertificateRequest
		var validity time.Duration
		var err error
		switch {
		case job.req != nil:
			if validity, err = validityFrom(job.req.Attributes); err == nil {
				csr, err = parseCSR(job.req.Request)
			}
		case job.renewReq != nil:
			if validity, err = validityFrom(job.renewReq.Attributes); err == nil {
				csr, err = parseCSR(job.renewReq.GetRequest())
			}
		default:
			err = fmt.Errorf("job carries no request")
		}
		if err != nil {
			return nil, false, err
		}
		// Consume the registration (if any) now — at actual signing time,
		// not at acceptance — so the registered subject overrides the CSR
		// subject and a canceled job never burns the registration.
		subjectOverride, err := b.consumeRegistration(job.regID)
		if err != nil {
			return nil, false, err
		}
		der, serial, signErr := b.ca.Sign(csr, validity, subjectOverride)
		if signErr != nil {
			return nil, false, shared.Invalid("VALIDATION_FAILED", "%s", signErr.Error())
		}
		job.done, job.serial, job.certDER = true, serial, der
	}
	return certResponse(job.certDER, job.serial), false, nil
}

// CancelIssue aborts a pending async job. Completed jobs refuse with 422.
func (b *Backend) CancelIssue(ctx context.Context, req *mdl.CertificateOperationCancelRequestDtoV3) error {
	if err := b.checkAuth(req.AuthorityAttributes); err != nil {
		return err
	}
	jobID, ok := metaString(req.Meta, metaJobUUID)
	if !ok {
		return shared.Invalid("VALIDATION_FAILED", "meta attribute %q (job_id) is required", metaJobUUID)
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	job, exists := b.jobs[jobID]
	if !exists || job.canceled {
		return authority.ErrOperationNotFound.WithProperty("job_id", jobID)
	}
	if job.done || !time.Now().Before(job.readyAt) {
		// Lazily-completable counts as past the point of no return.
		return authority.ErrCancelRefused.WithProperty("job_id", jobID)
	}
	job.canceled = true
	return nil
}

// Renew validates the existing certificate, then signs the renewal CSR with
// the same sync/async behavior as Issue. With ReuseKey=true and no CSR the
// example refuses — it cannot prove possession of the original key.
func (b *Backend) Renew(ctx context.Context, req *mdl.CertificateRenewRequestDtoV3) (*mdl.CertificateDataResponseDto, bool, error) {
	if err := b.checkAuth(req.AuthorityAttributes); err != nil {
		return nil, false, err
	}
	validity, err := validityFrom(req.Attributes)
	if err != nil {
		return nil, false, err
	}

	// The cert being renewed must be one we issued and not revoked.
	existing, err := parseCertB64(req.ExistingCertificate)
	if err != nil {
		return nil, false, err
	}
	rec := b.ca.Lookup(existing.SerialNumber.String())
	if rec == nil {
		return nil, false, authority.ErrCertificateNotFound.
			WithProperty("serial", existing.SerialNumber.String())
	}
	if rec.revoked {
		return nil, false, shared.Invalid("VALIDATION_FAILED", "certificate is revoked").
			WithProperty("serial", existing.SerialNumber.String())
	}

	csrB64 := req.GetRequest()
	if csrB64 == "" {
		return nil, false, shared.Invalid("VALIDATION_FAILED",
			"this example does not support reuseKey renewals; supply a CSR")
	}
	csr, err := parseCSR(csrB64)
	if err != nil {
		return nil, false, err
	}

	if b.cfg.AsyncIssue {
		jobID := uuid.NewString()
		b.mu.Lock()
		b.jobs[jobID] = &asyncJob{renewReq: req, readyAt: time.Now().Add(b.cfg.AsyncDelay)}
		b.mu.Unlock()
		resp := mdl.NewCertificateDataResponseDto()
		resp.Meta = []mdl.MetadataAttribute{
			newMetaString(metaJobUUID, "job_id", "Async Job", jobID),
		}
		return resp, true, nil
	}

	der, serial, signErr := b.ca.Sign(csr, validity, nil)
	if signErr != nil {
		return nil, false, shared.Invalid("VALIDATION_FAILED", "%s", signErr.Error())
	}
	return certResponse(der, serial), false, nil
}

// --- register family ----------------------------------------------------------

// Register stores a pre-registered identity. Always synchronous in this
// example; the returned meta carries the registration id a later Issue
// consumes (the registered subject then overrides the CSR subject).
func (b *Backend) Register(ctx context.Context, req *mdl.CertificateRegistrationRequestDtoV3) (*mdl.CertificateDataResponseDto, bool, error) {
	if err := b.checkAuth(req.AuthorityAttributes); err != nil {
		return nil, false, err
	}
	subjectDn := req.GetSubjectDn()
	subjectAlt := req.GetSubjectAltName()
	if subjectDn == "" && subjectAlt == "" {
		return nil, false, shared.Invalid("VALIDATION_FAILED",
			"at least one of subjectDn or subjectAltName must be non-empty")
	}

	regID := uuid.NewString()
	b.ca.AddRegistration(regID, subjectDn, subjectAlt)

	resp := mdl.NewCertificateDataResponseDto()
	resp.Meta = []mdl.MetadataAttribute{
		newMetaString(metaRegistrationUUID, "registration_id", "Registration", regID),
	}
	return resp, false, nil
}

// RegisterStatus: registration is synchronous, so a known id is always done.
func (b *Backend) RegisterStatus(ctx context.Context, req *mdl.CertificateOperationStatusRequestDtoV3) (*mdl.CertificateDataResponseDto, bool, error) {
	if err := b.checkAuth(req.AuthorityAttributes); err != nil {
		return nil, false, err
	}
	regID, ok := metaString(req.Meta, metaRegistrationUUID)
	if !ok {
		return nil, false, shared.Invalid("VALIDATION_FAILED", "meta attribute %q (registration_id) is required", metaRegistrationUUID)
	}
	if b.ca.GetRegistration(regID) == nil {
		return nil, false, authority.ErrOperationNotFound.WithProperty("registration_id", regID)
	}
	resp := mdl.NewCertificateDataResponseDto()
	resp.Meta = []mdl.MetadataAttribute{
		newMetaString(metaRegistrationUUID, "registration_id", "Registration", regID),
	}
	return resp, false, nil
}

// CancelRegister: synchronous registration is always past the point of no
// return; known ids refuse with 422, unknown ids 404.
func (b *Backend) CancelRegister(ctx context.Context, req *mdl.CertificateOperationCancelRequestDtoV3) error {
	if err := b.checkAuth(req.AuthorityAttributes); err != nil {
		return err
	}
	regID, ok := metaString(req.Meta, metaRegistrationUUID)
	if !ok {
		return shared.Invalid("VALIDATION_FAILED", "meta attribute %q (registration_id) is required", metaRegistrationUUID)
	}
	if b.ca.GetRegistration(regID) == nil {
		return authority.ErrOperationNotFound.WithProperty("registration_id", regID)
	}
	return authority.ErrCancelRefused.WithProperty("registration_id", regID)
}

// --- revoke family --------------------------------------------------------------

// Revoke marks the certificate revoked. Always synchronous (204).
func (b *Backend) Revoke(ctx context.Context, req *mdl.CertificateRevocationRequestDtoV3) (*mdl.CertificateDataResponseDto, bool, error) {
	if err := b.checkAuth(req.AuthorityAttributes); err != nil {
		return nil, false, err
	}
	cert, err := parseCertB64(req.Certificate)
	if err != nil {
		return nil, false, err
	}
	reason, ok := revocationReasonCodes[req.Reason]
	if !ok {
		return nil, false, shared.Invalid("VALIDATION_FAILED", "unknown revocation reason").
			WithProperty("reason", string(req.Reason))
	}
	if !b.ca.Revoke(cert.SerialNumber.String(), reason) {
		return nil, false, authority.ErrCertificateNotFound.
			WithProperty("serial", cert.SerialNumber.String())
	}
	return nil, false, nil
}

// RevokeStatus: revocation is synchronous; a revoked serial reports done
// (204), an issued-but-not-revoked or unknown serial reports 404.
func (b *Backend) RevokeStatus(ctx context.Context, req *mdl.CertificateOperationStatusRequestDtoV3) (*mdl.CertificateDataResponseDto, bool, error) {
	if err := b.checkAuth(req.AuthorityAttributes); err != nil {
		return nil, false, err
	}
	serial, ok := metaString(req.Meta, metaSerialUUID)
	if !ok {
		return nil, false, shared.Invalid("VALIDATION_FAILED", "meta attribute %q (serial) is required", metaSerialUUID)
	}
	rec := b.ca.Lookup(serial)
	if rec == nil || !rec.revoked {
		return nil, false, authority.ErrOperationNotFound.WithProperty("serial", serial)
	}
	return nil, false, nil
}

// CancelRevoke: synchronous revocation cannot be canceled — always 422 for
// revoked serials, 404 otherwise.
func (b *Backend) CancelRevoke(ctx context.Context, req *mdl.CertificateOperationCancelRequestDtoV3) error {
	if err := b.checkAuth(req.AuthorityAttributes); err != nil {
		return err
	}
	serial, ok := metaString(req.Meta, metaSerialUUID)
	if !ok {
		return shared.Invalid("VALIDATION_FAILED", "meta attribute %q (serial) is required", metaSerialUUID)
	}
	rec := b.ca.Lookup(serial)
	if rec == nil || !rec.revoked {
		return authority.ErrOperationNotFound.WithProperty("serial", serial)
	}
	return authority.ErrCancelRefused.WithProperty("serial", serial)
}

// --- identify -----------------------------------------------------------------

// Identify reports whether the certificate was issued by this CA. Returns
// the serial as meta on success, 404 when the serial is unknown or the
// certificate bytes do not match the issued record.
func (b *Backend) Identify(ctx context.Context, req *mdl.CertificateIdentificationRequestDtoV3) (*mdl.CertificateDataResponseDto, error) {
	if err := b.checkAuth(req.AuthorityAttributes); err != nil {
		return nil, err
	}
	cert, err := parseCertB64(req.Certificate)
	if err != nil {
		return nil, err
	}
	serial := cert.SerialNumber.String()
	rec := b.ca.Lookup(serial)
	if rec == nil || !rec.cert.Equal(cert) {
		return nil, authority.ErrCertificateNotFound.WithProperty("serial", serial)
	}
	resp := mdl.NewCertificateDataResponseDto()
	resp.Meta = []mdl.MetadataAttribute{
		newMetaString(metaSerialUUID, "serial", "Certificate Serial", serial),
	}
	return resp, nil
}

// --- authority management -------------------------------------------------------

// CheckAuthorityConnection validates the mandatory authority attributes.
// There is no remote backend; authentication is the meaningful probe.
func (b *Backend) CheckAuthorityConnection(ctx context.Context, attrs []mdl.RequestAttribute) error {
	return b.checkAuth(attrs)
}

// GetCrl signs and returns a fresh full CRL. The example does not maintain
// delta CRLs: requests with delta=true still receive the full CRL, flagged
// delta=false so callers are not misled.
func (b *Backend) GetCrl(ctx context.Context, req *mdl.CrlRequestDtoV3) (*mdl.CertificateRevocationListResponseDto, error) {
	if err := b.checkAuth(req.AuthorityAttributes); err != nil {
		return nil, err
	}
	der, err := b.ca.CRL()
	if err != nil {
		return nil, fmt.Errorf("generate CRL: %w", err)
	}
	resp := mdl.NewCertificateRevocationListResponseDto(base64.StdEncoding.EncodeToString(der))
	delta := false
	resp.Delta = &delta
	return resp, nil
}

// GetCaCertificates returns the single-element chain: the root certificate.
func (b *Backend) GetCaCertificates(ctx context.Context, req *mdl.CaCertificatesRequestDtoV3) (*mdl.CaCertificatesResponseDto, error) {
	if err := b.checkAuth(req.AuthorityAttributes); err != nil {
		return nil, err
	}
	root := mdl.NewCertificateDataResponseDto()
	b64 := base64.StdEncoding.EncodeToString(b.ca.RootDER())
	root.CertificateData = &b64
	ct := mdl.CERTIFICATETYPE_X_509
	root.CertificateType = &ct
	return mdl.NewCaCertificatesResponseDto([]mdl.CertificateDataResponseDto{*root}), nil
}

// parseCertB64 decodes a base64 DER certificate.
func parseCertB64(b64 string) (*x509.Certificate, error) {
	der, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, shared.Invalid("VALIDATION_FAILED", "certificate is not valid base64: %s", err.Error())
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, shared.Invalid("VALIDATION_FAILED", "certificate is not DER X.509: %s", err.Error())
	}
	return cert, nil
}
