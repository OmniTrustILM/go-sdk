package authority

import (
	"log/slog"
	"strings"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/authority/v3"
	"github.com/OmniTrustILM/go-sdk/connector/shared"
)

// Limits of a renewal info batch (1 to 50 certificates), which the generated
// model does not enforce.
const (
	minRenewalInfoItems = 1
	maxRenewalInfoItems = 50
)

// errValidationFailed renders 422 VALIDATION_FAILED. msg must be a %-free
// literal: shared.Invalid is printf-style and request content must not be
// echoed into an error body.
func errValidationFailed(msg string) *shared.Error {
	return shared.Invalid("VALIDATION_FAILED", "%s", msg)
}

// validateRenewalInfoRequest rejects a batch outside 1..50 items, and items
// with a blank or repeated reference or a blank certificate.
func validateRenewalInfoRequest(req *mdl.CertificateRenewalInfoRequestDtoV3) *shared.Error {
	n := len(req.Certificates)
	if n < minRenewalInfoItems || n > maxRenewalInfoItems {
		return errValidationFailed("certificates must contain between 1 and 50 items")
	}
	seen := make(map[string]struct{}, n)
	for _, item := range req.Certificates {
		if strings.TrimSpace(item.Reference) == "" {
			return errValidationFailed("certificate reference must not be blank")
		}
		if strings.TrimSpace(item.Certificate) == "" {
			return errValidationFailed("certificate must not be blank")
		}
		if _, dup := seen[item.Reference]; dup {
			return errValidationFailed("certificate references must be unique")
		}
		seen[item.Reference] = struct{}{}
	}
	return nil
}

// sanitizeRenewalInfoResponse returns resp with every available result that
// lacks a valid window (both bounds present, windowEnd after windowStart)
// rewritten to retry, which Core treats as a temporary failure. The provider's
// response is not modified.
func sanitizeRenewalInfoResponse(log *slog.Logger, resp *mdl.CertificateRenewalInfoResponseDtoV3) *mdl.CertificateRenewalInfoResponseDtoV3 {
	out := *resp
	out.Results = make([]mdl.CertificateRenewalInfoResultDtoV3, len(resp.Results))
	for i, res := range resp.Results {
		if res.Status == mdl.CERTIFICATERENEWALINFOSTATUSV3_AVAILABLE && !hasValidWindow(&res) {
			log.Warn("renewal info result has an invalid window; answering retry", "reference", res.Reference)
			res.Status = mdl.CERTIFICATERENEWALINFOSTATUSV3_RETRY
			res.WindowStart, res.WindowEnd = nil, nil
		}
		out.Results[i] = res
	}
	return &out
}

func hasValidWindow(res *mdl.CertificateRenewalInfoResultDtoV3) bool {
	return res.WindowStart != nil && res.WindowEnd != nil && res.WindowEnd.After(*res.WindowStart)
}
