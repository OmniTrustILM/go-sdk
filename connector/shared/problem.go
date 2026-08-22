package shared

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"sync"
	"time"
)

// ProblemContentType is the IANA media type for RFC 9457 problem responses.
const ProblemContentType = "application/problem+json"

// ErrorRenderer writes a JSON error response for err. Different connector
// specs use different error shapes (RFC 9457 ProblemDetail for v2 specs;
// ErrorMessageDto + validation arrays for v1 specs), so callers can swap
// implementations via WithErrorRenderer.
//
// The default renderer is WriteProblem (RFC 9457). Provider packages that
// need a different shape export their own renderer (e.g.
// discovery.WriteError) and require it to be set via WithErrorRenderer at
// Connector construction.
type ErrorRenderer func(w http.ResponseWriter, r *http.Request, err error)

// ProblemDetail mirrors the ProblemDetailExtended schema shared across every
// connector spec, rendered compliant with the platform error-handling
// contract (https://docs.otilm.com/docs/certificate-key/connectors/error-handling).
// Hoisted into the shared package so all providers serialize errors with one
// type rather than each generated copy.
//
// Type, Status, ErrorCode, Timestamp and Retryable are always present on the
// wire. Title and Detail are *string for source compatibility with existing
// callers, but WriteProblem always assigns them to a non-nil pointer to a
// non-empty string, so they too always render. Instance also always renders:
// WriteProblem defaults it to the request path when unset.
// RetryAfterSeconds renders only for retryable problems, defaulting to
// defaultRetryAfterSeconds when no explicit hint was set. CorrelationID,
// Causes and Properties are omitted when unset.
type ProblemDetail struct {
	Type              string         `json:"type"`
	Title             *string        `json:"title,omitempty"`
	Status            int            `json:"status"`
	Detail            *string        `json:"detail,omitempty"`
	Instance          *string        `json:"instance,omitempty"`
	ErrorCode         string         `json:"errorCode"`
	Timestamp         time.Time      `json:"timestamp"`
	CorrelationID     *string        `json:"correlationId,omitempty"`
	Retryable         bool           `json:"retryable"`
	RetryAfterSeconds *int           `json:"retryAfterSeconds,omitempty"`
	Causes            []Cause        `json:"causes,omitempty"`
	Properties        map[string]any `json:"properties,omitempty"`
}

// Cause describes one contributing failure within a problem document, e.g. a
// single failed field validation.
type Cause struct {
	Name   string `json:"name"`
	Reason string `json:"reason"`
	Rule   string `json:"rule,omitempty"`
}

// ProblemCategory is the first path segment of a problem type URI
// (https://docs.otilm.com/problems/{category}[/{interface}]/{CODE}).
type ProblemCategory string

const (
	// CategoryCommon groups error codes shared across every connector
	// interface (validation, not-found, internal errors, ...).
	CategoryCommon ProblemCategory = "common"
	// CategoryConnector groups error codes specific to connector behavior
	// (upstream/backend failures, credential/policy problems, ...).
	CategoryConnector ProblemCategory = "connector"
)

// Type-URI interface segments for the connector surfaces that scope an error
// code, e.g. https://docs.otilm.com/problems/connector/authority/CSR_MALFORMED.
// Each mirrors ConnectorInterface.getCode() upstream, which is the segment the
// platform's own renderer uses.
const (
	ifaceAuthority = "authority"
	ifaceDiscovery = "discovery"
)

// Known extension property keys conditionally promoted to top-level
// ProblemDetail fields by WriteProblem (see promoteProblemExtensions for
// exactly when each is consumed). Set via WithRetryable /
// WithRetryAfterSeconds / WithCauses rather than WithProperty directly,
// though WriteProblem honors either.
const (
	propRetryable         = "retryable"
	propRetryAfterSeconds = "retryAfterSeconds"
	propCauses            = "causes"
)

// defaultRetryAfterSeconds is the backoff hint rendered for a retryable
// problem that carries no explicit WithRetryAfterSeconds value — the
// platform's default retry backoff per the error-handling contract.
const defaultRetryAfterSeconds = 30

// buildProblemTypeURI constructs a platform problem type URI. iface is
// omitted from the path when empty. The variable segments are path-escaped:
// registered codes and ifaces are already shape-validated, but the error
// constructors accept arbitrary errorCode strings, and an unescaped space or
// slash would otherwise yield a malformed URI.
func buildProblemTypeURI(category ProblemCategory, iface, code string) string {
	if iface == "" {
		return fmt.Sprintf("https://docs.otilm.com/problems/%s/%s", category, url.PathEscape(code))
	}
	return fmt.Sprintf("https://docs.otilm.com/problems/%s/%s/%s", category, url.PathEscape(iface), url.PathEscape(code))
}

// problemCodeMeta describes how a given errorCode renders: which type-URI
// path it resolves to and whether it is retryable by default.
type problemCodeMeta struct {
	category  ProblemCategory
	iface     string
	retryable bool
}

var (
	problemCodeMu sync.RWMutex

	// problemCodeRegistry seeds the platform's canonical error codes;
	// connectors register additional codes (or override a built-in default)
	// via RegisterProblemCode at startup.
	problemCodeRegistry = map[string]problemCodeMeta{
		// common, no interface, non-retryable
		"VALIDATION_FAILED":       {category: CategoryCommon, retryable: false},
		"RESOURCE_NOT_FOUND":      {category: CategoryCommon, retryable: false},
		"RESOURCE_ALREADY_EXISTS": {category: CategoryCommon, retryable: false},
		"OPERATION_NOT_SUPPORTED": {category: CategoryCommon, retryable: false},
		"INTERNAL_SERVER_ERROR":   {category: CategoryCommon, retryable: false},
		"BAD_REQUEST":             {category: CategoryCommon, retryable: false},
		"UNAUTHORIZED":            {category: CategoryCommon, retryable: false},
		"FORBIDDEN":               {category: CategoryCommon, retryable: false},
		"ATTRIBUTES_ERROR":        {category: CategoryCommon, retryable: false},

		// common, no interface, retryable
		"REQUEST_TIMEOUT":     {category: CategoryCommon, retryable: true},
		"SERVICE_UNAVAILABLE": {category: CategoryCommon, retryable: true},
		"RATE_LIMIT_EXCEEDED": {category: CategoryCommon, retryable: true},
		"GATEWAY_TIMEOUT":     {category: CategoryCommon, retryable: true},

		// connector, no interface, non-retryable
		"UPSTREAM_ERROR":                    {category: CategoryConnector, retryable: false},
		"CREDENTIAL_INVALID":                {category: CategoryConnector, retryable: false},
		"POLICY_VIOLATION":                  {category: CategoryConnector, retryable: false},
		"OPERATION_PAST_POINT_OF_NO_RETURN": {category: CategoryConnector, retryable: false},
		"OPERATION_NOT_TRACKED":             {category: CategoryConnector, retryable: false},
		"ATTRIBUTE_DEFINITION_NOT_FOUND":    {category: CategoryConnector, retryable: false},

		// Document handling, raised by the content-signing formatting
		// contract. Cross-interface upstream, so no iface segment.
		"DOCUMENT_MALFORMED":    {category: CategoryConnector, retryable: false},
		"DOCUMENT_TOO_LARGE":    {category: CategoryConnector, retryable: false},
		"SIGNATURE_NOT_FOUND":   {category: CategoryConnector, retryable: false},
		"PARAMETER_UNSUPPORTED": {category: CategoryConnector, retryable: false},

		// connector/authority, non-retryable
		"CSR_MALFORMED":            {category: CategoryConnector, iface: ifaceAuthority, retryable: false},
		"REVOCATION_NOT_ALLOWED":   {category: CategoryConnector, iface: ifaceAuthority, retryable: false},
		"REGISTRATION_NOT_FOUND":   {category: CategoryConnector, iface: ifaceAuthority, retryable: false},
		"RENEWAL_SOURCE_NOT_FOUND": {category: CategoryConnector, iface: ifaceAuthority, retryable: false},
		"CSR_SUBJECT_MISMATCH":     {category: CategoryConnector, iface: ifaceAuthority, retryable: false},
		"CERTIFICATE_MISMATCH":     {category: CategoryConnector, iface: ifaceAuthority, retryable: false},

		// connector/discovery, non-retryable: a lost checkpoint cannot be
		// resumed, so the caller restarts the run rather than retrying.
		"CHECKPOINT_LOST": {category: CategoryConnector, iface: ifaceDiscovery, retryable: false},
	}
)

// problemCodeRe matches a valid errorCode: UPPER_SNAKE_CASE, starting with a
// letter.
var problemCodeRe = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)

// problemIfaceRe matches a valid type-URI interface segment: a single
// lowercase, kebab-case path segment (never a slash-separated path).
var problemIfaceRe = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)

// RegisterProblemCode adds or overrides the type-URI resolution and default
// retryability for an application error code. Connectors call this during
// startup, before serving any traffic, to register codes beyond the
// platform's built-in set (or to override a built-in default); it is not
// intended as a runtime toggle. Safe for concurrent use.
//
// code must be UPPER_SNAKE_CASE (^[A-Z][A-Z0-9_]*$); category must be
// CategoryCommon or CategoryConnector; iface must be empty or a single
// lowercase, kebab-case path segment (^[a-z][a-z0-9-]*$) — never a
// slash-separated path. RegisterProblemCode validates all three and returns
// a descriptive error without registering anything if any check fails.
func RegisterProblemCode(code string, category ProblemCategory, iface string, retryable bool) error {
	if !problemCodeRe.MatchString(code) {
		return fmt.Errorf("shared: invalid problem code %q: must match %s (UPPER_SNAKE_CASE)", code, problemCodeRe.String())
	}
	if category != CategoryCommon && category != CategoryConnector {
		return fmt.Errorf("shared: invalid problem category %q: must be %q or %q", category, CategoryCommon, CategoryConnector)
	}
	if iface != "" && !problemIfaceRe.MatchString(iface) {
		return fmt.Errorf("shared: invalid problem iface %q: must be empty or match %s (single lowercase path segment)", iface, problemIfaceRe.String())
	}
	problemCodeMu.Lock()
	defer problemCodeMu.Unlock()
	problemCodeRegistry[code] = problemCodeMeta{category: category, iface: iface, retryable: retryable}
	return nil
}

// lookupProblemCode returns the registered metadata for code, if any.
func lookupProblemCode(code string) (problemCodeMeta, bool) {
	problemCodeMu.RLock()
	defer problemCodeMu.RUnlock()
	meta, ok := problemCodeRegistry[code]
	return meta, ok
}

// resolveProblemTypeURI picks the RFC 9457 "type" value for a rendered
// problem document. An already-set, non-"about:blank" existing value wins
// (an explicit WithTypeURI always takes precedence); otherwise the errorCode
// is resolved against the registry, falling back to common/{errorCode}, and
// finally to common/INTERNAL_SERVER_ERROR when no errorCode is available.
func resolveProblemTypeURI(existing, errorCode string) string {
	if existing != "" && existing != "about:blank" {
		return existing
	}
	if meta, ok := lookupProblemCode(errorCode); ok {
		return buildProblemTypeURI(meta.category, meta.iface, errorCode)
	}
	if errorCode != "" {
		return buildProblemTypeURI(CategoryCommon, "", errorCode)
	}
	return buildProblemTypeURI(CategoryCommon, "", "INTERNAL_SERVER_ERROR")
}

// defaultRetryable returns the registry default retryability for code (false
// if the code is not registered).
func defaultRetryable(code string) bool {
	meta, ok := lookupProblemCode(code)
	return ok && meta.retryable
}

// Error is the connector domain error. Carries everything needed to render a
// ProblemDetailExtended response. Provider packages return *Error from their
// handlers; non-*Error values bubble through WriteProblem and are logged at
// error level then mapped to a generic 500.
type Error struct {
	Status     int
	ErrorCode  string
	Title      string
	Detail     string
	TypeURI    string
	Instance   string
	Properties map[string]any
	Cause      error
}

func (e *Error) Error() string {
	if e == nil {
		return "<nil shared.Error>"
	}
	if e.Cause != nil {
		return fmt.Sprintf("%s: %s: %v", e.ErrorCode, e.Detail, e.Cause)
	}
	return fmt.Sprintf("%s: %s", e.ErrorCode, e.Detail)
}

func (e *Error) Unwrap() error { return e.Cause }

// WithCause returns a copy of e with cause attached. The cause is logged but
// not serialized into the response body.
func (e *Error) WithCause(cause error) *Error {
	ne := *e
	ne.Cause = cause
	return &ne
}

// WithProperty returns a copy of e with the given extension property attached.
// Renders into the "properties" object of the problem JSON, unless key is one
// of the known extension keys ("retryable", "retryAfterSeconds", "causes"),
// which WriteProblem conditionally promotes to top-level ProblemDetail
// fields instead (see promoteProblemExtensions for when each is consumed).
func (e *Error) WithProperty(key string, value any) *Error {
	ne := *e
	if ne.Properties == nil {
		ne.Properties = map[string]any{key: value}
	} else {
		clone := make(map[string]any, len(ne.Properties)+1)
		for k, v := range ne.Properties {
			clone[k] = v
		}
		clone[key] = value
		ne.Properties = clone
	}
	return &ne
}

// WithInstance overrides the instance URI (default is the request path).
func (e *Error) WithInstance(instance string) *Error {
	ne := *e
	ne.Instance = instance
	return &ne
}

// WithTypeURI overrides the RFC 9457 type URI (default "about:blank", which
// WriteProblem resolves to a platform problem type URI).
func (e *Error) WithTypeURI(uri string) *Error {
	ne := *e
	ne.TypeURI = uri
	return &ne
}

// WithRetryable returns a copy of e recording whether the operation that
// produced it can be safely retried. Rendered as the top-level "retryable"
// field by WriteProblem, overriding the registry default for e.ErrorCode.
func (e *Error) WithRetryable(retryable bool) *Error {
	return e.WithProperty(propRetryable, retryable)
}

// WithRetryAfterSeconds returns a copy of e carrying a backoff hint. Rendered
// as the top-level "retryAfterSeconds" field by WriteProblem when the
// problem is retryable. Setting this does not by itself mark the error
// retryable — pair it with WithRetryable(true) (or rely on the registry
// default) if the error is not already retryable. On a non-retryable problem
// the hint is not promoted; it stays visible under "properties" instead of
// silently disappearing.
func (e *Error) WithRetryAfterSeconds(seconds int) *Error {
	return e.WithProperty(propRetryAfterSeconds, seconds)
}

// WithCauses returns a copy of e carrying the contributing failures rendered
// as the top-level "causes" field by WriteProblem.
func (e *Error) WithCauses(causes []Cause) *Error {
	return e.WithProperty(propCauses, causes)
}

func newError(status int, code, msg string, args ...any) *Error {
	detail := msg
	if len(args) > 0 {
		detail = fmt.Sprintf(msg, args...)
	}
	return &Error{
		Status:    status,
		ErrorCode: code,
		Title:     http.StatusText(status),
		Detail:    detail,
		TypeURI:   "about:blank",
	}
}

// HTTP-status constructors. The error code is application-defined and should
// match the ErrorCode enum from the relevant generated model package.
func BadRequest(code, msg string, a ...any) *Error {
	return newError(http.StatusBadRequest, code, msg, a...)
}
func Unauthorized(code, msg string, a ...any) *Error {
	return newError(http.StatusUnauthorized, code, msg, a...)
}
func Forbidden(code, msg string, a ...any) *Error {
	return newError(http.StatusForbidden, code, msg, a...)
}
func NotFound(code, msg string, a ...any) *Error {
	return newError(http.StatusNotFound, code, msg, a...)
}
func Conflict(code, msg string, a ...any) *Error {
	return newError(http.StatusConflict, code, msg, a...)
}
func Invalid(code, msg string, a ...any) *Error {
	return newError(http.StatusUnprocessableEntity, code, msg, a...)
}
func Internal(code, msg string, a ...any) *Error {
	return newError(http.StatusInternalServerError, code, msg, a...)
}
func Unavailable(code, msg string, a ...any) *Error {
	return newError(http.StatusServiceUnavailable, code, msg, a...)
}

// WriteProblem serializes err as application/problem+json, compliant with
// the platform error-handling contract
// (https://docs.otilm.com/docs/certificate-key/connectors/error-handling):
// type, title, status, detail, errorCode, timestamp, retryable and instance
// are always present (instance defaults to the request path when the error
// set none); retryAfterSeconds renders only for retryable problems,
// defaulting to defaultRetryAfterSeconds when no explicit hint was set;
// correlationId and causes are omitted when unset.
//
// Non-*Error values (including those wrapped via fmt.Errorf with %w) are
// unwrapped via errors.As; if no *Error is found, the error is logged and a
// generic 500 response is written with INTERNAL_SERVER_ERROR, the platform's
// canonical internal-error code.
func WriteProblem(w http.ResponseWriter, r *http.Request, err error) {
	if err == nil {
		return
	}

	var derr *Error
	if !errors.As(err, &derr) {
		derr = Internal("INTERNAL_SERVER_ERROR", "internal server error").WithCause(err)
	}

	log := LoggerFromContext(r.Context())
	logProblem(log, derr)

	title, detail := problemTitleDetail(derr)
	retryable, retryAfterSeconds, causes, properties := promoteProblemExtensions(derr)

	pd := ProblemDetail{
		Type:              resolveProblemTypeURI(derr.TypeURI, derr.ErrorCode),
		Title:             &title,
		Status:            derr.Status,
		Detail:            &detail,
		ErrorCode:         derr.ErrorCode,
		Timestamp:         time.Now().UTC(),
		Retryable:         retryable,
		RetryAfterSeconds: retryAfterSeconds,
		Causes:            causes,
		Properties:        properties,
	}
	instance := derr.Instance
	if instance == "" {
		instance = r.URL.Path
	}
	pd.Instance = &instance
	if cid := CorrelationIDFromContext(r.Context()); cid != "" {
		pd.CorrelationID = &cid
	}

	w.Header().Set("Content-Type", ProblemContentType)
	w.WriteHeader(derr.Status)
	if encErr := json.NewEncoder(w).Encode(pd); encErr != nil {
		log.Error("write problem failed", "err", encErr)
	}
}

// logProblem emits the one log record every rendered problem produces: ERROR
// with the underlying cause for 5xx, INFO otherwise.
func logProblem(log *slog.Logger, derr *Error) {
	if derr.Status >= http.StatusInternalServerError {
		log.Error("request failed",
			"status", derr.Status,
			"error_code", derr.ErrorCode,
			"detail", derr.Detail,
			"err", derr.Cause,
		)
		return
	}
	log.Info("request rejected",
		"status", derr.Status,
		"error_code", derr.ErrorCode,
		"detail", derr.Detail,
	)
}

// problemTitleDetail resolves the always-rendered title/detail pair: title
// falls back to the HTTP status text, then to a literal "Error"; detail
// falls back to title.
func problemTitleDetail(derr *Error) (title, detail string) {
	title = derr.Title
	if title == "" {
		title = http.StatusText(derr.Status)
	}
	if title == "" {
		title = "Error"
	}
	detail = derr.Detail
	if detail == "" {
		detail = title
	}
	return title, detail
}

// promoteProblemExtensions resolves the known extension properties
// ("retryable", "retryAfterSeconds", "causes") into their rendered top-level
// forms and returns whatever remains for the "properties" object. A known
// key is stripped from "properties" when its correctly-typed value is
// consumed by promotion: a typed retryable always is; a typed causes always
// is (a typed-but-empty []Cause renders nothing top-level and carries no
// information either); a typed retryAfterSeconds is consumed only when the
// problem is retryable — on a non-retryable problem the hint stays under
// "properties" rather than silently vanishing. A mistyped value (e.g.
// WithProperty("retryable", "yes")) fails its type assertion, stays in
// properties as an arbitrary nested value, and is never promoted — so
// mistyped known keys are not silently dropped.
func promoteProblemExtensions(derr *Error) (retryable bool, retryAfterSeconds *int, causes []Cause, properties map[string]any) {
	retryableVal, retryableOK := derr.Properties[propRetryable].(bool)
	retryable = defaultRetryable(derr.ErrorCode)
	if retryableOK {
		retryable = retryableVal
	}

	retryAfterVal, retryAfterOK := derr.Properties[propRetryAfterSeconds].(int)
	if retryable {
		seconds := defaultRetryAfterSeconds
		if retryAfterOK {
			seconds = retryAfterVal
		}
		retryAfterSeconds = &seconds
	}

	causesVal, causesOK := derr.Properties[propCauses].([]Cause)
	if causesOK && len(causesVal) > 0 {
		causes = causesVal
	}

	consumed := map[string]bool{
		propRetryable:         retryableOK,
		propRetryAfterSeconds: retryAfterOK && retryable,
		propCauses:            causesOK,
	}
	return retryable, retryAfterSeconds, causes, residualProperties(derr.Properties, consumed)
}

// residualProperties clones props minus the keys promotion consumed,
// returning nil when nothing remains so an empty "properties" object never
// renders.
func residualProperties(props map[string]any, consumed map[string]bool) map[string]any {
	if len(props) == 0 {
		return nil
	}
	clone := make(map[string]any, len(props))
	for k, v := range props {
		if consumed[k] {
			continue
		}
		clone[k] = v
	}
	if len(clone) == 0 {
		return nil
	}
	return clone
}
