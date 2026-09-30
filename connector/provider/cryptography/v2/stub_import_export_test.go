package cryptography_test

import (
	"context"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/cryptography/v2"
)

// stubKeyImport implements cryptography.KeyImportProvider. Every method
// returns the configured response/error pair for its own operation and keeps
// the request it was called with.
type stubKeyImport struct {
	keyTypes    []mdl.ImportableKeyTypeV2Dto
	keyTypesErr error

	importResp     *mdl.KeyCreationResponse
	importAccepted bool
	importErr      error
	imported       *mdl.ImportKeyRequestV2Dto

	result    *mdl.KeyCreationStatusResponse
	resultErr error
}

func (s *stubKeyImport) ImportableKeyTypes(ctx context.Context, req *mdl.TokenProfileScopedRequestV2Dto) ([]mdl.ImportableKeyTypeV2Dto, error) {
	return s.keyTypes, s.keyTypesErr
}

func (s *stubKeyImport) ImportKey(ctx context.Context, req *mdl.ImportKeyRequestV2Dto) (*mdl.KeyCreationResponse, bool, error) {
	s.imported = req
	return s.importResp, s.importAccepted, s.importErr
}

func (s *stubKeyImport) ImportKeyResult(ctx context.Context, req *mdl.ImportKeyResultRequestV2Dto) (*mdl.KeyCreationStatusResponse, error) {
	return s.result, s.resultErr
}

// stubAsyncKeyImport implements cryptography.AsyncKeyImportProvider.
type stubAsyncKeyImport struct {
	status    *mdl.KeyCreationStatusResponse
	statusErr error

	cancelErr error
}

func (s *stubAsyncKeyImport) ImportKeyStatus(ctx context.Context, req *mdl.OperationTrackingRequestV2Dto) (*mdl.KeyCreationStatusResponse, error) {
	return s.status, s.statusErr
}

func (s *stubAsyncKeyImport) CancelImportKey(ctx context.Context, req *mdl.OperationTrackingRequestV2Dto) error {
	return s.cancelErr
}

// stubKeyExport implements cryptography.KeyExportProvider.
type stubKeyExport struct {
	keyTypes    []mdl.ExportableKeyTypeV2Dto
	keyTypesErr error

	export    *mdl.ExportKeyResponseV2Dto
	exportErr error
	exported  *mdl.ExportKeyRequestV2Dto
}

func (s *stubKeyExport) ExportableKeyTypes(ctx context.Context, req *mdl.TokenProfileScopedRequestV2Dto) ([]mdl.ExportableKeyTypeV2Dto, error) {
	return s.keyTypes, s.keyTypesErr
}

func (s *stubKeyExport) ExportKey(ctx context.Context, req *mdl.ExportKeyRequestV2Dto) (*mdl.ExportKeyResponseV2Dto, error) {
	s.exported = req
	return s.export, s.exportErr
}

// stubTransferAttributes implements cryptography.ImportKeyAttributeProvider
// and cryptography.ExportKeyAttributeProvider.
type stubTransferAttributes struct {
	importAttrs []mdl.BaseAttributeDto
	exportAttrs []mdl.BaseAttributeDto
	err         error
}

func (s *stubTransferAttributes) ImportKeyAttributes(ctx context.Context, req *mdl.ImportKeyAttributesRequestV2Dto) ([]mdl.BaseAttributeDto, error) {
	return s.importAttrs, s.err
}

func (s *stubTransferAttributes) ExportKeyAttributes(ctx context.Context, req *mdl.KeyScopedRequestV2Dto) ([]mdl.BaseAttributeDto, error) {
	return s.exportAttrs, s.err
}
