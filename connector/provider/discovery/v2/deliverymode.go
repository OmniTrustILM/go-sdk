package discovery

import (
	"slices"
	"strings"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/discovery/v2"
	"github.com/OmniTrustILM/go-sdk/connector/shared"
)

const (
	// MaxCheckpointBytes is the largest serialized checkpoint the contract
	// allows, on a request or a response.
	MaxCheckpointBytes = 64 * 1024
	// CheckpointedResponseReserve is the room a checkpointed results response
	// keeps under MaxResultBytes for its checkpoint and its own fields. Core
	// asks for at most MaxResultBytes less this, and a provider that applies
	// its own bound leaves the same room.
	CheckpointedResponseReserve int64 = 128 * 1024
)

// OfferedDeliveryModes returns the delivery modes a request offers, in Core's
// order of preference. A request without deliveryModes comes from a Core that
// predates delivery modes and drives buffered delivery only; an empty list
// offers none. Codes this SDK does not know, and repeats, are skipped.
func OfferedDeliveryModes(offer []string) []mdl.DiscoveryDeliveryMode {
	if offer == nil {
		return []mdl.DiscoveryDeliveryMode{mdl.DISCOVERYDELIVERYMODE_BUFFERED}
	}
	modes := make([]mdl.DiscoveryDeliveryMode, 0, len(offer))
	for _, code := range offer {
		mode := mdl.DiscoveryDeliveryMode(code)
		if mode.IsValid() && !slices.Contains(modes, mode) {
			modes = append(modes, mode)
		}
	}
	return modes
}

// Offers reports whether a request's deliveryModes offers mode.
func Offers(offer []string, mode mdl.DiscoveryDeliveryMode) bool {
	return slices.Contains(OfferedDeliveryModes(offer), mode)
}

// ChooseDeliveryMode returns the first offered mode, in Core's order of
// preference, that the connector supports. When it supports none, the error
// is a 422 VALIDATION_FAILED whose detail names both lists; a connector that
// needs a newer platform can answer its own 422 saying so instead.
func ChooseDeliveryMode(offer []string, supported ...mdl.DiscoveryDeliveryMode) (mdl.DiscoveryDeliveryMode, error) {
	offered := OfferedDeliveryModes(offer)
	for _, mode := range offered {
		if slices.Contains(supported, mode) {
			return mode, nil
		}
	}
	return "", shared.Invalid("VALIDATION_FAILED", "none of the offered delivery modes [%s] is supported; this connector supports [%s]",
		joinModes(offered), joinModes(supported))
}

func joinModes(modes []mdl.DiscoveryDeliveryMode) string {
	codes := make([]string, len(modes))
	for i, mode := range modes {
		codes[i] = string(mode)
	}
	return strings.Join(codes, ", ")
}
