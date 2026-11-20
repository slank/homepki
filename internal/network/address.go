package network

import (
	"errors"
	"strings"
)

type AddressSelection struct {
	MDNSHost        string
	MDNSReachable   bool
	SelectedAddress string
	FallbackAddress string
	Reason          string
}

func SelectReachableAddress(mdnsHost string, mdnsReachable bool, fallbackAddress string) (AddressSelection, error) {
	fallbackAddress = strings.TrimSpace(fallbackAddress)
	if fallbackAddress == "" {
		return AddressSelection{}, errors.New("fallback address is required")
	}

	selection := AddressSelection{
		MDNSHost:        strings.TrimSpace(mdnsHost),
		MDNSReachable:   mdnsReachable,
		FallbackAddress: fallbackAddress,
	}

	if selection.MDNSHost != "" && selection.MDNSReachable {
		selection.SelectedAddress = selection.MDNSHost
		selection.Reason = "mdns_reachable"
		return selection, nil
	}

	selection.SelectedAddress = fallbackAddress
	if selection.MDNSHost == "" {
		selection.Reason = "mdns_unconfigured"
	} else {
		selection.Reason = "mdns_unreachable"
	}

	return selection, nil
}
