package network

import "testing"

func TestSelectReachableAddressUsesMDNSWhenReachable(t *testing.T) {
	t.Parallel()

	selection, err := SelectReachableAddress("homepki.local", true, "192.168.1.10")
	if err != nil {
		t.Fatalf("select reachable address: %v", err)
	}

	if selection.SelectedAddress != "homepki.local" {
		t.Fatalf("unexpected selected address: %s", selection.SelectedAddress)
	}
	if selection.Reason != "mdns_reachable" {
		t.Fatalf("unexpected reason: %s", selection.Reason)
	}
}

func TestSelectReachableAddressFallsBackWhenMDNSUnavailable(t *testing.T) {
	t.Parallel()

	selection, err := SelectReachableAddress("homepki.local", false, "192.168.1.10")
	if err != nil {
		t.Fatalf("select reachable address: %v", err)
	}

	if selection.SelectedAddress != "192.168.1.10" {
		t.Fatalf("unexpected selected address: %s", selection.SelectedAddress)
	}
	if selection.Reason != "mdns_unreachable" {
		t.Fatalf("unexpected reason: %s", selection.Reason)
	}
}
