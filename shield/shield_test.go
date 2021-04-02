package shield

import (
	"fmt"
	"strconv"
	"testing"
)

// MOCKS
type mockWAFClient struct{}

func (c *mockWAFClient) listWAFClassicIPSets() ([]WAFClassicIPSetResponse, error) {
	return []WAFClassicIPSetResponse{
		{ID: "1", Name: "one", IPsCount: 6},
		{ID: "2", Name: "two", IPsCount: 12},
	}, nil
}
func (c *mockWAFClient) getOrCreateWAFClassicIPSet(name string) (WAFClassicIPSetResponse, error) {
	return WAFClassicIPSetResponse{}, nil
}
func (c *mockWAFClient) findWAFClassicIPSet(name string) (string, error) {
	if name == "SHIELD-ASN20473-IPs" {
		return fmt.Sprintf("WAFClassicIPSetID-%s", name), nil
	} else if name == "SHIELD-ASN55555-IPs" {
		return "", nil
	} else {
		return "", fmt.Errorf("findWAFClassicIPSet failed")
	}
}
func (c *mockWAFClient) checkCidrSupportInWAFClassic(cidr int) bool {
	return true
}
func (c *mockWAFClient) addIPsToWAFClassicIPSet(IPSetID string, IPs []string) error {
	return nil
}
func (c *mockWAFClient) getOrCreateWAFClassicRule(name string) (WAFClassicRuleResponse, error) {
	return WAFClassicRuleResponse{}, nil
}
func (c *mockWAFClient) findWAFClassicRule(name string) (string, error) {
	return fmt.Sprintf("WAFClassicRuleID-%s", name), nil
}
func (c *mockWAFClient) addIPSetToWAFClassicRule(RuleID string, IPSetID string) error {
	return nil
}
func (c *mockWAFClient) removeIPSetFromWAFClassicRule(RuleID string, IPSetID string) error {
	return nil
}

type mockLookupClient struct{}

func (c *mockLookupClient) ipLookup(ip string) (*ipLookupResponse, error) {
	var response ipLookupResponse

	response.IP = ip

	prefixOne := ipPrefixes{Prefix: fmt.Sprintf("%s/9", ip), IP: ip, Cidr: 9}
	prefixOne.Asn.Number = 1
	prefixOne.Asn.Name = "AS-1"
	prefixOne.Asn.Description = "Safe LLC"
	prefixOne.Asn.CountryCode = "US"

	prefixTwo := ipPrefixes{Prefix: fmt.Sprintf("%s/24", ip), IP: ip, Cidr: 24}
	prefixTwo.Asn.Number = 4
	prefixTwo.Asn.Name = "AS-4"
	prefixTwo.Asn.Description = "Sketchy, LLC"
	prefixTwo.Asn.CountryCode = "US"

	response.Prefixes = []ipPrefixes{prefixOne, prefixTwo}

	return &response, nil
}
func (c *mockLookupClient) asnLookup(asn string) (*asnLookupResponse, error) {
	var response asnLookupResponse

	number, err := strconv.Atoi(asn)
	if err != nil {
		return &response, err
	}
	response.Number = number
	response.Name = fmt.Sprintf("AS-%s", asn)
	response.Description = "Sketchy, LLC"
	response.CountryCode = "US"

	return &response, nil
}
func (c *mockLookupClient) asnPrefixesLookup(asn string) (*asnPrefixesLookupResponse, error) {
	var response asnPrefixesLookupResponse

	response.IPv4 = []struct {
		Prefix      string `json:"prefix"`
		IP          string `json:"ip"`
		Cidr        int    `json:"cidr"`
		Description string `json:"description"`
		CountryCode string `json:"country_code"`
	}{
		{"192.167.1.1/8", "192.167.1.1", 8, "Home", "US"},
		{"192.167.1.1/24", "192.167.1.1", 24, "Casa", "MX"},
	}
	return &response, nil
}

func TestNewShield(t *testing.T) {
	shield := NewShield("us-east-1")

	if shield.waf == nil {
		t.Errorf("TestNewShield did not initialize waf attribute correctly")
	}

	if shield.lookup == nil {
		t.Errorf("TestNewShield did not initialize lookup attribute correctly")
	}
}

func TestLookup(t *testing.T) {
	mockShield := &Shield{waf: &mockWAFClient{}, lookup: &mockLookupClient{}}

	asn := "20473"

	asnResponse, _ := mockShield.Lookup(asn)
	if asnResponse.Type != "ASN" {
		t.Errorf("TestLookup for ASN type was incorrect, got: %s, want: %s.", asnResponse.Type, "ASN")
	}
	if asnResponse.AsnNumber != 20473 {
		t.Errorf("TestLookup for ASN number was incorrect, got: %d, want: %d.", asnResponse.AsnNumber, 20473)
	}
	if asnResponse.AsnName != "AS-20473" {
		t.Errorf("TestLookup for ASN name was incorrect, got: %s, want: %s.", asnResponse.AsnName, "AS-20473")
	}
	if asnResponse.AsnCountry != "US" {
		t.Errorf("TestLookup for ASN country was incorrect, got: %s, want: %s.", asnResponse.AsnCountry, "US")
	}
	if asnResponse.AsnIPv4Count != 2 {
		t.Errorf("TestLookup for ASN IPv4 count was incorrect, got: %d, want: %d.", asnResponse.AsnIPv4Count, 2)
	}

	ip := "8.6.8.0"
	ipResponse, _ := mockShield.Lookup(ip)
	if ipResponse.Type != "IP" {
		t.Errorf("TestLookup for IP type was incorrect, got: %s, want: %s.", ipResponse.Type, "IP")
	}
	if ipResponse.AsnNumber != 4 {
		t.Errorf("TestLookup for IP ASN number was incorrect, got: %d, want: %d.", ipResponse.AsnNumber, 5)
	}
	if ipResponse.AsnName != "AS-4" {
		t.Errorf("TestLookup for IP ASN name was incorrect, got: %s, want: %s.", ipResponse.AsnName, "AS-4")
	}
	if ipResponse.AsnCountry != "US" {
		t.Errorf("TestLookup for IP ASN country was incorrect, got: %s, want: %s.", ipResponse.AsnCountry, "US")
	}
	if ipResponse.AsnIPv4Count != 2 {
		t.Errorf("TestLookup for IP ASN IPv4 count was incorrect, got: %d, want: %d.", ipResponse.AsnIPv4Count, 2)
	}
}

// TESTS
func TestListIPSets(t *testing.T) {
	mockShield := &Shield{waf: &mockWAFClient{}, lookup: &mockLookupClient{}}

	ipsets, _ := mockShield.ListIPSets()

	if len(ipsets) != 2 {
		t.Errorf("ListIPSets return count was incorrect, got: %d, want: %d.", len(ipsets), 2)
	}

	expected := []WAFClassicIPSetResponse{
		{ID: "1", Name: "one", IPsCount: 6},
		{ID: "2", Name: "two", IPsCount: 12},
	}

	for index, ipset := range ipsets {
		if ipset.ID != expected[index].ID {
			t.Errorf("ListIPSets return value was incorrect, got: %s, want: %s.", ipset.ID, expected[index].ID)
		}
	}
}

func TestDisableBlockList(t *testing.T) {
	mockShield := &Shield{
		waf:    &mockWAFClient{},
		lookup: &mockLookupClient{},
	}

	asn := "20473"

	err := mockShield.DisableBlockList(asn)
	if err != nil {
		t.Errorf("DisableBlockList failed, got: %e", err)
	}
}

func TestDisableBlockListIPSetNotFound(t *testing.T) {
	mockShield := &Shield{
		waf:    &mockWAFClient{},
		lookup: &mockLookupClient{},
	}

	asn := "55555"

	err := mockShield.DisableBlockList(asn)
	if err == nil {
		t.Errorf("DisableBlockList should fail when looking up an IPSet that does not exist")
	}
}

func TestDisableBlockListError(t *testing.T) {
	mockShield := &Shield{
		waf:    &mockWAFClient{},
		lookup: &mockLookupClient{},
	}

	asn := "11111"

	err := mockShield.DisableBlockList(asn)
	if err == nil {
		t.Errorf("DisableBlockList should fail when lookup fails")
	}
}

func TestCreateBlockList(t *testing.T) {
	mockShield := &Shield{
		waf:    &mockWAFClient{},
		lookup: &mockLookupClient{},
	}

	asn := "20473"

	err := mockShield.CreateBlockList(asn)
	if err != nil {
		t.Errorf("CreateBlockList failed, got: %e", err)
	}
}

func TestCreateBlockListDoesNotAcceptIPs(t *testing.T) {
	mockShield := &Shield{
		waf:    &mockWAFClient{},
		lookup: &mockLookupClient{},
	}

	ip := "192.168.1.1"

	err := mockShield.CreateBlockList(ip)
	if err == nil {
		t.Errorf("CreateBlockList should have returned an error when an IP address is used")
	}
}

func TestEnableBlockList(t *testing.T) {
	mockShield := &Shield{
		waf:    &mockWAFClient{},
		lookup: &mockLookupClient{},
	}

	asn := "20473"

	err := mockShield.EnableBlockList(asn)
	if err != nil {
		t.Errorf("EnableBlockList failed, got: %e", err)
	}
}

func TestEnableBlockListError(t *testing.T) {
	mockShield := &Shield{
		waf:    &mockWAFClient{},
		lookup: &mockLookupClient{},
	}

	asn := "11111"

	err := mockShield.EnableBlockList(asn)
	if err == nil {
		t.Errorf("EnableBlockList should fail when lookup fails")
	}
}
