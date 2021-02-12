package shield

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestIpLookupSuccess(t *testing.T) {
	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{
			"status": "ok",
			"status_message": "Query was successful",
			"data": {
				"ip": "8.6.8.0",
				"ptr_record": null,
				"prefixes": [
				{
					"prefix": "8.6.8.0/24",
					"ip": "8.6.8.0",
					"cidr": 24,
					"asn": {
						"asn": 20473,
						"name": "AS-CHOOPA",
						"description": "Choopa, LLC",
						"country_code": "US"
					},
					"name": "LVLT-CHOOP-1-8-6-8",
					"description": "Choopa, LLC",
					"country_code": "US"
				},
				{
					"prefix": "8.0.0.0/12",
					"ip": "8.0.0.0",
					"cidr": 12,
					"asn": {
						"asn": 3356,
						"name": "LEVEL3",
						"description": "Level 3 Parent, LLC",
						"country_code": "US"
					},
					"name": "LVLT-ORG-8-8",
					"description": "Level 3 Parent, LLC",
					"country_code": "US"
				},
				{
					"prefix": "8.0.0.0/12",
					"ip": "8.0.0.0",
					"cidr": 12,
					"asn": {
						"asn": 3549,
						"name": "LVLT-3549",
						"description": "Level 3 Parent, LLC",
						"country_code": "US"
					},
					"name": "LVLT-ORG-8-8",
					"description": "Level 3 Parent, LLC",
					"country_code": "US"
				},
				{
					"prefix": "8.0.0.0/9",
					"ip": "8.0.0.0",
					"cidr": 9,
					"asn": {
						"asn": 3356,
						"name": "LEVEL3",
						"description": "Level 3 Parent, LLC",
						"country_code": "US"
					},
					"name": "LVLT-ORG-8-8",
					"description": "Level 3 Parent, LLC",
					"country_code": "US"
				},
				{
					"prefix": "8.0.0.0/9",
					"ip": "8.0.0.0",
					"cidr": 9,
					"asn": {
						"asn": 3549,
						"name": "LVLT-3549",
						"description": "Level 3 Parent, LLC",
						"country_code": "US"
					},
					"name": "LVLT-ORG-8-8",
					"description": "Level 3 Parent, LLC",
					"country_code": "US"
				}
				],
				"rir_allocation": {
					"rir_name": "ARIN",
					"country_code": "US",
					"ip": "8.0.0.0",
					"cidr": 9,
					"prefix": "8.0.0.0/9",
					"date_allocated": "1992-12-01 00:00:00",
					"allocation_status": "allocated"
				},
				"iana_assignment": {
					"assignment_status": "legacy",
					"description": "Administered by ARIN",
					"whois_server": "whois.arin.net",
					"date_assigned": null
				},
				"maxmind": {
				"country_code": null,
				"city": null
				}
			},
			"@meta": {
				"time_zone": "UTC",
				"api_version": 1,
				"execution_time": "321.42 ms"
			}
		}`))
	}))
	defer mock.Close()

	client := &lookupClient{
		HTTPClient: &http.Client{},
		baseURL:    mock.URL,
	}

	ipResponse, err := client.ipLookup("8.6.8.0")

	if err != nil {
		t.Errorf("ipLookup failed, got: %e", err)
	}

	if ipResponse.IP != "8.6.8.0" {
		t.Errorf("ipLookup for IP IP was incorrect, got: %s, want: %s.", ipResponse.IP, "8.6.8.0")
	}
	if len(ipResponse.Prefixes) != 5 {
		t.Errorf("ipLookup for IP Prefixes count was incorrect, got: %d, want: %d.", len(ipResponse.Prefixes), 5)
	}
	if ipResponse.Prefixes[0].Cidr != 24 {
		t.Errorf("ipLookup for IP Prefixes Cidr was incorrect, got: %d, want: %d.", ipResponse.Prefixes[0].Cidr, 24)
	}
	if ipResponse.Prefixes[0].Asn.Number != 20473 {
		t.Errorf("ipLookup for IP Prefixes Asn Number was incorrect, got: %d, want: %d.", ipResponse.Prefixes[0].Asn.Number, 20473)
	}
}

func TestIpLookupFailure(t *testing.T) {
	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{
			"status": "error",
			"status_message": "Malformed input",
			"@meta": {
				"time_zone": "UTC",
				"api_version": 1,
				"execution_time": "4.20 ms"
			}
		}`))
	}))
	defer mock.Close()

	client := &lookupClient{
		HTTPClient: &http.Client{},
		baseURL:    mock.URL,
	}

	_, err := client.ipLookup("not a real ip")

	if err == nil {
		t.Errorf("ipLookup should have returned an error")
	}
}

func TestAsnLookupSuccess(t *testing.T) {
	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{
			"status": "ok",
			"status_message": "Query was successful",
			"data": {
				"asn": 61138,
				"name": "ZAPPIE-HOST-AS",
				"description_short": "Zappie Host",
				"description_full": ["Zappie Host"],
				"country_code": "US",
				"website": "https://zappiehost.com/",
				"email_contacts": [
					"abuse@zappiehost.com",
					"admin@zappiehost.com",
					"noc@zappiehost.com"
				],
				"abuse_contacts": [
					"abuse@zappiehost.com"
				],
				"looking_glass": "https://lg-nz.zappiehost.com",
				"traffic_estimation": "5-10Gbps",
				"traffic_ratio": "Mostly Outbound",
				"owner_address": [
					"16192 Coastal HWY",
					"DE 19958",
					"Lewes",
					"UNITED STATES"
				],
				"rir_allocation": {
					"rir_name": "RIPE",
					"country_code": "US",
					"date_allocated": "2015-03-04 00:00:00",
					"allocation_status": "allocated"
				},
				"iana_assignment": {
					"assignment_status": "assigned",
					"description": "Assigned by RIPE NCC",
					"whois_server": "whois.ripe.net",
					"date_assigned": null
				},
				"date_updated": "2021-01-05 07:38:05"
			},
			"@meta": {
				"time_zone": "UTC",
				"api_version": 1,
				"execution_time": "156.88 ms"
			}
		}`))
	}))
	defer mock.Close()

	client := &lookupClient{
		HTTPClient: &http.Client{},
		baseURL:    mock.URL,
	}

	asnResponse, err := client.asnLookup("61138")

	if err != nil {
		t.Errorf("asnLookup failed, got: %e", err)
	}

	if asnResponse.Number != 61138 {
		t.Errorf("asnLookup for ASN Number was incorrect, got: %d, want: %d.", asnResponse.Number, 61138)
	}
	if asnResponse.Name != "ZAPPIE-HOST-AS" {
		t.Errorf("asnLookup for ASN Name was incorrect, got: %s, want: %s.", asnResponse.Name, "ZAPPIE-HOST-AS")
	}
	if asnResponse.Description != "Zappie Host" {
		t.Errorf("asnLookup for ASN Description was incorrect, got: %s, want: %s.", asnResponse.Description, "Zappie Host")
	}
	if asnResponse.CountryCode != "US" {
		t.Errorf("asnLookup for ASN CountryCode was incorrect, got: %s, want: %s.", asnResponse.CountryCode, "US")
	}
	if asnResponse.Website != "https://zappiehost.com/" {
		t.Errorf("asnLookup for ASN Website was incorrect, got: %s, want: %s.", asnResponse.CountryCode, "https://zappiehost.com/")
	}
}

func TestAsnLookupFailure(t *testing.T) {
	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{
			"status": "error",
			"status_message": "Malformed input",
			"@meta": {
				"time_zone": "UTC",
				"api_version": 1,
				"execution_time": "4.20 ms"
			}
		}`))
	}))
	defer mock.Close()

	client := &lookupClient{
		HTTPClient: &http.Client{},
		baseURL:    mock.URL,
	}

	_, err := client.asnLookup("not a real asn")

	if err == nil {
		t.Errorf("asnLookup should have returned an error")
	}
}

func TestAsnPrefixesLookupSuccess(t *testing.T) {
	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{
			"status": "ok",
			"status_message": "Query was successful",
			"data": {
				"ipv4_prefixes": [
					{
						"prefix": "103.208.86.0/24",
						"ip": "103.208.86.0",
						"cidr": 24,
						"roa_status": "None",
						"name": "ZAPPIE-HOST-NZ-3",
						"description": "Zappie Host - Auckland, New Zealand",
						"country_code": "NZ",
						"parent": {
						"prefix": "103.208.84.0/22",
						"ip": "103.208.84.0",
						"cidr": 22,
						"rir_name": "APNIC",
						"allocation_status": "unknown"
						}
					},
					{
						"prefix": "169.239.128.0/23",
						"ip": "169.239.128.0",
						"cidr": 23,
						"roa_status": "None",
						"name": "ZAPPIE-HOST-ZA-1",
						"description": "Zappie Host - Johannesburg, South Africa",
						"country_code": "ZA",
						"parent": {
						"prefix": "169.239.128.0/22",
						"ip": "169.239.128.0",
						"cidr": 22,
						"rir_name": "AfriNIC",
						"allocation_status": "unknown"
						}
					},
					{
						"prefix": "169.239.130.0/23",
						"ip": "169.239.130.0",
						"cidr": 23,
						"roa_status": "None",
						"name": "ZAPPIE-HOST-ZA-2",
						"description": "Zappie Host - Johannesburg, South Africa",
						"country_code": "ZA",
						"parent": {
						"prefix": "169.239.128.0/22",
						"ip": "169.239.128.0",
						"cidr": 22,
						"rir_name": "AfriNIC",
						"allocation_status": "unknown"
						}
					}
				],
				"ipv6_prefixes": [
					{
						"prefix": "2a06:1280::/32",
						"ip": "2a06:1280::",
						"cidr": 32,
						"roa_status": "None",
						"name": "ZAPPIE-HOST-NZ-v6",
						"description": "Zappie Host - Auckland, New Zealand v6",
						"country_code": "NZ",
						"parent": {
						"prefix": "2a06:1280::/29",
						"ip": "2a06:1280::",
						"cidr": 29,
						"rir_name": "RIPE",
						"allocation_status": "unknown"
						}
					},
					{
						"prefix": "2a06:1280:ae02::/48",
						"ip": "2a06:1280:ae02::",
						"cidr": 48,
						"roa_status": "None",
						"name": "ZAPPIE-HOST-NZ-v6",
						"description": "Zappie Host - Auckland, New Zealand v6",
						"country_code": "NZ",
						"parent": {
						"prefix": "2a06:1280::/29",
						"ip": "2a06:1280::",
						"cidr": 29,
						"rir_name": "RIPE",
						"allocation_status": "unknown"
						}
					}
				]
			},
			"@meta": {
				"time_zone": "UTC",
				"api_version": 1,
				"execution_time": "120.9 ms"
			}
		}`))
	}))
	defer mock.Close()

	client := &lookupClient{
		HTTPClient: &http.Client{},
		baseURL:    mock.URL,
	}

	asnPrefixesResponse, err := client.asnPrefixesLookup("61138")

	if err != nil {
		t.Errorf("asnPrefixesLookup failed, got: %e", err)
	}

	if len(asnPrefixesResponse.IPv4) != 3 {
		t.Errorf("asnPrefixesLookup for ASN IPv4 prefixes count was incorrect, got: %d, want: %d.", len(asnPrefixesResponse.IPv4), 3)
	}
	if asnPrefixesResponse.IPv4[0].Prefix != "103.208.86.0/24" {
		t.Errorf("asnPrefixesLookup for ASN IPv4 prefixes Prefix was incorrect, got: %s, want: %s.", asnPrefixesResponse.IPv4[0].Prefix, "103.208.86.0/24")
	}
}

func TestAsnPrefixesLookupFailure(t *testing.T) {
	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{
			"status": "error",
			"status_message": "Malformed input",
			"@meta": {
				"time_zone": "UTC",
				"api_version": 1,
				"execution_time": "4.20 ms"
			}
		}`))
	}))
	defer mock.Close()

	client := &lookupClient{
		HTTPClient: &http.Client{},
		baseURL:    mock.URL,
	}

	_, err := client.asnPrefixesLookup("not a real asn")

	if err == nil {
		t.Errorf("asnPrefixesLookup should have returned an error")
	}
}
