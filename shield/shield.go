/*
Package shield .

Copyright © 2021 Walter Beller-Morales engineering@koala.io

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package shield

import (
	"errors"
	"fmt"
	"net"
	"sort"
)

// Shield .
type Shield struct {
	waf    wafInterface
	lookup lookupInterface
}

// NewShield creates a new client and loads the default AWS config
func NewShield(region string) *Shield {
	waf := newWAFClient(region)

	bpg := newLookupClient()
	return &Shield{
		waf:    waf,
		lookup: bpg,
	}
}

// CreateBlockList will lookup all the IPv4 prefixes registered to a specific ASN and create a WAF classic IP set
func (s *Shield) CreateBlockList(asn string) error {
	if isIP(asn) {
		return errors.New("Can only create block lists for ASNs — did you use an IP address?")
	}

	lookup, err := s.lookup.asnPrefixesLookup(asn)
	if err != nil {
		return err
	}

	ipset, err := s.waf.getOrCreateWAFClassicIPSet(ipsetName(asn))
	if err != nil {
		return err
	}

	var ips [][]string
	ips = append(ips, []string{})

	for _, prefix := range lookup.IPv4 {
		if s.waf.checkCidrSupportInWAFClassic(prefix.Cidr) {
			ips[len(ips)-1] = append(ips[len(ips)-1], prefix.Prefix)
		}

		if len(ips[len(ips)-1]) > s.waf.maxWAFClassicIPSetBatchSize() {
			ips = append(ips, []string{})
		}
	}

	for _, set := range ips {
		err = s.waf.addIPsToWAFClassicIPSet(ipset.ID, set)
		if err != nil {
			return err
		}
	}

	return nil
}

// EnableBlockList will add a WAF classic IP set for a specific ASN (if it exists) to the SHIELD WAF Rule
func (s *Shield) EnableBlockList(asn string) error {
	ipsetID, err := s.waf.findWAFClassicIPSet(ipsetName(asn))
	if err != nil {
		return err
	}

	rule, err := s.waf.getOrCreateWAFClassicRule(ruleName())
	if err != nil {
		return err
	}

	err = s.waf.addIPSetToWAFClassicRule(rule.ID, ipsetID)
	if err != nil {
		return err
	}

	return nil
}

// DisableBlockList will remove a WAF classic IP set for a specific ASN (if it exists) from the SHIELD WAF Rule
func (s *Shield) DisableBlockList(asn string) error {
	ipset, err := s.waf.findWAFClassicIPSet(ipsetName(asn))
	if err != nil {
		return err
	}

	if ipset == "" {
		return fmt.Errorf("Could not find a WAF Classic IP Set for ASN %s", asn)
	}

	rule, err := s.waf.getOrCreateWAFClassicRule(ruleName())
	if err != nil {
		return err
	}

	err = s.waf.removeIPSetFromWAFClassicRule(rule.ID, ipset)
	if err != nil {
		return err
	}

	return nil

}

// ListIPSets returns all the WAF Classic IP Sets
func (s *Shield) ListIPSets() ([]WAFClassicIPSetResponse, error) {
	response, err := s.waf.listWAFClassicIPSets()

	if err != nil {
		return []WAFClassicIPSetResponse{}, err
	}

	return response, nil
}

// LookupResponse represents lookup information for IP addresses and AS Numbers
type LookupResponse struct {
	Type           string
	Record         string
	AsnName        string
	AsnNumber      int
	AsnDescription string
	AsnCountry     string
	AsnIPv4Count   int
}

// Lookup returns information about IP addresses and AS Numbers
func (s *Shield) Lookup(record string) (LookupResponse, error) {
	var final LookupResponse
	if isIP(record) {
		response, err := s.lookup.ipLookup(record)
		if err != nil {
			return LookupResponse{}, err
		}

		var prefix ipPrefixes
		// get the most specific ASN (highest CIDR)
		sort.SliceStable(response.Prefixes, func(i, j int) bool {
			return response.Prefixes[i].Cidr > response.Prefixes[j].Cidr
		})
		prefix = response.Prefixes[0]

		prefixes, err := s.lookup.asnPrefixesLookup(fmt.Sprint(prefix.Asn.Number))
		if err != nil {
			return LookupResponse{}, err
		}

		final = LookupResponse{"IP", response.IP, prefix.Asn.Name, prefix.Asn.Number, prefix.Asn.Description, prefix.Asn.CountryCode, len(prefixes.IPv4)}
	} else {
		response, err := s.lookup.asnLookup(record)
		if err != nil {
			return LookupResponse{}, err
		}
		prefixes, err := s.lookup.asnPrefixesLookup(record)
		if err != nil {
			return LookupResponse{}, err
		}

		final = LookupResponse{"ASN", record, response.Name, response.Number, response.Description, response.CountryCode, len(prefixes.IPv4)}
	}
	return final, nil
}

func isIP(host string) bool {
	return net.ParseIP(host) != nil
}

func ruleName() string {
	return "KOALA-SHIELD-BLOCK-LIST"
}

func ipsetName(asn string) string {
	return fmt.Sprintf("SHIELD-ASN%s-IPs", asn)
}
