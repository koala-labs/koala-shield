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
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type lookupInterface interface {
	ipLookup(ip string) (*ipLookupResponse, error)
	asnLookup(asn string) (*asnLookupResponse, error)
	asnPrefixesLookup(asn string) (*asnPrefixesLookupResponse, error)
}

// lookupClient .
type lookupClient struct {
	baseURL         string
	backoffSchedule []time.Duration
	HTTPClient      *http.Client
}

// backoffSchedule dictates how often and when to retry failed HTTP requests.
// After the last attempt the retries stop and the request is accepted as failed.
var defaultBackoffSchedule = []time.Duration{
	1 * time.Second,
	3 * time.Second,
	5 * time.Second,
	10 * time.Second,
}

// newLookupClient creates new bgpview.io BPGViewClient to lookup IP and ASN information
func newLookupClient() *lookupClient {
	return &lookupClient{
		HTTPClient: &http.Client{
			Timeout: 5 * time.Minute,
		},
		backoffSchedule: defaultBackoffSchedule,
		baseURL:         "https://api.bgpview.io",
	}
}

type response struct {
	Code    string      `json:"status"`
	Message string      `json:"status_message"`
	Data    interface{} `json:"data"`
}

func (c *lookupClient) send(req *http.Request, data interface{}) error {
	req.Header.Set("Accept", "application/json; charset=utf-8")

	execute := func(req *http.Request) (*http.Response, error) {
		res, err := c.HTTPClient.Do(req)
		if err != nil {
			return res, err
		}

		// Only 200 status codes are considered successful
		if res.StatusCode != http.StatusOK {
			return res, fmt.Errorf("unknown error, status code: %d", res.StatusCode)
		}

		return res, nil
	}

	var err error
	var res *http.Response
	for _, backoff := range c.backoffSchedule {
		res, err = execute(req)
		if err == nil {
			break
		}
		time.Sleep(backoff)
	}

	if err != nil {
		return err
	}

	defer res.Body.Close()

	// Unmarshall and populate data
	finalRes := response{
		Data: data,
	}
	if err = json.NewDecoder(res.Body).Decode(&finalRes); err != nil {
		return err
	}

	// Check response code
	if finalRes.Code != "ok" {
		return fmt.Errorf("API error, message: %s", finalRes.Message)
	}

	return nil
}

// ipLookupResponse represents an BGPview IP lookup
type ipLookupResponse struct {
	IP       string       `json:"ip"`
	Prefixes []ipPrefixes `json:"prefixes"`
}

// ipPrefixes represents BGPview IP prefixes
type ipPrefixes struct {
	Prefix string `json:"prefix"`
	IP     string `json:"ip"`
	Cidr   int8   `json:"cidr"`
	Asn    struct {
		Number      int    `json:"asn"`
		Name        string `json:"name"`
		Description string `json:"description"`
		CountryCode string `json:"country_code"`
	} `json:"asn"`
}

// ipLookup returns information about a particular IP from BGPview
func (c *lookupClient) ipLookup(ip string) (*ipLookupResponse, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/ip/%s", c.baseURL, ip), nil)
	if err != nil {
		return nil, err
	}

	res := ipLookupResponse{}
	if err := c.send(req, &res); err != nil {
		return nil, err
	}

	return &res, nil
}

// asnLookupResponse represents an BGPview ASN lookup
type asnLookupResponse struct {
	Number      int    `json:"asn"`
	Name        string `json:"name"`
	Description string `json:"description_short"`
	CountryCode string `json:"country_code"`
	Website     string `json:"website"`
}

// asnLookup returns information about a particular ASN from BGPview
func (c *lookupClient) asnLookup(asn string) (*asnLookupResponse, error) {

	req, err := http.NewRequest("GET", fmt.Sprintf("%s/asn/%s", c.baseURL, asn), nil)
	if err != nil {
		return nil, err
	}

	res := asnLookupResponse{}
	if err := c.send(req, &res); err != nil {
		return nil, err
	}

	return &res, nil
}

// asnPrefixesLookupResponse represents the IP prefixes owned by an ASN according to BGPview
type asnPrefixesLookupResponse struct {
	IPv4 []struct {
		Prefix      string `json:"prefix"`
		IP          string `json:"ip"`
		Cidr        int    `json:"cidr"`
		Description string `json:"description"`
		CountryCode string `json:"country_code"`
	} `json:"ipv4_prefixes"`
}

// asnPrefixesLookup returns the IP prefixes owned by an ASN according to BGPview
func (c *lookupClient) asnPrefixesLookup(asn string) (*asnPrefixesLookupResponse, error) {

	req, err := http.NewRequest("GET", fmt.Sprintf("%s/asn/%s/prefixes", c.baseURL, asn), nil)
	if err != nil {
		return nil, err
	}

	res := asnPrefixesLookupResponse{}
	if err := c.send(req, &res); err != nil {
		return nil, err
	}

	return &res, nil
}
