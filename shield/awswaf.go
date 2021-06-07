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
	"regexp"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/waf"
	"github.com/aws/aws-sdk-go/service/wafregional"
	"github.com/aws/aws-sdk-go/service/wafregional/wafregionaliface"
)

type wafInterface interface {
	maxWAFClassicIPSetBatchSize() int
	listWAFClassicIPSets() ([]WAFClassicIPSetResponse, error)
	getWAFClassicIPSet(ipsetID string) (WAFClassicIPSetResponse, error)
	getOrCreateWAFClassicIPSet(name string) (WAFClassicIPSetResponse, error)
	findWAFClassicIPSet(name string) (string, error)
	checkCidrSupportInWAFClassic(cidr int) bool
	addIPsToWAFClassicIPSet(IPSetID string, IPs []string) error
	removeIPsFromWAFClassicIPSet(IPSetID string, IPs []string) error
	getOrCreateWAFClassicRule(name string) (WAFClassicRuleResponse, error)
	findWAFClassicRule(name string) (string, error)
	addIPSetToWAFClassicRule(RuleID string, IPSetID string) error
}

// awsWAFClient .
type awsWAFClient struct {
	waf wafregionaliface.WAFRegionalAPI
}

// newWAFClient creates a new client and loads the default AWS config
func newWAFClient(region string) *awsWAFClient {
	session := session.Must(session.NewSession(&aws.Config{
		Region: aws.String(region),
	}))
	return &awsWAFClient{
		waf: wafregional.New(session),
	}
}

// maxWAFClassicIPSetBatchSize returns max batch size of IP sets being inserted
func (c *awsWAFClient) maxWAFClassicIPSetBatchSize() int {
	return 900
}

// WAFClassicIPSetResponse represents a set of IP lists from AWS WAF Classic
type WAFClassicIPSetResponse struct {
	ID   string
	Name string
	IPs  []*waf.IPSetDescriptor
}

// listWAFClassicIPSets returns information about IP sets in WAF Classic
func (c *awsWAFClient) listWAFClassicIPSets() ([]WAFClassicIPSetResponse, error) {

	// // Using the session create the WAF Regional client
	limit := int64(10)
	response, err := c.waf.ListIPSets(&waf.ListIPSetsInput{
		Limit: &limit,
	})

	if err != nil {
		return []WAFClassicIPSetResponse{}, err
	}

	final := []WAFClassicIPSetResponse{}
	for _, set := range response.IPSets {
		resp, err := c.getWAFClassicIPSet(*set.IPSetId)

		if err != nil {
			return final, err
		}

		final = append(final, resp)
	}
	return final, nil
}

// getWAFClassicIPSet returns a WAF Classic IP Sets
func (c *awsWAFClient) getWAFClassicIPSet(ipsetID string) (WAFClassicIPSetResponse, error) {

	resp, err := c.waf.GetIPSet(&waf.GetIPSetInput{
		IPSetId: &ipsetID,
	})

	if err != nil {
		return WAFClassicIPSetResponse{}, err
	}

	return WAFClassicIPSetResponse{
		ID:   *resp.IPSet.IPSetId,
		Name: *resp.IPSet.Name,
		IPs:  resp.IPSet.IPSetDescriptors,
	}, nil
}

// getOrCreateWAFClassicIPSet creates an IP set in WAF Classic
func (c *awsWAFClient) getOrCreateWAFClassicIPSet(name string) (WAFClassicIPSetResponse, error) {
	id, err := c.findWAFClassicIPSet(name)

	if err != nil {
		return WAFClassicIPSetResponse{}, err
	}

	if id == "" {
		token, err := c.waf.GetChangeToken(&waf.GetChangeTokenInput{})

		if err != nil {
			return WAFClassicIPSetResponse{}, err
		}

		result, err := c.waf.CreateIPSet(&waf.CreateIPSetInput{
			ChangeToken: token.ChangeToken,
			Name:        &name,
		})

		if err != nil {
			return WAFClassicIPSetResponse{}, err
		}

		return WAFClassicIPSetResponse{
			ID:   *result.IPSet.IPSetId,
			Name: *result.IPSet.Name,
			IPs:  []*waf.IPSetDescriptor{},
		}, nil

	}

	return c.getWAFClassicIPSet(id)
}

// findWAFClassicIPSet searches for an WAF IP Set by name and returns the IP Set ID if it exists
func (c *awsWAFClient) findWAFClassicIPSet(name string) (string, error) {
	var IPSetID string
	var find func(name string, marker string) (string, error)
	find = func(name string, marker string) (string, error) {
		input := waf.ListIPSetsInput{
			Limit: aws.Int64(100),
		}

		if marker != "" {
			input.NextMarker = &marker
		}

		list, err := c.waf.ListIPSets(&input)

		if err != nil {
			return IPSetID, err
		}

		for _, ipset := range list.IPSets {
			if *ipset.Name == name {
				IPSetID = *ipset.IPSetId
				return IPSetID, nil
			}
		}

		if list.NextMarker != nil {
			return find(name, *list.NextMarker)
		}

		return IPSetID, nil
	}

	return find(name, "")
}

// addIPsToWAFClassicIPSet adds specified IP address in CIDR notation to IP Set
func (c *awsWAFClient) addIPsToWAFClassicIPSet(IPSetID string, IPs []string) error {
	return c.modifyIPsInIPSet(waf.ChangeActionInsert, IPSetID, IPs)
}

// removeIPsFromWAFClassicIPSet removes specified IP address in CIDR notation from an IP Set
func (c *awsWAFClient) removeIPsFromWAFClassicIPSet(IPSetID string, IPs []string) error {
	return c.modifyIPsInIPSet(waf.ChangeActionDelete, IPSetID, IPs)
}

func (c *awsWAFClient) modifyIPsInIPSet(action string, IPSetID string, IPs []string) error {
	token, err := c.waf.GetChangeToken(&waf.GetChangeTokenInput{})

	if err != nil {
		return err
	}

	updates := []*waf.IPSetUpdate{}

	ipv4 := "IPV4"

	for index := range IPs {
		updates = append(updates, &waf.IPSetUpdate{
			Action: &action,
			IPSetDescriptor: &waf.IPSetDescriptor{
				Type:  &ipv4,
				Value: &IPs[index],
			},
		})
	}

	_, err = c.waf.UpdateIPSet(&waf.UpdateIPSetInput{
		ChangeToken: token.ChangeToken,
		IPSetId:     &IPSetID,
		Updates:     updates,
	})

	return err
}

// WAFClassicRuleResponse represents a Rule in AWS WAF Classic
type WAFClassicRuleResponse struct {
	ID              string
	Name            string
	MetricName      string
	PredicatesCount int
}

// getOrCreateWAFClassicRule fetches or creates a WAF rule by name
func (c *awsWAFClient) getOrCreateWAFClassicRule(name string) (WAFClassicRuleResponse, error) {
	id, err := c.findWAFClassicRule(name)

	if err != nil {
		return WAFClassicRuleResponse{}, err
	}

	if id == "" {
		token, err := c.waf.GetChangeToken(&waf.GetChangeTokenInput{})

		if err != nil {
			return WAFClassicRuleResponse{}, err
		}

		metricName := strings.ToLower(regexp.MustCompile("[^a-zA-Z0-9]+").ReplaceAllString(name, ""))

		rule, err := c.waf.CreateRule(&waf.CreateRuleInput{
			ChangeToken: token.ChangeToken,
			Name:        &name,
			MetricName:  &metricName,
		})

		if err != nil {
			return WAFClassicRuleResponse{}, err
		}

		return WAFClassicRuleResponse{
			ID:              *rule.Rule.RuleId,
			Name:            *rule.Rule.Name,
			MetricName:      *rule.Rule.MetricName,
			PredicatesCount: len(rule.Rule.Predicates),
		}, nil
	}

	rule, err := c.waf.GetRule(&waf.GetRuleInput{
		RuleId: &id,
	})

	if err != nil {
		return WAFClassicRuleResponse{}, err
	}

	return WAFClassicRuleResponse{
		ID:              *rule.Rule.RuleId,
		Name:            *rule.Rule.Name,
		MetricName:      *rule.Rule.MetricName,
		PredicatesCount: len(rule.Rule.Predicates),
	}, nil
}

// findWAFClassicRule searches for a WAF Rule by name and returns the Rule ID if it exists
func (c *awsWAFClient) findWAFClassicRule(name string) (string, error) {
	var RuleID string
	var find func(name string, marker string) (string, error)
	find = func(name string, marker string) (string, error) {
		input := waf.ListRulesInput{
			Limit: aws.Int64(100),
		}

		if marker != "" {
			input.NextMarker = &marker
		}

		list, err := c.waf.ListRules(&input)

		if err != nil {
			return RuleID, err
		}

		for _, rule := range list.Rules {
			if *rule.Name == name {
				RuleID = *rule.RuleId
				return RuleID, nil
			}
		}

		if list.NextMarker != nil {
			return find(name, *list.NextMarker)
		}

		return RuleID, nil
	}

	return find(name, "")
}

func (c *awsWAFClient) checkCidrSupportInWAFClassic(cidr int) bool {
	return cidr == 8 || (cidr >= 16 && cidr <= 32)
}

// addIPSetToWAFClassicRule adds specified IPSet to Rule
func (c *awsWAFClient) addIPSetToWAFClassicRule(RuleID string, IPSetID string) error {
	return c.modifyWAFClassicRule(waf.ChangeActionInsert, RuleID, IPSetID)
}

func (c *awsWAFClient) modifyWAFClassicRule(action string, RuleID string, IPSetID string) error {
	token, err := c.waf.GetChangeToken(&waf.GetChangeTokenInput{})

	if err != nil {
		return err
	}

	updates := []*waf.RuleUpdate{}

	ipmatch := "IPMatch"
	negated := false

	updates = append(updates, &waf.RuleUpdate{
		Action: &action,
		Predicate: &waf.Predicate{
			Type:    &ipmatch,
			DataId:  &IPSetID,
			Negated: &negated,
		},
	})

	_, err = c.waf.UpdateRule(&waf.UpdateRuleInput{
		ChangeToken: token.ChangeToken,
		RuleId:      &RuleID,
		Updates:     updates,
	})

	return err
}
