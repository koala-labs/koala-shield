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
	listWAFClassicIPSets() ([]WAFClassicIPSetResponse, error)
	getOrCreateWAFClassicIPSet(name string) (WAFClassicIPSetResponse, error)
	findWAFClassicIPSet(name string) (string, error)
	checkCidrSupportInWAFClassic(cidr int) bool
	addIPsToWAFClassicIPSet(IPSetID string, IPs []string) error
	getOrCreateWAFClassicRule(name string) (WAFClassicRuleResponse, error)
	findWAFClassicRule(name string) (string, error)
	addIPSetToWAFClassicRule(RuleID string, IPSetID string) error
	removeIPSetFromWAFClassicRule(RuleID string, IPSetID string) error
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

// WAFClassicIPSetResponse represents a set of IP lists from AWS WAF Classic
type WAFClassicIPSetResponse struct {
	ID       string
	Name     string
	IPsCount int
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
		resp, err := c.waf.GetIPSet(&waf.GetIPSetInput{
			IPSetId: set.IPSetId,
		})

		if err != nil {
			return final, err
		}

		final = append(final, WAFClassicIPSetResponse{
			ID:       *set.IPSetId,
			Name:     *set.Name,
			IPsCount: len(resp.IPSet.IPSetDescriptors),
		})
	}
	return final, nil
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
			ID:       *result.IPSet.IPSetId,
			Name:     *result.IPSet.Name,
			IPsCount: 0,
		}, nil

	}
	result, err := c.waf.GetIPSet(&waf.GetIPSetInput{
		IPSetId: &id,
	})

	if err != nil {
		return WAFClassicIPSetResponse{}, err
	}

	return WAFClassicIPSetResponse{
		ID:       *result.IPSet.IPSetId,
		Name:     *result.IPSet.Name,
		IPsCount: len(result.IPSet.IPSetDescriptors),
	}, nil
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
	token, err := c.waf.GetChangeToken(&waf.GetChangeTokenInput{})

	if err != nil {
		return err
	}

	updates := []*waf.IPSetUpdate{}

	action := "INSERT"
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
	return c.modifyWAFClassicRule("INSERT", RuleID, IPSetID)
}

// removeIPSetFromWAFClassicRule adds specified IPSet to Rule
func (c *awsWAFClient) removeIPSetFromWAFClassicRule(RuleID string, IPSetID string) error {
	return c.modifyWAFClassicRule("DELETE", RuleID, IPSetID)
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
