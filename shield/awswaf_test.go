package shield

import (
	"testing"

	"github.com/aws/aws-sdk-go/service/waf"
	"github.com/aws/aws-sdk-go/service/wafregional/wafregionaliface"
)

// MOCKS
type mockedWafRegional struct {
	wafregionaliface.WAFRegionalAPI
}

func (m mockedWafRegional) GetChangeToken(in *waf.GetChangeTokenInput) (*waf.GetChangeTokenOutput, error) {
	token := "hope & change"
	return &waf.GetChangeTokenOutput{
		ChangeToken: &token,
	}, nil
}

func (m mockedWafRegional) ListIPSets(in *waf.ListIPSetsInput) (*waf.ListIPSetsOutput, error) {
	aID := "A"
	aName := "SHIELD-A-IPs"
	bID := "B"
	bName := "SHIELD-B-IPs"

	return &waf.ListIPSetsOutput{
		IPSets: []*waf.IPSetSummary{
			{IPSetId: &aID, Name: &aName},
			{IPSetId: &bID, Name: &bName},
		},
	}, nil
}

func (m mockedWafRegional) GetIPSet(in *waf.GetIPSetInput) (*waf.GetIPSetOutput, error) {
	aID := "A"
	aName := "SHIELD-A-IPs"
	bID := "B"
	bName := "SHIELD-B-IPs"

	ipv4 := "IPV4"
	aIP := "64.252.173.0/32"
	bIP1 := "52.21.188.49/32"
	bIP2 := "192.168.1.1/32"

	responses := map[string]waf.GetIPSetOutput{
		aID: {
			IPSet: &waf.IPSet{
				IPSetId: &aID,
				Name:    &aName,
				IPSetDescriptors: []*waf.IPSetDescriptor{
					{Type: &ipv4, Value: &aIP},
				},
			},
		},
		bID: {
			IPSet: &waf.IPSet{
				IPSetId: &bID,
				Name:    &bName,
				IPSetDescriptors: []*waf.IPSetDescriptor{
					{Type: &ipv4, Value: &bIP1},
					{Type: &ipv4, Value: &bIP2},
				},
			},
		},
	}
	final := responses[*in.IPSetId]
	return &final, nil
}

func (m mockedWafRegional) UpdateIPSet(in *waf.UpdateIPSetInput) (*waf.UpdateIPSetOutput, error) {
	token := "hope & change"
	return &waf.UpdateIPSetOutput{
		ChangeToken: &token,
	}, nil
}

func (m mockedWafRegional) CreateIPSet(in *waf.CreateIPSetInput) (*waf.CreateIPSetOutput, error) {
	token := "hope & change"
	cID := "C"
	cName := "SHIELD-C-IPs"

	return &waf.CreateIPSetOutput{
		IPSet: &waf.IPSet{
			IPSetId:          &cID,
			Name:             &cName,
			IPSetDescriptors: []*waf.IPSetDescriptor{},
		},
		ChangeToken: &token,
	}, nil
}

func (m mockedWafRegional) ListRules(in *waf.ListRulesInput) (*waf.ListRulesOutput, error) {
	aName := "KOALA-SHIELD-BLOCK-LIST"
	aRuleID := "A"
	bName := "WHITELIST"
	bRuleID := "B"

	return &waf.ListRulesOutput{
		Rules: []*waf.RuleSummary{
			{RuleId: &aRuleID, Name: &aName},
			{RuleId: &bRuleID, Name: &bName},
		},
	}, nil
}

func (m mockedWafRegional) GetRule(in *waf.GetRuleInput) (*waf.GetRuleOutput, error) {
	aName := "KOALA-SHIELD-BLOCK-LIST"
	aMetricName := "koalashieldblocklist"
	aRuleID := "A"
	bName := "WHITELIST"
	bMetricName := "whitelist"
	bRuleID := "B"

	ipmatch := "IPMatch"
	negated := false

	responses := map[string]waf.GetRuleOutput{
		aRuleID: {
			Rule: &waf.Rule{
				MetricName: &aMetricName,
				Name:       &aName,
				RuleId:     &aRuleID,
				Predicates: []*waf.Predicate{
					{Type: &ipmatch, Negated: &negated, DataId: &aRuleID},
				},
			},
		},
		bRuleID: {
			Rule: &waf.Rule{
				MetricName: &bMetricName,
				Name:       &bName,
				RuleId:     &bRuleID,
				Predicates: []*waf.Predicate{
					{Type: &ipmatch, Negated: &negated, DataId: &aRuleID},
					{Type: &ipmatch, Negated: &negated, DataId: &bRuleID},
				},
			},
		},
	}
	final := responses[*in.RuleId]
	return &final, nil
}

func (m mockedWafRegional) CreateRule(in *waf.CreateRuleInput) (*waf.CreateRuleOutput, error) {
	token := "hope & change"
	cID := "C"
	cName := "C-RULE"
	cMetricName := "crule"

	return &waf.CreateRuleOutput{
		Rule: &waf.Rule{
			RuleId:     &cID,
			Name:       &cName,
			MetricName: &cMetricName,
		},
		ChangeToken: &token,
	}, nil
}

func (m mockedWafRegional) UpdateRule(in *waf.UpdateRuleInput) (*waf.UpdateRuleOutput, error) {
	token := "hope & change"
	return &waf.UpdateRuleOutput{
		ChangeToken: &token,
	}, nil
}

// TESTS
func TestListWAFClassicIPSets(t *testing.T) {
	awsWAFClient := &awsWAFClient{
		waf: mockedWafRegional{},
	}

	resp, err := awsWAFClient.listWAFClassicIPSets()
	if err != nil {
		t.Errorf("listWAFClassicIPSets failed, got: %e", err)
	}

	if len(resp) != 2 {
		t.Errorf("listWAFClassicIPSets returned too few results, got: %d, want: %d.", len(resp), 2)
	}

	setA := resp[0]
	setB := resp[1]

	if !(setA.ID == "A" && setA.Name == "SHIELD-A-IPs" && setA.IPsCount == 1) {
		t.Errorf("listWAFClassicIPSets returned the wrong data for IP Set A, got: %#v\n", setA)
	}
	if !(setB.ID == "B" && setB.Name == "SHIELD-B-IPs" && setB.IPsCount == 2) {
		t.Errorf("listWAFClassicIPSets returned the wrong data for IP Set B, got: %#v\n", setB)
	}
}

func TestFindWAFClassicIPSet(t *testing.T) {
	awsWAFClient := &awsWAFClient{
		waf: mockedWafRegional{},
	}

	resp, err := awsWAFClient.findWAFClassicIPSet("SHIELD-A-IPs")
	if err != nil {
		t.Errorf("findWAFClassicIPSet failed, got: %e", err)
	}

	if resp != "A" {
		t.Errorf("findWAFClassicIPSet returned wrong result, got: %s, want: %s.", resp, "A")
	}
}

func TestCheckCidrSupport(t *testing.T) {
	awsWAFClient := &awsWAFClient{
		waf: mockedWafRegional{},
	}

	for cidr := 0; cidr < 8; cidr++ {
		if awsWAFClient.checkCidrSupportInWAFClassic(cidr) {
			t.Errorf("checkCidrSupportInWAFClassic should not support cidr: %d", cidr)
		}
	}

	if !awsWAFClient.checkCidrSupportInWAFClassic(8) {
		t.Errorf("checkCidrSupportInWAFClassic should support cidr: %d", 8)
	}

	for cidr := 9; cidr < 16; cidr++ {
		if awsWAFClient.checkCidrSupportInWAFClassic(cidr) {
			t.Errorf("checkCidrSupportInWAFClassic should not support cidr: %d", cidr)
		}
	}

	for cidr := 16; cidr < 33; cidr++ {
		if !awsWAFClient.checkCidrSupportInWAFClassic(cidr) {
			t.Errorf("checkCidrSupportInWAFClassic should support cidr: %d", cidr)
		}
	}
}

func TestAddIPsToWAFClassicIPSet(t *testing.T) {
	awsWAFClient := &awsWAFClient{
		waf: mockedWafRegional{},
	}

	err := awsWAFClient.addIPsToWAFClassicIPSet("A", []string{"52.21.188.49/32", "192.168.1.1/32"})

	if err != nil {
		t.Errorf("addIPsToWAFClassicIPSet failed, got: %e", err)
	}
}

func TestGetOrCreateWAFClassicIPSet(t *testing.T) {
	awsWAFClient := &awsWAFClient{
		waf: mockedWafRegional{},
	}

	resp, err := awsWAFClient.getOrCreateWAFClassicIPSet("SHIELD-A-IPs")

	if err != nil {
		t.Errorf("getOrCreateWAFClassicIPSet failed, got: %e", err)
	}

	if !(resp.ID == "A" && resp.Name == "SHIELD-A-IPs" && resp.IPsCount == 1) {
		t.Errorf("getOrCreateWAFClassicIPSet returned the wrong data for IP Set A, got: %#v\n", resp)
	}

	resp, err = awsWAFClient.getOrCreateWAFClassicIPSet("SHIELD-C-IPs")

	if err != nil {
		t.Errorf("getOrCreateWAFClassicIPSet failed, got: %e", err)
	}

	if !(resp.ID == "C" && resp.Name == "SHIELD-C-IPs" && resp.IPsCount == 0) {
		t.Errorf("getOrCreateWAFClassicIPSet returned the wrong data for IP Set C")
	}
}

func TestFindWAFClassicRule(t *testing.T) {
	awsWAFClient := &awsWAFClient{
		waf: mockedWafRegional{},
	}

	resp, err := awsWAFClient.findWAFClassicRule("KOALA-SHIELD-BLOCK-LIST")
	if err != nil {
		t.Errorf("findWAFClassicRule failed, got: %e", err)
	}

	if resp != "A" {
		t.Errorf("findWAFClassicRule returned wrong result, got: %s, want: %s.", resp, "A")
	}
}

func TestGetOrCreateWAFClassicRule(t *testing.T) {
	awsWAFClient := &awsWAFClient{
		waf: mockedWafRegional{},
	}

	resp, err := awsWAFClient.getOrCreateWAFClassicRule("KOALA-SHIELD-BLOCK-LIST")

	if err != nil {
		t.Errorf("getOrCreateWAFClassicRule failed, got: %e", err)
	}

	if !(resp.ID == "A" && resp.Name == "KOALA-SHIELD-BLOCK-LIST" && resp.PredicatesCount == 1) {
		t.Errorf("getOrCreateWAFClassicRule returned the wrong data for Rule C, got: %#v\n", resp)
	}

	resp, err = awsWAFClient.getOrCreateWAFClassicRule("C-RULE")

	if err != nil {
		t.Errorf("getOrCreateWAFClassicRule failed, got: %e", err)
	}

	if !(resp.ID == "C" && resp.Name == "C-RULE" && resp.PredicatesCount == 0) {
		t.Errorf("getOrCreateWAFClassicRule returned the wrong data for Rule C")
	}
}

func TestAddIPSetToWAFClassicRule(t *testing.T) {
	awsWAFClient := &awsWAFClient{
		waf: mockedWafRegional{},
	}

	err := awsWAFClient.addIPSetToWAFClassicRule("A", "A")
	if err != nil {
		t.Errorf("addIPSetToWAFClassicRule failed, got: %e", err)
	}
}

func TestRemoveIPSetFromWAFClassicRule(t *testing.T) {
	awsWAFClient := &awsWAFClient{
		waf: mockedWafRegional{},
	}

	err := awsWAFClient.removeIPSetFromWAFClassicRule("A", "A")
	if err != nil {
		t.Errorf("removeIPSetFromWAFClassicRule failed, got: %e", err)
	}
}

func TestMaxWAFClassicIPSetBatchSize(t *testing.T) {
	awsWAFClient := &awsWAFClient{
		waf: mockedWafRegional{},
	}

	max := awsWAFClient.maxWAFClassicIPSetBatchSize()
	if max != 900 {
		t.Errorf("maxWAFClassicIPSetBatchSize is wrong, got: %d, want: %d.", max, 900)
	}
}
