package syslog_ng_pattern_db

import (
	"encoding/xml"
	"fmt"
	"gitlab.in2p3.fr/cc-in2p3-system/sequence"
	"gitlab.in2p3.fr/cc-in2p3-system/sequence/models"
	"strconv"
)

//This represents a ruleset section in the sys-log ng yaml file
type xPatternDB struct {
	XMLName  xml.Name   `xml:"patterndb"`
	Version  string     `xml:"version,attr"`
	Pubdate  string     `xml:"pub_date,attr"`
	Rulesets []xRuleset `xml:"ruleset"`
}

//This represents a ruleset section in the sys-log ng yaml file
type xRuleset struct {
	ID       string    `xml:"id,attr"`
	Name     string    `xml:"name,attr"`
	Patterns xPatterns `xml:"patterns"`
	Rules    xRules    `xml:"rules"`
}

//this is needed for the xml to format properly
type xRules struct {
	Rules []xRule `xml:"rule"`
}

//This represents a rule section in the sys-log ng yaml file
type xRule struct {
	XMLName  xml.Name    `xml:"rule"`
	Class    string      `xml:"class,attr"`
	Patterns []xPattern  `xml:"patterns"`
	Examples xExamples   `xml:"examples"`
	Values   xRuleValues `xml:"values"`
	ID       string      `xml:"id,attr"`
}

//this is needed for the xml to format properly
type xPatterns struct {
	Patterns []string `xml:"pattern"`
}

type xPattern struct {
	Pattern string `xml:"pattern"`
}

//this is needed for the xml to format properly
type xExamples struct {
	Examples []xExample `xml:"example"`
}

type xExample struct {
	XMLName     xml.Name     `xml:"example"`
	TestMessage xTestMessage `xml:"test_message"`
	TestValues  xTestValues  `xml:"test_values"`
}

type xTestValues struct {
	Values []xTestValue `xml:"test_values"`
}

type xTestMessage struct {
	XMLName     xml.Name `xml:"test_message"`
	TestMessage string   `xml:",chardata"`
	Program     string   `xml:"program,attr"`
}

type xTestValue struct {
	XMLName xml.Name `xml:"test_value"`
	Value   string   `xml:",chardata"`
	Key     string   `xml:"name,attr"`
}

type xRuleValues struct {
	Values []xRuleValue `xml:"values"`
}

type xRuleValue struct {
	XMLName xml.Name `xml:"value"`
	Name    string   `xml:"name,attr"`
	Value   string   `xml:",chardata"`
}

//This method takes the path to the file output by the analyzer as in and
//converts it to Yaml and saves in the out path.
func convertToXml(document xPatternDB) string {
	// turn the document into XML format
	y, _ := xml.MarshalIndent(document, "  ", "   ")
	return string(y)
}

func addToRuleset(pattern sequence.AnalyzerResult, document xPatternDB) xPatternDB {
	//build the rule as XML
	rule := buildRuleXML(pattern)
	//get the ruleset name for the example
	//it will be the service value
	rs := pattern.Service.Name
	rsID := pattern.Service.ID
	found := false
	//look in the ruleset if it exists already
	for i, rls := range document.Rulesets {
		if rls.Name == rs {
			// found, so add the new rule
			rls.Rules.Rules = append(rls.Rules.Rules, rule)
			//remove the old ruleset
			document.Rulesets = append(document.Rulesets[:i], document.Rulesets[i+1:]...)
			//re-add the updated ruleset
			document.Rulesets = append(document.Rulesets, rls)
			found = true
			break
		}
	}
	//if not found make a new ruleset
	if !found {
		//create the ruleset
		rs := buildRulesetXML(rsID, rs, pattern.Service)
		//add the rule
		rs.Rules.Rules = append(rs.Rules.Rules, rule)
		//add the ruleset
		document.Rulesets = append(document.Rulesets, rs)
	}
	return document
}

func buildRuleXML(result sequence.AnalyzerResult) xRule {
	rule := xRule{}
	count := xRuleValue{Name: "seq-matches", Value: strconv.Itoa(result.ExampleCount)}
	rule.Values.Values = append(rule.Values.Values, count)
	dc := xRuleValue{Name: "seq-created", Value: result.DateCreated.Format("2006-01-02")}
	rule.Values.Values = append(rule.Values.Values, dc)
	dlm := xRuleValue{Name: "seq-last-match", Value: result.DateLastMatched.Format("2006-01-02")}
	rule.Values.Values = append(rule.Values.Values, dlm)
	dcs := xRuleValue{Name: "seq-complexity", Value: fmt.Sprintf("%.2f", result.ComplexityScore)}
	rule.Values.Values = append(rule.Values.Values, dcs)
	var p xPattern
	var e xExample
	var t xTestMessage
	for _, ex := range result.Examples {
		e = xExample{}
		t.TestMessage = ex.Message
		t.Program = ex.Service
		e.TestMessage = t
		m, err := extractTestValuesForTokens(ex.Message, result)
		if err != nil {
			logger.HandleError(fmt.Sprintf("Unable to make test_values map for examples for pattern %s", result.PatternId))
		} else {
			for key, val := range m {
				e.TestValues.Values = append(e.TestValues.Values, xTestValue{Key: key, Value: val["name"]})
			}
		}
		rule.Examples.Examples = append(rule.Examples.Examples, e)
	}
	p.Pattern = replaceTags(result.Pattern)
	rule.Patterns = append(rule.Patterns, p)

	//create a new UUID
	rule.ID = result.PatternId
	rule.Class = "sequence"
	return rule
}

func buildRulesetXML(rsID string, rsName string, svc models.Service) xRuleset {
	rs := xRuleset{Name: rsName, ID: rsID}
	rs.Patterns.Patterns = append(rs.Patterns.Patterns, svc.Name)
	return rs
}
