package syslog_ng_pattern_db

import (
	"fmt"
	"gitlab.in2p3.fr/cc-in2p3-system/sequence"
	"gopkg.in/yaml.v3"
	"math"
	"os"
	"time"
)

type yPatternDB struct {
	Rules    map[string]yRule    `yaml:"coloss::patterndb::simple::rule"`
	Rulesets map[string]yRuleset `yaml:"coloss::patterndb::simple::ruleset"`
}

//This represents a rule section in the sys-log ng yaml file
type yRule struct {
	Ruleset   string         `yaml:"ruleset"`
	RuleClass string         `yaml:"ruleclass"`
	Patterns  []string       `yaml:"patterns"`
	Examples  []yRuleExample `yaml:"examples"`
	Values    yRuleValues    `yaml:"values"`
	ID        string         `yaml:"id,omitempty"`
}

type yRuleValues struct {
	Complexity      float64 `yaml:"seq-complexity"`
	Seqmatches      int     `yaml:"seq-matches"`
	DateCreated     string  `yaml:"seq-created"`
	DateLastMatched string  `yaml:"seq-last-match"`
}

//This represents a ruleset section in the sys-log ng yaml file
type yRuleset struct {
	Pubdate  string
	ID       string `yaml:"id,omitempty"`
	Parser   string
	Patterns []string `yaml:"patterns"`
}

type yRuleExample struct {
	Program     string                       `yaml:"program"`
	TestMessage string                       `yaml:"test_message"`
	TextValues  map[string]map[string]string `yaml:"test_values"`
}

func saveAsYaml(oFile *os.File, db yPatternDB) error {
	//check if the pattern exists
	// turn the rule into YAML format
	en := yaml.NewEncoder(oFile)
	en.SetIndent(2)
	y := en.Encode(db)
	return y
}

func addToYaml(pattern sequence.AnalyzerResult, db yPatternDB) yPatternDB {
	//do we have a special case where it belongs to more that one service
	rsName := pattern.Service.Name
	rsID := pattern.Service.ID
	//look in the ruleset if it exists already
	_, ok := db.Rulesets[rsName]
	if !ok {
		rs := buildRuleset(pattern, rsID)
		db.Rulesets[rsName] = rs
	}

	//every pattern should be unique
	r := buildRule(pattern, rsName)
	db.Rules[r.ID] = r

	return db
}

func buildRule(result sequence.AnalyzerResult, rsName string) yRule {
	rule := yRule{}
	rule.Values.Seqmatches = result.ExampleCount
	//get the ruleset from the example (service)
	rule.Ruleset = rsName
	rule.RuleClass = "sequence"
	rule.Patterns = append(rule.Patterns, replaceTags(result.Pattern))
	for _, ex := range result.Examples {
		m, err := extractTestValuesForTokens(ex.Message, result)
		if err != nil {
			//make an empty map, log an error and continue
			m = make(map[string]map[string]string)
			logger.HandleError(fmt.Sprintf("Unable to make test_values map for examples for pattern %s", result.PatternId))
		}
		example := yRuleExample{ex.Service, ex.Message, m}
		rule.Examples = append(rule.Examples, example)
	}
	rule.Values.DateCreated = result.DateCreated.Format("2006-01-02")
	rule.Values.DateLastMatched = result.DateLastMatched.Format("2006-01-02")
	rule.Values.Complexity = math.Round(result.ComplexityScore*100) / 100
	//create a new UUID
	rule.ID = result.PatternId
	return rule
}

func buildRuleset(result sequence.AnalyzerResult, rsID string) yRuleset {
	rs := yRuleset{}
	rs.Pubdate = time.Now().Format("2006-01-02")
	//get the ruleset from the example (service)
	rs.Parser = "sequence"
	rs.Patterns = append(rs.Patterns, result.Service.Name)
	//create a new UUID
	rs.ID = rsID
	return rs
}
