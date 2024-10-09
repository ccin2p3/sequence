// This package is solely for the transformation and the output to file of sequence patterns found in server logs
// for use with Syslog-ng's patterndb parser. The transformation is solid, but not perfect and this is designed to assist
// a system administrator to create the patterns, not to be a full automation of the process.
// The outputs for patterndb have been tested with a live patterndb and pass at a rate close to 80% with the pdb test tool.
// The variable names usually need a bit of review as they can be string, string1 etc as the tool can detect a variable, but not what the variable is eg:server name.
package syslog_ng_pattern_db

import (
	"fmt"
	"index/suffixarray"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"gitlab.in2p3.fr/cc-in2p3-system/sequence"
)

var (
	tags struct {
		general map[string]string
		delstr  map[string]string
		cfield  map[string]string
	}
	logger *sequence.StandardLogger
)

// Allows the user to set the logger to a global instance.
func SetLogger(log *sequence.StandardLogger) {
	logger = log
}

func readConfig(file string) error {
	var configInfo struct {
		Patterndb struct {
			Tags struct {
				General         map[string]string
				DelimitedString map[string]string
				Fieldname       map[string]string
			}
		}
	}
	if _, err := toml.DecodeFile(file, &configInfo); err != nil {
		return err
	}

	tags.general = configInfo.Patterndb.Tags.General
	tags.delstr = configInfo.Patterndb.Tags.DelimitedString
	tags.cfield = configInfo.Patterndb.Tags.Fieldname

	return nil
}

// this replaces the sequence tags with the syslog-ng tags
// first we replace the easy ones that are surrounded by spaces
// then we deal with the compound ones
func replaceTags(pattern string) string {
	if len(pattern) < 1 {
		return pattern
	}
	//make sure @ are escaped @@ before we start
	pattern = strings.Replace(pattern, "@", "@@", -1)
	//some patterns start with a space, we need to catch that
	hasSpace := pattern[0:1] == " "
	s := strings.Fields(pattern)
	var new []string
	mtc := make(map[string]int)

	for _, p := range s {
		if val, ok := tags.general[p]; ok {
			p, mtc = getUpdatedTag(p, mtc, val, "")
		} else {
			p, mtc = getSpecial(p, mtc)
		}
		//reconstruct
		new = append(new, p)
	}
	var result string
	//no space at the start
	var space = ""
	for _, k := range new {
		result += space + k
		space = " "
		//need to remove the space after an ESTRING if space delimited
		if len(k) > 10 {
			if k[len(k)-3:] == ": @" {
				space = ""
			}
		}
	}
	// if the pattern ends looking for a space delimiter
	// remove the space
	if len(result) > 6 {
		if result[len(result)-3:] == ": @" {
			result = result[:len(result)-3] + ":@"
		}
	}

	if hasSpace {
		result = " " + result
	}

	return result
}

func getUpdatedTag(p string, mtc map[string]int, tag string, del string) (string, map[string]int) {
	tok := ""
	xchars := len(del)
	if xchars == 2 {
		tok = p[2 : len(p)-2]
	} else if xchars == 1 {
		tok = p[1 : len(p)-2]
	} else {
		tok = p[1 : len(p)-1]
	}
	//replace any field names that have a custom value in the config
	tok = checkForCustomFieldName(tok)
	fieldname := tok
	//check if there is more than one in the pattern and number
	if t, ok := mtc[tok]; ok {
		fieldname = fieldname + strconv.Itoa(t)
		mtc[tok] = t + 1
		p = strings.Replace(tag, "[fieldname]", fieldname, 1)
	} else {
		mtc[tok] = 1
		p = strings.Replace(tag, "[fieldname]", fieldname, 1)
	}
	return p, mtc
}

func getSpecial(p string, mtc map[string]int) (string, map[string]int) {
	var (
		last              = -1
		fieldname, del, s string
	)

	//first get the indexes of the % function
	k := p
	index := suffixarray.New([]byte(p))
	offsets := index.Lookup([]byte("%"), -1)
	sort.Slice(offsets, func(i, j int) bool {
		return offsets[i] < offsets[j]
	})

	for i, off := range offsets {
		if i%2 == 0 && i < len(offsets)-1 {
			s, del, fieldname, last = getWithDelimiters(p, off, offsets[i+1]+1, last)
			fieldname = checkForCustomFieldName(fieldname)
			//check if a time regex tag, this needs some manipulation
			if del == "" && strings.Contains(s, sequence.TagRegExTime.String()) {
				r, rg := getTimeRegex(s)
				// look for the pattern
				if val, ok := tags.general[r]; ok {
					r = val
					if rg != "" {
						r = strings.Replace(r, "[regexnotfound]", rg, 1)
					}
				}
				k = strings.Replace(k, s, r, 1)
			} else if del != "" {
				//remove any extra colons and numbers
				if strings.Contains(s, sequence.TagRegExTime.String()) {
					fieldname = sequence.TagRegExTime.String()
				}
				if val, ok := tags.delstr[del]; ok {
					val, mtc = getUpdatedTag(s, mtc, val, del)
					k = strings.Replace(k, s, val, 1)
				} else {
					//this means we have a custom delimiter instead of a space
					if val, ok := tags.delstr["default"]; ok {
						val, mtc = getUpdatedTag(s, mtc, val, del)
						val = strings.Replace(val, "[del]", del, 1)
						k = strings.Replace(k, s, val, 1)
					}
				}
			} else {
				if val, ok := tags.general[s]; ok {
					val, mtc = getUpdatedTag(s, mtc, val, del)
					k = strings.Replace(k, s, val, 1)
				}
			}
		}
	}
	return k, mtc
}

func checkForCustomFieldName(f string) string {
	if val, ok := tags.cfield[f]; ok {
		return val
	}
	return f
}

func getWithDelimiters(p string, start, end int, last int) (string, string, string, int) {
	fieldname := p[start+1 : end-1]
	before := ""
	//integer and ip fields are not considered strings so can bypass this
	if fieldname == "integer" || fieldname == "srcip" || fieldname == "dstip" || fieldname == "float" || fieldname == "ipv6" || fieldname == "srcmac" || fieldname == "dstmac" {
		return p[start:end], "", fieldname, end - 1
	}
	if start > 0 && end < len(p) {
		if last != start-1 {
			before = p[start-1 : start]
		}
		after := p[end : end+1]
		switch {
		case before == after && (before == "\"" || before == "'" || before == "`"):
			return p[start-1 : end+1], before + after, fieldname, end
		case (before == "(" && after == ")") || (before == "[" && after == "]"):
			return p[start-1 : end+1], before + after, fieldname, end
		case before == "<" && after == ">":
			return p[start-1 : end+1], before + after, fieldname, end
		case after != "%" && after != "@":
			return p[start : end+1], after, fieldname, end
		}
	} else if end < len(p) {
		after := p[end : end+1]
		if after != "%" && after != "@" {
			return p[start : end+1], after, fieldname, end
		}
	}
	return p[start:end], "", fieldname, end - 1
}

func getTimeRegex(p string) (string, string) {
	//this should be in the format %regextime:number%, the number is the regex id
	//find the colon
	i := strings.Index(p, ":")
	h := p[i+1 : len(p)-1]
	rg, ok := sequence.GetTimeSettingsRegExValue(h)
	if ok {
		p = p[:i] + "%"
	}
	return p, rg
}

// This is the function that drives the output to file.
// The user can pass the pattern map if no database is used or
// pass the map created during the analysis
func OutputToFiles(outformat string, outfile string, config string, complexitylevel float64, cmap map[string]sequence.AnalyzerResult, thresholdType string, thresholdValue string) (int, string, error) {

	var (
		txtFile  *os.File
		xmlFile  *os.File
		yamlFile *os.File
		xPattDB  xPatternDB
		yPattDB  yPatternDB
		err      error
		count    int
		top5     string
		patmap   map[string]sequence.AnalyzerResult
	)

	if config == "" {
		config = "./sequence.toml"
	}
	//read the config to load the tags
	if err = readConfig(config); err != nil {
		return count, top5, err
	}
	if sequence.GetUseDatabase() && cmap == nil {
		db, ctx := sequence.OpenDbandSetContext()
		defer db.Close()
		//get from the config instead
		if thresholdType == "" {
			thresholdType = sequence.GetThresholdType()
			thresholdValue = sequence.GetThresholdValue()
		}
		patmap, top5 = sequence.GetPatternsWithExamplesFromDatabase(db, ctx, complexitylevel, thresholdType, thresholdValue)
	} else {
		patmap = cmap
	}

	logger.HandleInfo(fmt.Sprintf("Found %d patterns for output", len(patmap)))
	count = len(patmap)
	outformats := strings.Split(outformat, ",")
	//open the output files for saving data and add any headers
	var fname string
	for _, fmat := range outformats {
		if fmat == "" || fmat == "txt" {
			//open the file for the text output
			if outfile != "" {
				fname = outfile + ".txt"
			}
			txtFile, err = sequence.OpenOutputFile(fname)
			if err != nil {
				return count, top5, err
			}
			defer txtFile.Close()
		}
		if fmat == "yaml" {
			//open the file for the xml output and write the header
			if outfile != "" {
				fname = outfile + ".yaml"
			}
			yamlFile, err = sequence.OpenOutputFile(fname)
			defer yamlFile.Close()
			if err != nil {
				return count, top5, err
			}
			yPattDB = yPatternDB{}
			yPattDB.Rulesets = make(map[string]yRuleset)
			yPattDB.Rules = make(map[string]yRule)
		}
		if fmat == "xml" {
			//open the file for the xml output and write the header
			if outfile != "" {
				fname = outfile + ".xml"
			}
			xmlFile, err = sequence.OpenOutputFile(fname)
			defer xmlFile.Close()
			if err != nil {
				return count, top5, err
			}
			fmt.Fprintf(xmlFile, "<?xml version='1.0' encoding='UTF-8'?>\n")
			xPattDB = xPatternDB{Version: "4", Pubdate: time.Now().Format("2006-01-02 15:04:05")}
		}
	}
	//add the patterns and examples
	for _, result := range patmap {
		for _, fmat := range outformats {
			if fmat == "" || fmat == "txt" {
				fmt.Fprintf(txtFile, "# %s\n %s\n# %d log messages matched\n# %s\n\n", result.PatternId, result.Pattern, result.ExampleCount, result.Examples[0].Message)
			}
			if fmat == "yaml" {
				yPattDB = addToYaml(result, yPattDB)
			}
			if fmat == "xml" {
				xPattDB = addToRuleset(result, xPattDB)
			}
		}
	}

	//finalise the files
	for _, fmat := range outformats {
		if fmat == "yaml" {
			//write to the file
			err := saveAsYaml(yamlFile, yPattDB)
			if err != nil {
				logger.HandleError(err.Error())
			}
		}
		if fmat == "xml" {
			//write to the file
			x := convertToXml(xPattDB)
			fmt.Fprintf(xmlFile, "%s", x)
		}
	}

	return count, top5, err
}

// This function extracts the values of the tokens for the test examples
func extractTestValuesForTokens(message string, ar sequence.AnalyzerResult) (map[string]map[string]string, error) {
	var (
		tok string
	)
	scanner := sequence.NewScanner()
	parser := sequence.NewParser()
	m := make(map[string]map[string]string)
	//no tags to find
	if ar.TagPositions == "" {
		return m, nil
	}
	pos := sequence.SplitToInt(ar.TagPositions, ",")
	//scan the pattern
	seq, _, err := scanner.Scan(ar.Pattern, true, pos)
	//add to the parser
	err = parser.Add(seq)
	//scan the example
	mseq, _, _ := sequence.ScanMessage(scanner, message, "")
	//parse the example
	pseq, err := parser.Parse(mseq)
	mtc := make(map[string]int)
	for _, p := range pseq {
		if p.Type != sequence.TokenLiteral && p.Type != sequence.TokenMultiLine {
			if p.Tag == 0 {
				tok = checkForCustomFieldName(p.Type.String())
			} else {
				tok = checkForCustomFieldName(p.Tag.String())
			}
			if t, ok := mtc[tok]; ok {
				m[tok+strconv.Itoa(t)] = make(map[string]string)
				m[tok+strconv.Itoa(t)]["value"] = p.Value
				mtc[tok] = t + 1
			} else {
				m[tok] = make(map[string]string)
				m[tok]["value"] = p.Value
				mtc[tok] = 1
			}
		}
	}
	return m, err
}
