// This package is solely for the transformation and the output to file of sequence patterns found in server logs
// for use with Logstash's grok parser. The transformation is solid, but not perfect and this is designed to assist
// a system administrator to create the patterns, not to be a full automation of the process.
// The outputs for Grok have been tested with an online grok pattern tester, but not with a live system like the
// Syslog-ng patterndB transformations.
// There is a possibility of duplication of patterns if the services that log have similar messages.
package logstash_grok

import (
	"fmt"
	"github.com/BurntSushi/toml"
	"gitlab.in2p3.fr/cc-in2p3-system/sequence"
	"index/suffixarray"
	"sort"
	"strconv"
	"strings"
)

var (
	tags struct {
		general map[string]string
		delstr  map[string]string
		cfield  map[string]string
	}
	logger *sequence.StandardLogger
)

func SetLogger(log *sequence.StandardLogger) {
	logger = log
}

func readConfig(file string) error {
	var configInfo struct {
		Grok struct {
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

	tags.general = configInfo.Grok.Tags.General
	tags.delstr = configInfo.Grok.Tags.DelimitedString
	tags.cfield = configInfo.Grok.Tags.Fieldname

	return nil
}

// This function takes patterns created by the sequence module and outputs them in a grok format.
// This translation is only lighly tested and as with any translation is not always perfect.
// Transformed patterns need to be reviewed before use in production.
func OutputToFiles(outfile string, config string, complexitylevel float64, cmap map[string]sequence.AnalyzerResult, thresholdType string, thresholdValue string) (int, string, error) {
	var (
		err    error
		count  int
		top5   string
		patmap map[string]sequence.AnalyzerResult
	)

	if config == "" {
		config = "./sequence.toml"
	}
	//read the config to load the tags
	if err = readConfig(config); err != nil {
		return count, "", err
	}
	if sequence.GetUseDatabase() {
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
	//open the file for the text output
	txtFile, err := sequence.OpenOutputFile(outfile)
	if err != nil {
		return count, top5, err
	}
	defer txtFile.Close()
	fmt.Fprintf(txtFile, "filter {\n")

	//add all the patterns here
	//match => { "message" => "Duration: %{NUMBER:duration}", "Speed: %{NUMBER:speed}" }
	//add_tag => [ "id_value", "pattern_id" ]
	for _, result := range patmap {
		fmt.Fprintf(txtFile, "\tgrok {\n \t\tmatch => {\"message\" => \"%s\"}\n\t\tadd_tag => [\"%s\", \"pattern_id\"]\n\t}\n", replaceTags(result.Pattern), result.PatternId)
	}
	fmt.Fprintf(txtFile, "}\n")
	return 0, top5, nil
}

// This replaces the sequence tags with the grok formatted tags
func replaceTags(pattern string) string {
	//make sure " are escaped \" before we start
	//pattern = strings.Replace(pattern, "\"", "\\\"", -1)
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
	}

	replacer := strings.NewReplacer("\"", "\\\"", "[", "\\[", "]", "\\]", "(", "\\(", ")", "\\)")
	output := replacer.Replace(result)
	return output
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

func checkForCustomFieldName(f string) string {
	if val, ok := tags.cfield[f]; ok {
		return val
	}
	return f
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
			//TODO: deal with regex and time formats
			if strings.Contains(s, sequence.TagRegExTime.String()) {
				k = getTimeRegex(s)
			}
			if del != "" {
				//remove any extra colons and numbers
				if val, ok := tags.delstr[del]; ok {
					val, mtc = getUpdatedTag(s, mtc, val, del)
					k = strings.Replace(k, s, val, 1)
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

func getWithDelimiters(p string, start, end int, last int) (string, string, string, int) {
	fieldname := p[start+1 : end-1]
	before := ""
	//integer and ip fields are not considered strings so can bypass this
	if fieldname == "integer" || fieldname == "srcip" || fieldname == "dstip" || fieldname == "float" || fieldname == "ipv6" {
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
		}
	}
	return p[start:end], "", fieldname, end - 1
}

func getTimeRegex(p string) string {
	//this should be in the format %regextime:number%, the number is the regex id
	//find the colon
	i := strings.Index(p, ":")
	h := p[i+1 : len(p)-1]
	rg, ok := sequence.GetTimeSettingsGrokValue(h)
	if !ok {
		rg = p
	}
	return rg
}
