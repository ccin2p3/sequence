package sequence

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"sort"
	"strconv"
	"strings"
)

// Scans the message using the appropriate format
func ScanMessage(scanner *Scanner, data string, format string) (Sequence, bool, error) {
	var (
		seq    Sequence
		isJson bool
		err    error
		pos    []int
	)

	if testJson(data) {
		seq, isJson, err = scanner.ScanJson_Preserve(data)
	} else {
		switch format {
		case "json":
			seq, isJson, err = scanner.ScanJson(data)

		default:
			seq, isJson, err = scanner.Scan(data, false, pos)
		}
	}
	return seq, isJson, err
}

func testJson(data string) bool {
	data = strings.TrimSpace(data)
	var js interface{}
	if data[:1] == "{" && data[len(data)-1:] == "}" {
		//try to marshall the json
		x := json.Unmarshal([]byte(data), &js)
		return x == nil
	}
	return false
}

// Builds the parser from a pattern file or series of pattern files in the same directory.
func BuildParser(patfile string) *Parser {
	parser := NewParser()

	if patfile == "" {
		return parser
	}

	var files []string
	var pos []int

	if fi, err := os.Stat(patfile); err != nil {
		logger.HandleFatal(err.Error())
	} else if fi.Mode().IsDir() {
		files, err = getDirOfFiles(patfile)
	} else {
		files = append(files, patfile)
	}

	scanner := NewScanner()

	for _, file := range files {
		// Open pattern file
		pscan, pfile, err := OpenInputFile(file)
		defer pfile.Close()
		if err != nil {
			logger.HandleFatal(err.Error())
		}

		for pscan.Scan() {
			line := pscan.Text()
			if len(line) == 0 || line[0] == '#' {
				continue
			}

			seq, _, err := scanner.Scan(line, true, pos)
			if err != nil {
				logger.HandleError(err.Error())
			}

			if err := parser.Add(seq); err != nil {
				logger.HandleError(err.Error())
			}
		}
	}

	return parser
}

func BuildParserFromDb(serviceid string) *Parser {
	parser := NewParser()
	scanner := NewScanner()
	db, ctx := OpenDbandSetContext()
	defer db.Close()
	//load all patterns from the database
	pmap := GetPatternsFromDatabaseByService(db, ctx, serviceid)
	for _, ar := range pmap {
		pos := SplitToInt(ar.TagPositions, ",")
		seq, _, err := scanner.Scan(ar.Pattern, true, pos)
		if err != nil {
			logger.HandleError(fmt.Sprintf("%s, Service: %s, Pattern: %s", err.Error(), ar.Service.Name, ar.PatternId))
		}

		if err := parser.Add(seq); err != nil {
			logger.HandleError(fmt.Sprintf("%s, Service: %s, Pattern: %s", err.Error(), ar.Service.Name, ar.PatternId))
		}
	}
	return parser
}

// Calculate the threshold value to use when exporting patterns from the database.
func getThreshold(numTotal int, typ string, val string) int {
	if typ == "count" {
		tr, err := strconv.Atoi(val)
		if err != nil {
			return 0
		} else {
			return tr
		}
	} else {
		f, err := strconv.ParseFloat(val, 64)
		if err != nil {
			return 0
		} else {
			total := float64(numTotal)
			t := f * total
			tr := int(math.Floor(t))
			return tr
		}
	}
	return 0
}

// This can be useful for debugging
func SortLogMessages(lr []LogRecord) []LogRecord {
	sort.Slice(lr, func(i, j int) bool {
		if lr[i].Service != lr[j].Service {
			return lr[i].Service < lr[j].Service
		}

		return lr[i].Message < lr[j].Message
	})
	return lr
}

// This can be used to sort and inspect the records in order
// useful for checking the patterns against all the examples
func SortandSaveLogMessages(lr []LogRecord, fname string) {
	sort.Slice(lr, func(i, j int) bool {
		if lr[i].Service != lr[j].Service {
			return lr[i].Service < lr[j].Service
		}
		return lr[i].Message < lr[j].Message
	})
	ofile, _ := OpenOutputFile(fname)
	defer ofile.Close()
	for _, r := range lr {
		fmt.Fprintf(ofile, "%s  %s\n", r.Service, r.Message)
	}
}

// This can be useful to save the service and message in text format.
func SaveLogMessages(lr LogRecordCollection, fname string) {
	ofile, _ := OpenOutputFile(fname)
	defer ofile.Close()
	for _, r := range lr.Records {
		fmt.Fprintf(ofile, "%s  %s\n", r.Service, r.Message)
	}
}
