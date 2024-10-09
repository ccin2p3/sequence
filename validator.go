package sequence

import (
	"strconv"
	"strings"
)

//this file is for various validation that may be called from more than one method

//validation of the argument input from the command line

// input format
// the in-format is for supporting a feed that has the service and the message provided.
// this can be either txt or json
func ValidateInformat(informat string) string {
	if (informat == "json") || (informat == "txt") {
		return ""
	}
	if informat == "" {
		return "Input format is required for this method, please select either json or txt"
	}
	return informat + " is not a supported input format type, please select either json or txt"
}

// output format
func ValidateOutformat(outformat string) string {
	outformats := strings.Split(outformat, ",")
	//open the output files for saving data and add any headers
	for _, fmat := range outformats {
		if (fmat != "xml") && (fmat != "yaml") && (fmat != "txt") {
			return "Valid values for out format are: xml,yaml or xml or yaml (for patterndb) or txt (for grok)"
		}
	}
	return ""
}

func ValidateOutsystem(outsystem string) string {
	if (outsystem == "patterndb") || (outsystem == "grok") {
		return ""
	}
	if outsystem == "" {
		return "Output system is required for this method, please select either patterndb or grok"
	}
	return outsystem + " is not a supported out system type, please select either patterndb or grok"
}

func ValidateOutFormatWithFile(outfile string, outformat string) string {
	outformats := strings.Split(outformat, ",")
	if len(outformats) > 1 && outfile == "" {
		return "Stdout can only supported one output format type, please select only one"
	}
	return ""
}

// for the create database
func ValidateOutFile(outfile string) string {
	if outfile == "" {
		return "Out file name must be specified for this method"
	}
	return ""
}

func ValidateBatchSize(batchsize int) string {
	if batchsize < 0 {
		return "Batch size must be zero or greater. Negative numbers are not permitted"
	}
	return ""
}

func ValidateLogLevel(lvl string) string {
	if len(lvl) > 0 {
		switch lvl {
		case "debug", "trace", "info", "error", "fatal":
			//valid - do nothing
			return ""
		default:
			return "Valid values for log level are: trace, debug, info, error or fatal, defaults to info. Please pass one of these values"
		}
	}
	return ""
}

func ValidateType(dbtype string) string {
	switch dbtype {
	case "sqlite3", "postgres", "mssql", "mysql":
		//valid - do nothing
		return ""
	default:
		return "Valid values for database type are: sqlite3, postgres, mssql or mysql. Please use one of these values"
	}
}

func ValidateThresholdType(thresholdType string) string {
	switch thresholdType {
	case "count", "percent":
		//valid - do nothing
		return ""
	default:
		return "Valid values for threshold type are: count or percent. Please pass use of these values"
	}
}

// if type is count it just needs to be 0 or greater
// if type is percent it needs to be a float between 0 and 1.
func ValidateThresholdValue(thresholdType string, thresholdValue string) string {
	switch thresholdType {
	case "count":
		//test conversion to int64
		tr, err := strconv.Atoi(thresholdValue)
		if err != nil {
			return "Valid values for threshold value used with count type are non-negative integer values. Please adjust the input"
		} else {
			//test 0 or greater
			if tr < 0 {
				return "Valid values for threshold value used with count type are non-negative integer values. Please adjust the input"
			}
		}
	case "percent":
		//test conversion to float
		f, err := strconv.ParseFloat(thresholdValue, 64)
		if err != nil {
			return "Valid values for threshold value used with percent type are non-negative decimal values. Please adjust the input"
		} else {
			//test 0 or greater
			if f < 0 {
				return "Valid values for threshold value used with percent type are non-negative decimal values. Please adjust the input"
			}
		}
	}
	return ""
}
