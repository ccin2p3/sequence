package main

import (
	"fmt"
	"github.com/spf13/cobra"
	"gitlab.in2p3.fr/cc-in2p3-system/sequence"
	"gitlab.in2p3.fr/cc-in2p3-system/sequence/logstash_grok"
	"gitlab.in2p3.fr/cc-in2p3-system/sequence/syslog_ng_pattern_db"
	"os"
	"os/signal"
	"runtime/pprof"
	"strings"
	"time"
)

var (
	cfgfile        string
	infile         string
	outfile        string
	logfile        string
	loglevel       string
	errorfile      string
	outsystem      string
	outformat      string
	informat       string
	patfile        string
	cpuprofile     string
	dbtype         string
	dbconn         string
	dbpath         string
	dbname         string
	workers        int
	format         string
	batchsize      int
	purgeThreshold int
	thresholdType  string
	thresholdValue string
	complimit      float64
	allinone       bool
	standardLogger *sequence.StandardLogger

	quit chan struct{}
	done chan struct{}
)

func profile() {
	var f *os.File
	var err error

	if cpuprofile != "" {
		f, err = os.Create(cpuprofile)
		if err != nil {
			sequence.StandardLogger{}.Fatal(err)
		}

		pprof.StartCPUProfile(f)
	}

	sigchan := make(chan os.Signal, 1)
	signal.Notify(sigchan, os.Interrupt, os.Kill)
	go func() {
		select {
		case sig := <-sigchan:
			standardLogger.HandleInfo(fmt.Sprintf("Existing due to trapped signal; %v", sig))

		case <-quit:
			standardLogger.HandleInfo("Quiting...")

		}

		if f != nil {
			standardLogger.HandleError("Stopping profile")
			pprof.StopCPUProfile()
			f.Close()
		}

		close(done)
		os.Exit(0)
	}()
}

func start(commandType string) {
	standardLogger = sequence.NewLogger(logfile, loglevel)
	//if errorfile != ""{
	//ofile, err := sequence.OpenOutputFile(errorfile)
	//if err == nil {
	//err = sequence.RedirectStderr(ofile)
	//if err != nil{
	//standardLogger.HandleFatal(fmt.Sprintf("Failed to redirect stderr to file: %v", err))
	//}
	//}else{
	//standardLogger.HandleFatal(fmt.Sprintf("Error opening file for system errors: %v", err))
	//}
	//}
	standardLogger.HandleInfo(fmt.Sprintf("Starting up: method called %s", commandType))
	readConfig()
	validateInputs(commandType)
	warnExtraInputs(commandType, allinone)
	profile()
}

func scan(cmd *cobra.Command, args []string) {
	start("scan")
	if infile != "" {
		scanner := sequence.NewScanner()
		iscan, ifile, err := sequence.OpenInputFile(infile)
		if err != nil {
			standardLogger.HandleFatal(err.Error())
		}
		defer ifile.Close()

		ofile, _ := sequence.OpenOutputFile(outfile)
		defer ofile.Close()

		lrMap := make(map[string]sequence.LogRecordCollection)
		//We load the file completely
		_, lrMap, _ = sequence.ReadLogRecordAsMap(iscan, informat, lrMap, batchsize)
		for _, lrc := range lrMap {
			for _, l := range lrc.Records {
				seq, _, _ := sequence.ScanMessage(scanner, l.Message, format)
				fmt.Fprintf(ofile, "%s\n\n", seq.PrintTokens())
			}
		}
	} else {
		standardLogger.HandleFatal("Invalid input file or string specified")
	}
}

func createdatabase(cmd *cobra.Command, args []string) {
	start("createdatabase")
	sequence.CreateDatabase(dbconn, dbtype, dbpath, dbname)
	standardLogger.HandleInfo(fmt.Sprintf("Database created successfully"))
}

func purgepatterns(cmd *cobra.Command, args []string) {
	start("purgepatterns")
	rf := sequence.PurgePatternsfromDatabase(int64(purgeThreshold))
	standardLogger.HandleInfo(fmt.Sprintf("%d patterns and their examples removed from the database.", rf))
}

func updateignorepatterns(cmd *cobra.Command, args []string) {
	start("ignorepatterns")
	iscan, ifile, err := sequence.OpenInputFile(infile)
	if err != nil {
		standardLogger.HandleFatal(err.Error())
	}
	defer ifile.Close()
	var ids []string
	for iscan.Scan() {
		ids = append(ids, iscan.Text())
	}
	sequence.SaveIgnoredPatterns(ids)
	standardLogger.HandleInfo(fmt.Sprintf("Ignore patterns updated."))
}

func analyzebyservice(cmd *cobra.Command, args []string) {
	start("analyzebyservice")
	scanner := sequence.NewScanner()
	var (
		err   error
		aseq  sequence.Sequence
		mtype string
	)
	iscan, ifile, err := sequence.OpenInputFile(infile)
	if err != nil {
		standardLogger.HandleFatal(err.Error())
	}
	defer ifile.Close()

	for {
		lrMap := make(map[string]sequence.LogRecordCollection)
		startTime := time.Now()
		//We load the file completely
		total, lrMap, exit := sequence.ReadLogRecordAsMap(iscan, informat, lrMap, batchsize)
		if exit {
			break
		}
		standardLogger.HandleInfo(fmt.Sprintf("Read in %d records successfully, starting analysis..", total))
		standardLogger.HandleDebug(fmt.Sprintf("Threshhold equals %d ", purgeThreshold))
		//Here we group by service and process
		//We lose the cross service patterns but we get better
		//within service patterns
		err_count := 0
		processed := 0
		amap := make(map[string]sequence.AnalyzerResult)
		pmap := make(map[string]sequence.AnalyzerResult)
		anStartTime := time.Now()
		for svc, lrc := range lrMap {
			standardLogger.HandleDebug(fmt.Sprintf("Started processing records from service: %s", svc))
			// For all the log messages, if we can't parse it, then let's add it to the
			// analyzer for pattern analysis, this requires the previous pattern file/folder
			//	to be passed in
			analyzer := sequence.NewAnalyzer()
			jsonParser := sequence.NewParser()
			sid := sequence.GenerateIDFromString("", svc)
			standardLogger.HandleDebug("Started building parser using patterns from database")
			parser := sequence.BuildParserFromDb(sid)
			standardLogger.HandleDebug("Completed building parser and starting to check if matches existing patterns")
			var seq sequence.Sequence
			var isJson bool
			partitionMap := make(map[int]sequence.LogRecordCollection)
			var jCol sequence.LogRecordCollection
			for _, l := range lrc.Records {
				seq, isJson, _ = sequence.ScanMessage(scanner, l.Message, format)
				pseq, err := parser.Parse(seq)
				//if the pattern is found we still need to update the pattern/service relationship
				//and the statistics
				if err == nil {
					pat, pos := pseq.String()
					ar, ok := pmap[pat]
					if !ok {
						ar = sequence.AnalyzerResult{}
					}
					sequence.AddExampleToAnalyzerResult(&ar, l)
					ar.Service.ID = sid
					ar.Service.Name = svc
					ar.TagPositions = sequence.SplitToString(pos, ",")
					ar.PatternId = sequence.GenerateIDFromString(pat, svc)
					ar.Pattern = pat
					ar.ExampleCount++
					pmap[pat] = ar

					processed++

				} else if err != nil {
					if isJson {
						jsonParser.Add(seq)
						jCol.Records = append(jCol.Records, l)
					} else {
						//we need to do something here based on number of tokens
						//we want to compare only those with same number.
						if col, ok := partitionMap[len(seq)]; ok {
							col.Records = append(col.Records, l)
							partitionMap[len(seq)] = col
						} else {
							col.Records = append(col.Records, l)
							partitionMap[len(seq)] = col
						}
						//analyzer.Add(seq)
					}
				}
			}
			//analyzer.Finalize()
			standardLogger.HandleDebug("Parsed statistics updated, new messages scanned and grouped.")
			standardLogger.HandleDebug("Starting analysis of json messages")
			for _, l := range jCol.Records {
				seq, _, _ := sequence.ScanMessage(scanner, l.Message, format)
				aseq, err = jsonParser.Parse(seq)
				mtype = "json"
				if err != nil {
					standardLogger.LogAnalysisFailed(l, mtype)
					err_count++
				} else {
					pat, pos := aseq.String()
					ar, ok := amap[pat]
					if !ok {
						ar = sequence.AnalyzerResult{}
					}
					sequence.AddExampleToAnalyzerResult(&ar, l)
					ar.Service.ID = sid
					ar.Service.Name = svc
					ar.TagPositions = sequence.SplitToString(pos, ",")
					ar.PatternId = sequence.GenerateIDFromString(pat, svc)
					ar.Pattern = pat
					ar.ExampleCount++
					ar.DateCreated = time.Now()
					ar.DateLastMatched = time.Now()
					ar.ComplexityScore = sequence.CalculatePatternComplexity(aseq, len(l.Message))
					amap[pat] = ar

					processed++
				}
			}
			for _, lrc := range partitionMap {
				analyzer = sequence.NewAnalyzer()
				for _, l := range lrc.Records {
					seq, _, _ := sequence.ScanMessage(scanner, l.Message, format)
					analyzer.Add(seq)
				}
				analyzer.Finalize()
				for _, l := range lrc.Records {
					seq, _, _ := sequence.ScanMessage(scanner, l.Message, format)
					aseq, err = analyzer.Analyze(seq)
					mtype = "general"
					if err != nil {
						standardLogger.LogAnalysisFailed(l, mtype)
						err_count++
					} else {
						pat, pos := aseq.String()
						ar, ok := amap[pat]
						if !ok {
							ar = sequence.AnalyzerResult{}
						}
						sequence.AddExampleToAnalyzerResult(&ar, l)
						ar.Service.ID = sid
						ar.Service.Name = svc
						ar.TagPositions = sequence.SplitToString(pos, ",")
						ar.PatternId = sequence.GenerateIDFromString(pat, svc)
						ar.Pattern = pat
						ar.ExampleCount++
						ar.DateCreated = time.Now()
						ar.DateLastMatched = time.Now()
						ar.ComplexityScore = sequence.CalculatePatternComplexity(aseq, len(l.Message))

						amap[pat] = ar
						processed++
					}
				}
			}
		}
		anTime := time.Since(anStartTime)
		standardLogger.HandleInfo(fmt.Sprintf("Analysed in: %s\n", anTime))
		if sequence.GetUseDatabase() && !allinone {
			standardLogger.HandleDebug("Starting save to the database.")
			sequence.SaveExistingToDatabase(pmap)
			new, saved := sequence.SaveToDatabase(amap)
			standardLogger.HandleDebug("Finished save to the database.")
			standardLogger.AnalyzeInfo(processed, len(amap)+len(pmap), new, saved, err_count, time.Since(startTime), anTime)
		} else {
			//output directly to the files
			//merge pmap and amap
			//syslog-ng patterndb
			cmap := amap
			for k, v := range pmap {
				cmap[k] = v
			}
			export(cmap)
			//always output to a txt file for parsing later
			oFile, _ := sequence.OpenOutputFile("C:\\data\\debug.txt")
			defer oFile.Close()
			for pat, stat := range amap {
				fmt.Fprintf(oFile, "%s\n# %d log messages matched\n# %s\n\n", pat, stat.ExampleCount, stat.Examples[0].Message)
			}
		}

		if batchsize == 0 || infile != "-" {
			break
		}
	}
}

func exportPatterns(cmd *cobra.Command, args []string) {
	start("exportpatterns")
	export(nil)
}

func export(cmap map[string]sequence.AnalyzerResult) {
	startTime := time.Now()
	if outsystem == "patterndb" {
		processed, top5, err := syslog_ng_pattern_db.OutputToFiles(outformat, outfile, cfgfile, complimit, cmap, thresholdType, thresholdValue)
		if err != nil {
			standardLogger.HandleError(err.Error())
		} else {
			standardLogger.ExportPatternsInfo(processed, top5, time.Since(startTime))
		}
	} else if outsystem == "grok" {
		processed, top5, err := logstash_grok.OutputToFiles(outfile, cfgfile, complimit, cmap, thresholdType, thresholdValue)
		if err != nil {
			standardLogger.HandleError(err.Error())
		} else {
			standardLogger.ExportPatternsInfo(processed, top5, time.Since(startTime))
		}
	} else {
		standardLogger.HandleError("No export format provided, could not export the patterns.")
	}
}

func validateInputs(commandType string) {
	var errors []string
	err := sequence.ValidateLogLevel(loglevel)
	if err != "" {
		errors = append(errors, err)
	}
	switch commandType {
	case "analyzebyservice":
		//set the formats to lower before we start
		informat = strings.ToLower(informat)
		outformat = strings.ToLower(outformat)
		//validate input file
		if infile == "" {
			errors = append(errors, "Invalid input file specified")
		}
		err := sequence.ValidateInformat(informat)
		if err != "" {
			errors = append(errors, err)
		}
		err = sequence.ValidateBatchSize(batchsize)
		if err != "" {
			errors = append(errors, err)
		}
		if allinone {
			err = sequence.ValidateOutFile(outfile)
			if err != "" {
				errors = append(errors, err)
			}
			err = sequence.ValidateOutFormatWithFile(outfile, outformat)
			if err != "" {
				errors = append(errors, err)
			}
			err = sequence.ValidateOutsystem(outsystem)
			if err != "" {
				errors = append(errors, err)
			}
			err = sequence.ValidateOutformat(outformat)
			if err != "" {
				errors = append(errors, err)
			}
			//threshold type is optional
			if thresholdType != "" || thresholdValue != "0" {
				err = sequence.ValidateThresholdType(thresholdType)
				if err != "" {
					errors = append(errors, err)
				}
				err = sequence.ValidateThresholdValue(thresholdType, thresholdValue)
				if err != "" {
					errors = append(errors, err)
				}
			}
			//it is 1 by default
			if complimit != 1 {
				if complimit < 0 || complimit > 1 {
					errors = append(errors, "The value for the complexity score limit must be between 0 and 1.")
				}
			}
		}
	case "exportpatterns":
		//this requires outfile, outformat, outsystem
		//optional are thresholdtype and thresholdvalue and complexity score
		// set the formats to lower before we start
		outformat = strings.ToLower(outformat)
		err := sequence.ValidateOutformat(outformat)
		if err != "" {
			errors = append(errors, err)
		}
		err = sequence.ValidateOutsystem(outsystem)
		if err != "" {
			errors = append(errors, err)
		}
		err = sequence.ValidateOutFormatWithFile(outfile, outformat)
		if err != "" {
			errors = append(errors, err)
		}
		//threshold type is optional
		if thresholdType != "" || thresholdValue != "0" {
			err = sequence.ValidateThresholdType(thresholdType)
			if err != "" {
				errors = append(errors, err)
			}
			err = sequence.ValidateThresholdValue(thresholdType, thresholdValue)
			if err != "" {
				errors = append(errors, err)
			}
		}
		//it is 1 by default
		if complimit != 1 {
			if complimit < 0 || complimit > 1 {
				errors = append(errors, "The value for the complexity score limit must be between 0 and 1.")
			}
		}
	case "createdatabase":
		//create database only works with Sqlite3 at the moment.
		err = sequence.ValidateType(dbtype)
		if err != "" {
			errors = append(errors, err)
		}
		//validate input file
		if dbconn == "" {
			errors = append(errors, "Invalid database connection details specified")
		}

	case "purgepatterns":
		if purgeThreshold <= 0 {
			errors = append(errors, "Threshold must be greater than zero or no records will be deleted.")
		}
	case "scan":
		//validate input file
		if infile == "" {
			errors = append(errors, "Invalid input file specified")
		}
		err := sequence.ValidateInformat(informat)
		if err != "" {
			errors = append(errors, err)
		}
		err = sequence.ValidateOutFile(outfile)
		if err != "" {
			errors = append(errors, err)
		}

	case "updateignorepatterns":
		//validate input file
		if infile == "" {
			errors = append(errors, "Invalid input file specified")
		}
	}
	exs := ""
	for i, ex := range errors {
		exs += fmt.Sprintf("(%d) %s. ", i+1, ex)
	}

	if exs != "" {
		standardLogger.HandleFatal(exs)
	}
}

func warnExtraInputs(commandType string, all bool) {
	var warnings string
	var extras []string
	switch commandType {
	case "analyzebyservice":
		if purgeThreshold != 0 {
			extras = append(extras, "purge threshold (-t)")
		}
		if dbconn != "" {
			extras = append(extras, "connection string (--conn)")
		}
		if dbtype != "" {
			extras = append(extras, "database type (--type)")
		}
		if !all {
			if outfile != "" {
				extras = append(extras, "output file (-o)")
			}
			if outformat != "" {
				extras = append(extras, "output format (-f)")
			}
			if outsystem != "" {
				extras = append(extras, "output system (-s)")
			}
			if complimit != 1 {
				extras = append(extras, "complexity score limit (-c)")
			}
			if thresholdValue != "0" {
				extras = append(extras, "threshold value (-v)")
			}
			if thresholdType != "" {
				extras = append(extras, "threshold type (-y)")
			}
		}

	case "exportpatterns":
		if purgeThreshold != 0 {
			extras = append(extras, "purge threshold (-t)")
		}
		if infile != "" {
			extras = append(extras, "input file (-i)")
		}
		if informat != "" {
			extras = append(extras, "input format (-k)")
		}
		if batchsize != 0 {
			extras = append(extras, "batch size (-b)")
		}
		if dbconn != "" {
			extras = append(extras, "connection string (--conn)")
		}
		if dbtype != "" {
			extras = append(extras, "database type (--type)")
		}
		if all {
			extras = append(extras, "all in one (--all)")
		}
	case "scan":
		if purgeThreshold != 0 {
			extras = append(extras, "purge threshold (-t)")
		}
		if batchsize != 0 {
			extras = append(extras, "batch size (-b)")
		}
		if dbconn != "" {
			extras = append(extras, "connection string (--conn)")
		}
		if dbtype != "" {
			extras = append(extras, "database type (--type)")
		}
		if outformat != "" {
			extras = append(extras, "output format (-f)")
		}
		if outsystem != "" {
			extras = append(extras, "output system (-s)")
		}
		if complimit != 1 {
			extras = append(extras, "complexity score limit (-c)")
		}
		if thresholdValue != "0" {
			extras = append(extras, "threshold value (-v)")
		}
		if thresholdType != "" {
			extras = append(extras, "threshold type (-y)")
		}
		if all {
			extras = append(extras, "all in one (--all)")
		}
	case "createdatabase":
		//create database only works with Sqlite3 at the moment.
		if purgeThreshold != 0 {
			extras = append(extras, "purge threshold (-t)")
		}
		if infile != "" {
			extras = append(extras, "input file (-i)")
		}
		if informat != "" {
			extras = append(extras, "input format (-k)")
		}
		if batchsize != 0 {
			extras = append(extras, "batch size (-b)")
		}
		if outfile != "" {
			extras = append(extras, "output file (-o)")
		}
		if outformat != "" {
			extras = append(extras, "output format (-f)")
		}
		if outsystem != "" {
			extras = append(extras, "output system (-s)")
		}
		if complimit != 1 {
			extras = append(extras, "complexity score limit (-c)")
		}
		if thresholdValue != "" {
			extras = append(extras, "threshold value (-v)")
		}
		if thresholdType != "" {
			extras = append(extras, "threshold type (-y)")
		}
		if all {
			extras = append(extras, "all in one (--all)")
		}

	case "purgepatterns":
		if infile != "" {
			extras = append(extras, "input file (-i)")
		}
		if informat != "" {
			extras = append(extras, "input format (-k)")
		}
		if batchsize != 0 {
			extras = append(extras, "batch size (-b)")
		}
		if outfile != "" {
			extras = append(extras, "output file (-o)")
		}
		if outformat != "" {
			extras = append(extras, "output format (-f)")
		}
		if outsystem != "" {
			extras = append(extras, "output system (-s)")
		}
		if complimit != 1 {
			extras = append(extras, "complexity score limit (-c)")
		}
		if thresholdValue != "" {
			extras = append(extras, "threshold value (-v)")
		}
		if thresholdType != "" {
			extras = append(extras, "threshold type (-y)")
		}
		if dbconn != "" {
			extras = append(extras, "connection string (--conn)")
		}
		if dbtype != "" {
			extras = append(extras, "database type (--type)")
		}
		if all {
			extras = append(extras, "all in one (--all)")
		}
	case "updateignorepatterns":
		if purgeThreshold != 0 {
			extras = append(extras, "purge threshold (-t)")
		}
		if informat != "" {
			extras = append(extras, "input format (-k)")
		}
		if batchsize != 0 {
			extras = append(extras, "batch size (-b)")
		}
		if outfile != "" {
			extras = append(extras, "output file (-o)")
		}
		if outformat != "" {
			extras = append(extras, "output format (-f)")
		}
		if outsystem != "" {
			extras = append(extras, "output system (-s)")
		}
		if complimit != 1 {
			extras = append(extras, "complexity score limit (-c)")
		}
		if thresholdValue != "" {
			extras = append(extras, "threshold value (-v)")
		}
		if thresholdType != "" {
			extras = append(extras, "threshold type (-y)")
		}
		if dbconn != "" {
			extras = append(extras, "connection string (--conn)")
		}
		if dbtype != "" {
			extras = append(extras, "database type (--type)")
		}
		if all {
			extras = append(extras, "all in one (--all)")
		}
	}
	// Build message
	for _, w := range extras {
		warnings += w + ", "
	}

	if warnings != "" {
		warnings = fmt.Sprintf("Warning: The following flags are assigned values but are not used by the %s function: %s", commandType, warnings)
		standardLogger.HandleInfo(warnings)
		println(warnings)
	}
}

func readConfig() {
	if cfgfile == "" {
		cfgfile = "./sequence.toml"

		if _, err := os.Stat(cfgfile); err != nil {
			if slash := strings.LastIndex(os.Args[0], "/"); slash != -1 {
				cfgfile = os.Args[0][:slash] + "/sequence.toml"

				if _, err := os.Stat(cfgfile); err != nil {
					standardLogger.HandleFatal("No configuration file found")
				}
			}
		}
	}

	if err := sequence.ReadConfig(cfgfile); err != nil {
		standardLogger.HandleFatal(err.Error())
	}
	//set the logger for the sequence, syslog_ng_pattern_db and logstash grok modules
	sequence.SetLogger(standardLogger)
	syslog_ng_pattern_db.SetLogger(standardLogger)
	logstash_grok.SetLogger(standardLogger)
}

func main() {
	quit = make(chan struct{})
	done = make(chan struct{})

	var (
		sequenceCmd = &cobra.Command{
			Use:   "sequence",
			Short: "sequence is a high performance sequential log analyzer and parser",
		}

		scanCmd = &cobra.Command{
			Use:   "scan",
			Short: "tokenizes a log file or message and output a list of tokens",
		}

		createDatabaseCmd = &cobra.Command{
			Use:   "createdatabase",
			Short: "creates a new sequence database to the location in the config file",
		}

		purgePatternsCmd = &cobra.Command{
			Use:   "purgepatterns",
			Short: "deletes patterns and their examples under a threshold",
		}

		analyzeByServiceCmd = &cobra.Command{
			Use:   "analyzebyservice",
			Short: "analyzes a log file and output a list of patterns that will match all the log messages",
		}

		exportPatternsCmd = &cobra.Command{
			Use:   "exportpatterns",
			Short: "outputs a list of patterns to the files in the formats requested.",
		}

		updateIgnoreCmd = &cobra.Command{
			Use:   "updateignorepatterns",
			Short: "outputs a list of patterns to the files in the formats requested.",
		}
	)

	sequenceCmd.PersistentFlags().StringVarP(&cfgfile, "config", "", "", "TOML-formatted configuration file, default checks ./sequence.toml, then sequence.toml in the same directory as program")
	sequenceCmd.PersistentFlags().StringVarP(&infile, "input", "i", "", "input file, required, if - then stdin")
	sequenceCmd.PersistentFlags().StringVarP(&outfile, "output", "o", "", "output file, if omitted, to stdout, if multiple out-formats will use the same file name with diff extensions")
	sequenceCmd.PersistentFlags().StringVarP(&patfile, "patterns", "p", "", "existing patterns text file, can be a file or directory")
	sequenceCmd.PersistentFlags().StringVarP(&outformat, "out-format", "f", "", "format of the output file, can be yaml, xml or txt or a combo comma separated eg txt,xml, if empty it uses text, used by analyze")
	sequenceCmd.PersistentFlags().StringVarP(&outsystem, "out-system", "s", "", "system that will use the output, not needed if use database is set to true in the config, valid values are patterndb and grok, used by analyzebyservice")
	sequenceCmd.PersistentFlags().StringVarP(&informat, "in-format", "k", "", "format of the input data, can be json or txt, if empty it uses txt, used by analyze")
	sequenceCmd.PersistentFlags().IntVarP(&batchsize, "batch-size", "b", 0, "if using a large file or stdin, the batch size sets the limit of how many to process at one time")
	sequenceCmd.PersistentFlags().StringVarP(&logfile, "log-file", "l", "", "location of log file if different from the exe directory")
	sequenceCmd.PersistentFlags().StringVarP(&loglevel, "log-level", "n", "", "defaults to info level, can be 'trace' 'debug', 'info', 'error', 'fatal'")
	sequenceCmd.PersistentFlags().IntVarP(&purgeThreshold, "purge-threshold", "t", 0, "this is used with the purge patterns command and exportpatterns, for purge patterns is represents a number below which patterns are deleted, for exported patterns exported patterns to override the config value in matchThresholdValue.")
	sequenceCmd.PersistentFlags().StringVarP(&thresholdType, "match-threshold-type", "y", "", "this can be used with exported patterns to override the config value in matchThresholdType")
	sequenceCmd.PersistentFlags().StringVarP(&thresholdValue, "match-threshold-value", "v", "0", "this can be used with exported patterns to override the config value in matchThresholdValue")
	sequenceCmd.PersistentFlags().Float64VarP(&complimit, "complexity-limit", "c", 1, "the complexity of a pattern is between 0 and 1, higher numbers represent more tags. 0.5 is a good level to limit exporting over-tagged patterns.")
	sequenceCmd.PersistentFlags().BoolVarP(&allinone, "all", "", false, "if passed to analyzebyservice it by passes saving to the database and directly out puts the patterns.")
	sequenceCmd.PersistentFlags().StringVarP(&dbtype, "type", "", "", "type of the database when creating it, can mssql, postgres, sqlite3 or mysql")
	sequenceCmd.PersistentFlags().StringVarP(&dbconn, "conn", "", "", "connection details for the server")

	scanCmd.Run = scan
	createDatabaseCmd.Run = createdatabase
	purgePatternsCmd.Run = purgepatterns
	analyzeByServiceCmd.Run = analyzebyservice
	exportPatternsCmd.Run = exportPatterns
	updateIgnoreCmd.Run = updateignorepatterns

	sequenceCmd.AddCommand(scanCmd)
	sequenceCmd.AddCommand(createDatabaseCmd)
	sequenceCmd.AddCommand(purgePatternsCmd)
	sequenceCmd.AddCommand(analyzeByServiceCmd)
	sequenceCmd.AddCommand(exportPatternsCmd)
	sequenceCmd.AddCommand(updateIgnoreCmd)

	sequenceCmd.Execute()
}
