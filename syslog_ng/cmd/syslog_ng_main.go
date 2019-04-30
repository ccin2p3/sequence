package main

import (
	"fmt"
	"github.com/spf13/cobra"
	"github.com/surge/glog"
	"log"
	"os"
	"os/signal"
	"runtime/pprof"
	"sequence"
	"sequence/syslog_ng"
	"strings"
	"time"
)

var (
	cfgfile    string
	infile     string
	outfile    string
	outformat  string
	informat  string
	patfile    string
	cpuprofile string
	workers    int
	format     string

	quit chan struct{}
	done chan struct{}
)

func profile() {
	var f *os.File
	var err error

	if cpuprofile != "" {
		f, err = os.Create(cpuprofile)
		if err != nil {
			log.Fatal(err)
		}

		pprof.StartCPUProfile(f)
	}

	sigchan := make(chan os.Signal, 1)
	signal.Notify(sigchan, os.Interrupt, os.Kill)
	go func() {
		select {
		case sig := <-sigchan:
			log.Printf("Existing due to trapped signal; %v", sig)

		case <-quit:
			log.Println("Quiting...")

		}

		if f != nil {
			glog.Errorf("Stopping profile")
			pprof.StopCPUProfile()
			f.Close()
		}

		close(done)
		os.Exit(0)
	}()
}


func analyze(cmd *cobra.Command, args []string) {
	readConfig()
	if infile == "" {
		log.Fatal("Invalid input file specified")
	}
	profile()
	parser := buildParser()
	analyzer := sequence.NewAnalyzer()
	scanner := sequence.NewScanner()

	//We load the file completely
	var lr []sequence.LogRecord

	if informat == "json" {
		lr = sequence.ReadLogRecordJson(infile)
	} else{
		lr = sequence.ReadLogRecordTxt(infile)
	}

	// For all the log messages, if we can't parse it, then let's add it to the
	// analyzer for pattern analysis, this requires the previous pattern file/folder
	//	to be passed in
	for _, r := range lr {
		//TODO Fix this so it doesn't scan twice or parse twice
		seq := scanMessage(scanner, r.Message)
		if _, err := parser.Parse(seq); err != nil {
			analyzer.Add(seq)
		}
	}
	analyzer.Finalize()

	//Uncomment this to sort the slice by the service
	//Useful for debugging
	syslog_ng.SortLogMessages(lr)

	//these are existing patterns
	pmap := make(map[string]struct {
		ex  string
		cnt int
		svc string
	})
	//these are the newly discovered patterns
	amap := make(map[string]sequence.AnalyzerResult)

	// Now that we have built the analyzer, let's go through each log message again
	// to determine the unique patterns
	err_count := 0
	processed := 0
	var vals []int

	for _, l := range lr {
		//TODO Fix this so it doesn't scan twice or parse twice
		seq := scanMessage(scanner, l.Message)

		pseq, err := parser.Parse(seq)
		if err == nil {
			pat := strings.TrimSpace(pseq.String())
			stat, ok := pmap[pat]
			if !ok {
				stat = struct {
					ex  string
					cnt int
					svc string
				}{}
			}
			stat.ex = l.Message
			stat.cnt++
			stat.svc = l.Service
			pmap[pat] = stat
		} else {
			aseq, err := analyzer.Analyze(seq)
			if err != nil {
				log.Printf("Error analyzing: %s", l.Message)
				err_count++
			} else {
				pat := strings.TrimSpace(aseq.String())
				stat, ok := amap[pat]
				if !ok {
					stat = sequence.AnalyzerResult{}
				}
				sequence.AddExampleToAnalyzerResult(&stat, l.Message)
				stat.PatternId = sequence.GenerateIDFromPattern(pat)
				stat.ExampleCount++
				stat.Service = l.Service
				amap[pat] = stat
			}
		}
		processed++
	}

	opatfile := sequence.OpenOutputFile("C:\\data\\pattern.txt")
	defer opatfile.Close()

	//get the threshold for including the pattern in the
	//output files
	threshold := sequence.GetThreshold(len(lr))

	//
	//if outformat == "text" || outformat == ""{
		for pat, stat := range pmap {
			fmt.Fprintf(opatfile, "%s\n# %d log messages matched\n# %s\n\n", pat, stat.cnt, stat.ex)
		}

		for pat, stat := range amap {
			fmt.Fprintf(opatfile, "%s\n# %d log messages matched\n# %s\n\n", pat, stat.ExampleCount, stat.Examples[0])
		}
	//}

	ofile := sequence.OpenOutputFile(outfile)
	defer ofile.Close()

	if outformat == "yaml"{
		fmt.Fprintf(ofile, "coloss::patterndb::simple::rule:\n")
		pattern := sequence.AnalyzerResult{}
		for pat, stat := range pmap {
			pattern = sequence.AnalyzerResult{Pattern:pat, ExampleCount: stat.cnt, Service:stat.svc}
			pattern.Examples = append(pattern.Examples, stat.ex)
			y := syslog_ng.ConvertToYaml(pattern)
			//write to the file line by line with a tab in front.
			s := strings.Split(y,"\n")
			for _, v := range s {
				if len(v)>0{
					fmt.Fprintf(ofile, "\t%s\n", v)
				}

			}
		}
		for pat, stat := range amap {
			pattern = sequence.AnalyzerResult{stat.PatternId, pat, stat.ExampleCount, stat.Examples, stat.Service}
			//only add patterns with a certain number of examples found
			if threshold < stat.ExampleCount {
				y := syslog_ng.ConvertToYaml(pattern)
				//write to the file line by line with a tab in front.
				s := strings.Split(y,"\n")
				for _, v := range s {
					if len(v)>0{
						fmt.Fprintf(ofile, "\t%s\n", v)
					}

				}
				vals = append(vals, stat.ExampleCount)
			}

		}
	}

	if outformat == "xml"{
		fmt.Fprintf(ofile, "<?xml version='1.0' encoding='UTF-8'?>\n")
		pattDB := syslog_ng.PatternDB{Version:"4", Pubdate:time.Now().Format("2006-01-02 15:04:05")}
		pattern := sequence.AnalyzerResult{}

		//existing patterns
		for pat, stat := range pmap {
			pattern = sequence.AnalyzerResult{Pattern:pat, ExampleCount: stat.cnt, Service:stat.svc}
			pattern.Examples = append(pattern.Examples, stat.ex)
			pattDB = syslog_ng.AddToRuleset(pattern, pattDB)

		}
		//new patterns
		for pat, stat := range amap {
			pattern = sequence.AnalyzerResult{stat.PatternId, pat, stat.ExampleCount, stat.Examples, stat.Service}
			if threshold < stat.ExampleCount{
				pattDB = syslog_ng.AddToRuleset(pattern, pattDB)
				vals = append(vals, stat.ExampleCount)
			}
		}

		//write to the file
		y := syslog_ng.ConvertToXml(pattDB)
		fmt.Fprintf(ofile, "\t%s\n", y)
	}

	log.Printf("Analyzed %d messages, found %d unique patterns, %d are new. %d passed the threshold and were added to the xml/yaml file, %d messages errored", len(lr), len(pmap)+len(amap), len(amap), len(vals), err_count)
}

func analyzebyservice(cmd *cobra.Command, args []string) {
	readConfig()

	if infile == "" {
		log.Fatal("Invalid input file specified")
	}
	profile()
	parser := buildParser()
	analyzer := sequence.NewAnalyzer()
	scanner := sequence.NewScanner()

	startTime := time.Now()

	//We load the file completely
	var lrMap = make(map[string]sequence.LogRecordCollection)
	if informat == "json" {
		lrMap = sequence.ReadLogRecordJsonAsMap(infile)
	} else{
		lrMap = sequence.ReadLogRecordTxtAsMap(infile)
	}

	//Here we group by service and process
	//We lose the cross service patterns but we get better
	//within service patterns
	err_count := 0
	processed := 0
	amap := make(map[string]sequence.AnalyzerResult)
	for _, lrc := range lrMap{
		// For all the log messages, if we can't parse it, then let's add it to the
		// analyzer for pattern analysis, this requires the previous pattern file/folder
		//	to be passed in
		analyzer = sequence.NewAnalyzer()
		for _, l := range lrc.Records {
			//TODO Fix this so it doesn't scan twice or parse twice
			seq := scanMessage(scanner, l.Message)
			if _, err := parser.Parse(seq); err != nil {
				analyzer.Add(seq)
			}
		}
		analyzer.Finalize()

		for _, l := range lrc.Records {
			seq := scanMessage(scanner, l.Message)
			aseq, err := analyzer.Analyze(seq)
			if err != nil {
				log.Printf("Error analyzing: %s", l.Message)
				err_count++
			} else {
				pat := strings.TrimSpace(aseq.String())
				stat, ok := amap[pat]
				if !ok {
					stat = sequence.AnalyzerResult{}
				}
				sequence.AddExampleToAnalyzerResult(&stat, l.Message)
				stat.PatternId = sequence.GenerateIDFromPattern(pat)
				stat.ExampleCount++
				stat.Service = l.Service
				amap[pat] = stat
			}
			processed++
		}
		fmt.Printf("Processed: %d\n", processed)
	}
	anTime := time.Since(startTime)
	fmt.Printf("Analysed in: %s\n", anTime)

	var vals []int


	opatfile := sequence.OpenOutputFile("C:\\data\\pattern.txt")
	defer opatfile.Close()

	//get the threshold for including the pattern in the
	//output files
	threshold := sequence.GetThreshold(processed)

	for pat, stat := range amap {
		fmt.Fprintf(opatfile, "%s\n# %d log messages matched\n# %s\n\n", pat, stat.ExampleCount, stat.Examples[0])
	}

	ofile := sequence.OpenOutputFile(outfile)
	defer ofile.Close()

	if outformat == "yaml"{
		fmt.Fprintf(ofile, "coloss::patterndb::simple::rule:\n")
		pattern := sequence.AnalyzerResult{}
		for pat, stat := range amap {
			pattern = sequence.AnalyzerResult{stat.PatternId, pat,stat.ExampleCount, stat.Examples, stat.Service}
			//only add patterns with a certain number of examples found
			if threshold < stat.ExampleCount {
				y := syslog_ng.ConvertToYaml(pattern)
				//write to the file line by line with a tab in front.
				s := strings.Split(y,"\n")
				for _, v := range s {
					if len(v)>0{
						fmt.Fprintf(ofile, "\t%s\n", v)
					}
				}
				vals = append(vals, stat.ExampleCount)
			}
		}
	}

	if outformat == "xml"{
		fmt.Fprintf(ofile, "<?xml version='1.0' encoding='UTF-8'?>\n")
		pattDB := syslog_ng.PatternDB{Version:"4", Pubdate:time.Now().Format("2006-01-02 15:04:05")}
		pattern := sequence.AnalyzerResult{}
		//new patterns
		for pat, stat := range amap {
			pattern = sequence.AnalyzerResult{stat.PatternId, pat,stat.ExampleCount, stat.Examples, stat.Service}
			if threshold < stat.ExampleCount{
				pattDB = syslog_ng.AddToRuleset(pattern, pattDB)
				vals = append(vals, stat.ExampleCount)
			}
		}

		//write to the file
		y := syslog_ng.ConvertToXml(pattDB)
		fmt.Fprintf(ofile, "\t%s\n", y)
	}

	log.Printf("Analyzed %d messages, found %d unique patterns, %d are new. %d passed the threshold, %d messages errored, time taken: %s", processed, len(amap), len(amap), len(vals), err_count, time.Since(startTime))
}

func scanMessage(scanner *sequence.Scanner, data string) sequence.Sequence {
	var (
		seq sequence.Sequence
		err error
	)

	switch format {
	case "json":
		seq, err = scanner.ScanJson(data)

	default:
		seq, err = scanner.Scan(data)
	}

	if err != nil {
		log.Fatal(err)
	}
	return seq
}

func buildParser() *sequence.Parser {
	parser := sequence.NewParser()

	if patfile == "" {
		return parser
	}

	var files []string

	if fi, err := os.Stat(patfile); err != nil {
		log.Fatal(err)
	} else if fi.Mode().IsDir() {
		files = sequence.GetDirOfFiles(patfile)
	} else {
		files = append(files, patfile)
	}

	scanner := sequence.NewScanner()

	for _, file := range files {
		// Open pattern file
		pscan, pfile := sequence.OpenInputFile(file)

		for pscan.Scan() {
			line := pscan.Text()
			if len(line) == 0 || line[0] == '#' {
				continue
			}

			seq, err := scanner.Scan(line)
			if err != nil {
				log.Fatal(err)
			}

			if err := parser.Add(seq); err != nil {
				log.Fatal(err)
			}
		}

		pfile.Close()
	}

	return parser
}

func readConfig() {
	if cfgfile == "" {
		cfgfile = "./sequence.toml"

		if _, err := os.Stat(cfgfile); err != nil {
			if slash := strings.LastIndex(os.Args[0], "/"); slash != -1 {
				cfgfile = os.Args[0][:slash] + "/sequence.toml"

				if _, err := os.Stat(cfgfile); err != nil {
					log.Fatalln("No configuration file found")
				}
			}
		}
	}

	if err := sequence.ReadConfig(cfgfile); err != nil {
		log.Fatal(err)
	}
}

func main() {
	quit = make(chan struct{})
	done = make(chan struct{})

	var (
		sequenceCmd = &cobra.Command{
			Use:   "sequence",
			Short: "sequence is a high performance sequential log analyzer and parser",
		}

		analyzeCmd = &cobra.Command{
			Use:   "analyze",
			Short: "analyzes a log file and output a list of patterns that will match all the log messages",
		}

		analyzeByServiceCmd = &cobra.Command{
			Use:   "analyzebyservice",
			Short: "analyzes a log file and output a list of patterns that will match all the log messages",
		}
	)

	sequenceCmd.PersistentFlags().StringVarP(&cfgfile, "config", "", "", "TOML-formatted configuration file, default checks ./sequence.toml, then sequence.toml in the same directory as program")
	sequenceCmd.PersistentFlags().StringVarP(&format, "format", "", "", "format of the message to tokenize, can be 'json' or leave empty")
	sequenceCmd.PersistentFlags().StringVarP(&infile, "input", "i", "", "input file, required")
	sequenceCmd.PersistentFlags().StringVarP(&outfile, "output", "o", "", "output file, if empty, to stdout")
	sequenceCmd.PersistentFlags().StringVarP(&patfile, "patterns", "p", "", "existing patterns text file, can be a file or directory")
	sequenceCmd.PersistentFlags().StringVarP(&outformat, "out-format", "f", "", "format of the output file, can be YAML or text, if empty it uses text, used by analyze")
	sequenceCmd.PersistentFlags().StringVarP(&informat, "in-format", "k", "", "format of the input data, can be JSON or text, if empty it uses text, used by analyze")

	analyzeCmd.Run = analyze
	analyzeByServiceCmd.Run = analyzebyservice

	sequenceCmd.AddCommand(analyzeCmd)
	sequenceCmd.AddCommand(analyzeByServiceCmd)

	sequenceCmd.Execute()
}
