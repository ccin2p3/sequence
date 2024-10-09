package sequence

import (
	"bufio"
	"encoding/json"
	"strings"
)

type LogRecord struct {
	Service string `json:"service"`
	Message string `json:"message"`
}

type LogRecordCollection struct {
	Service string
	Records []LogRecord
}

// This method expects records in the format {"service": "service-name", message: "log message"}
// eg {"service":"remctld","message":"error receiving initial token: unexpected end of file"} if json or for text
// service [space] message, eg: remctld error receiving initial token: unexpected end of file.
// See Examples folder for example files.
// Returns a collection of log records.
func ReadLogRecord(fname string, format string, lr []LogRecord, batchLimit int) []LogRecord {
	iscan, ifile, err := OpenInputFile(fname)
	defer ifile.Close()
	if err != nil {
		logger.HandleFatal(err.Error())
	}
	var r LogRecord
	var count = 0
	for iscan.Scan() {
		message := iscan.Text()
		if len(message) == 0 {
			break
		}
		if len(message) == 0 || message[0] == '#' {
			continue
		}
		if format == "json" {
			r = LogRecord{}
			_ = json.Unmarshal([]byte(message), &r)
			//check for an empty service and set it to none
			//TODO: Review if these should be discarded too
			if r.Service == "" {
				r.Service = "none"
			}
		} else {
			//the first field is the service, delimited by a space
			k := strings.Fields(message)
			s := k[0]
			//we need to remove the service from the remaining message
			i := len(s) + 1
			if i < len(message) {
				m := message[i:]
				r = LogRecord{Service: s, Message: m}
			}
		}
		//check for an empty message and discard
		if len(strings.TrimSpace(r.Message)) == 0 {
			continue
		}
		lr = append(lr, r)
		count++
		if batchLimit != 0 && count >= batchLimit {
			break
		}
	}
	//fmt.Printf("File loaded: %d records found\n", len(lr))
	return lr
}

// This method expects records in the format {"service": "service-name", message: "log message"}
// eg {"service":"remctld","message":"error receiving initial token: unexpected end of file"} if json or for text
// service [space] message, eg: remctld error receiving initial token: unexpected end of file.
// See Examples folder for example files.
// Returns a map.
func ReadLogRecordAsMap(iscan *bufio.Scanner, format string, smap map[string]LogRecordCollection, batchLimit int) (int, map[string]LogRecordCollection, bool) {
	var lr LogRecordCollection
	var count = 0
	var exit = false
	var r LogRecord
	for iscan.Scan() {
		message := iscan.Text()
		//
		if len(strings.TrimSpace(message)) == 0 {
			break
		}
		if strings.TrimSpace(message) == "exit" {
			exit = true
			break
		}
		if message[0] == '#' {
			continue
		}
		if format == "json" {
			r = LogRecord{}
			_ = json.Unmarshal([]byte(message), &r)
			//check for an empty service and set it to none
			//TODO: Review if these should be discarded too
			if r.Service == "" {
				r.Service = "none"
			}
		} else {
			//the first field is the service, delimited by a space
			k := strings.Fields(message)
			s := k[0]
			//we need to remove the service from the remaining message
			i := len(s) + 1
			if i < len(message) {
				m := message[i:]
				r = LogRecord{Service: s, Message: m}
			} else {
				r = LogRecord{Service: s, Message: ""}
			}
		}
		//check for an empty message and discard
		if len(strings.TrimSpace(r.Message)) == 0 {
			continue
		}
		//look for the service in the map
		if val, ok := smap[r.Service]; ok {
			val.Records = append(val.Records, r)
			smap[r.Service] = val
		} else {
			lr = LogRecordCollection{Service: r.Service}
			lr.Records = append(lr.Records, r)
			smap[r.Service] = lr
		}
		count++
		if batchLimit != 0 && count >= batchLimit {
			break
		}
	}
	return count, smap, exit
}
