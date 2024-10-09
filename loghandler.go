package sequence

import (
	"github.com/sirupsen/logrus"
	"os"
	"time"
)

//this log wrapper makes it easy to change logging library in one
//place if other golang logging libraries are preferred.

// Event stores messages to log later, from our standard interface
type Event struct {
	id      int
	message string
}

// StandardLogger enforces specific log message formats
type StandardLogger struct {
	*logrus.Logger
}

// NewLogger initializes the standard logger
func NewLogger(fname string, level string) *StandardLogger {
	var baseLogger = logrus.New()

	var standardLogger = &StandardLogger{baseLogger}
	if len(fname) == 0 {
		fname = "sequence.log"
	}
	file, err := os.OpenFile(fname, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	if err == nil {
		standardLogger.Out = file
	} else {
		standardLogger.HandleInfo("Failed to log to file, using default stderr")
	}

	//if set level for logging, default to info
	switch level {
	case "fatal":
		standardLogger.SetLevel(logrus.FatalLevel)
	case "error":
		standardLogger.SetLevel(logrus.ErrorLevel)
	case "debug":
		standardLogger.SetLevel(logrus.DebugLevel)
	case "trace":
		standardLogger.SetLevel(logrus.TraceLevel)
	default:
		standardLogger.SetLevel(logrus.InfoLevel)
	}

	standardLogger.Formatter = &logrus.JSONFormatter{}

	return standardLogger
}

// Declare variables to store log messages as new Events
var (
	eventGenericDebug   = Event{000, "%s"}
	eventGenericInfo    = Event{100, "%s"}
	eventAnalyzeInfo    = Event{101, "Analyzed %d messages, found %d unique patterns, %d are new, %d saved to the database. %d messages errored, Total time taken: %s, Time for analysis: %s"}
	eventOutputInfo     = Event{102, "Output %d patterns to file, the top 5 matched patterns are %s, time taken: %s"}
	eventGenericError   = Event{200, "%s"}
	eventAnalysisFailed = Event{201, "Unable to analyze: %s, Message type: %s"}
	eventDbInsertFailed = Event{301, "Failed to insert record into %s table, id: %s, reason: %s"}
	eventDbUpdateFailed = Event{302, "Failed to update record in %s table, id: %s, reason: %s"}
	eventDbSelectFailed = Event{303, "Failed to select record(s) from %s table, query: %s, reason: %s"}
	eventGenericFatal   = Event{400, "Fatal error occurred, reason: %s"}
	eventGenericPanic   = Event{500, "Panic occurred, reason: %s"}
)

func (l *StandardLogger) LogAnalysisFailed(lr LogRecord, mtype string) {
	l.WithFields(logrus.Fields{
		"id":      eventAnalysisFailed.id,
		"version": Version,
	}).Debugf(eventAnalysisFailed.message, lr.Message, mtype)
}

func (l *StandardLogger) DatabaseInsertFailed(tablename string, id string, reason string) {
	l.WithFields(logrus.Fields{
		"id":      eventDbInsertFailed.id,
		"version": Version,
	}).Errorf(eventDbInsertFailed.message, tablename, id, reason)
}

func (l *StandardLogger) DatabaseUpdateFailed(tablename string, query string, reason string) {
	l.WithFields(logrus.Fields{
		"id":      eventDbUpdateFailed.id,
		"version": Version,
	}).Errorf(eventDbUpdateFailed.message, tablename, query, reason)
}

func (l *StandardLogger) DatabaseSelectFailed(tablename string, query string, reason string) {
	l.WithFields(logrus.Fields{
		"id":      eventDbSelectFailed.id,
		"version": Version,
	}).Errorf(eventDbSelectFailed.message, tablename, query, reason)
}

func (l *StandardLogger) AnalyzeInfo(analyzedCount int, patternsCount int, new int, saved int, errCount int, totaltaken time.Duration, analysis time.Duration) {
	l.WithFields(logrus.Fields{
		"id":             eventAnalyzeInfo.id,
		"analyzed_msg":   analyzedCount,
		"analyzed_time":  float64(analysis) / float64(time.Second),
		"patterns_found": patternsCount,
		"patterns_new":   new,
		"patterns_saved": saved,
		"errored_msg":    errCount,
		"total_time":     float64(totaltaken) / float64(time.Second),
		"version":        Version,
	}).Infof(eventAnalyzeInfo.message, analyzedCount, patternsCount, new, saved, errCount, totaltaken, analysis)
}

func (l *StandardLogger) ExportPatternsInfo(outputCount int, top5 string, taken time.Duration) {
	l.WithFields(logrus.Fields{
		"id":              eventOutputInfo.id,
		"output_patterns": outputCount,
		"top_5":           top5,
		"version":         Version,
	}).Infof(eventOutputInfo.message, outputCount, top5, taken)
}

// Generic fatal level message handler
func (l *StandardLogger) HandleFatal(err string) {
	l.WithFields(logrus.Fields{
		"id":      eventGenericFatal.id,
		"version": Version,
	}).Fatalf(eventGenericFatal.message, err)
}

// Generic panic level message handler
func (l *StandardLogger) HandlePanic(err string) {
	l.WithFields(logrus.Fields{
		"id":      eventGenericPanic.id,
		"version": Version,
	}).Panicf(eventGenericPanic.message, err)
}

// Generic debug level message handler
func (l *StandardLogger) HandleInfo(message string) {
	l.WithFields(logrus.Fields{
		"id":      eventGenericInfo.id,
		"version": Version,
	}).Infof(eventGenericInfo.message, message)
}

// Generic error level message handler
func (l *StandardLogger) HandleError(message string) {
	l.WithFields(logrus.Fields{
		"id":      eventGenericError.id,
		"version": Version,
	}).Errorf(eventGenericError.message, message)
}

// Generic debug level message handler
func (l *StandardLogger) HandleDebug(message string) {
	l.WithFields(logrus.Fields{
		"id":      eventGenericDebug.id,
		"version": Version,
	}).Debugf(eventGenericDebug.message, message)
}
