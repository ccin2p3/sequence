package sequence

import (
	"context"
	"database/sql"
	"github.com/gofrs/uuid"
	_ "github.com/mattn/go-sqlite3"
	"github.com/volatiletech/null"
	"github.com/volatiletech/sqlboiler/boil"
	"github.com/volatiletech/sqlboiler/queries"
	"github.com/volatiletech/sqlboiler/queries/qm"
	"gitlab.in2p3.fr/cc-in2p3-system/sequence/models"
	"strconv"
	"strings"
	"time"
)

// This creates the database from the scripts in the toml file at the location and db type specified.
// SQLite3 needs cinfo and driver
// Microsoft SQL Server needs cinfo, driver, path and dbname
func CreateDatabase(cinfo string, driver string, path string, dbname string) {
	database, err := sql.Open(driver, cinfo)
	if err != nil {
		logger.HandleFatal(err.Error())
	}
	tx, err := database.Begin()
	if err != nil {
		logger.HandleFatal(err.Error())
	}
	if driver == "sqlite3" {
		s, file, err := OpenInputFile("database_scripts/sqlite3.txt")
		defer file.Close()
		for s.Scan() {
			_, err = database.Exec(s.Text())
			if err != nil {
				logger.HandleFatal(err.Error())
			}
		}
		tx.Commit()
	} else if driver == "sqlserver" {
		s, file, err := OpenInputFile("database_scripts/mssql.txt")
		defer file.Close()
		query := ""
		for s.Scan() {
			if strings.Contains(s.Text(), "GO") {
				_, err = database.Exec(query)
				query = ""
			} else {
				q := s.Text()
				q = strings.Replace(q, "%path%", path, -1)
				q = strings.Replace(q, "%databasename%", dbname, -1)
				query = query + q + "\n"
			}
			if err != nil {
				logger.HandleFatal(err.Error())
			}
		}
		tx.Commit()
	} else {
		//Not supported
	}

}

// This deletes all the patterns and related data from the database
// which have a cumulative match count below the passed threshold.
func PurgePatternsfromDatabase(threshold int64) int64 {
	database, ctx := OpenDbandSetContext()
	tx, err := database.Begin()
	if err != nil {
		logger.HandleError(err.Error())
	}
	patterns, _ := models.Patterns(models.PatternWhere.CumulativeMatchCount.LT(threshold)).All(ctx, tx)
	for _, pat := range patterns {
		pat.PatternExamples().DeleteAll(ctx, tx)
	}
	if len(patterns) > 0 {
		rowsAff, err := patterns.DeleteAll(ctx, tx)
		if err != nil {
			logger.HandleFatal(err.Error())
		}
		tx.Commit()
		return rowsAff
	}
	return 0
}

// This opens tha database for use.
func OpenDbandSetContext() (*sql.DB, context.Context) {
	// Get a handle to the SQLite database, using mattn/go-sqlite3
	db, err := sql.Open(config.databaseType, config.connectionInfo)
	if err != nil {
		logger.HandleFatal(err.Error())
	}
	// Configure SQLBoiler to use the sqlite database
	boil.SetDB(db)
	// Need to set a context for purposes I don't understand yet
	ctx := context.Background() // Dark voodoo magic, https://golang.org/pkg/context/#Background
	return db, ctx
}

// Returns all of the patterns from the database.
func getPatternsFromDatabase(db *sql.DB, ctx context.Context) map[string]string {
	pmap := make(map[string]string)
	// This pulls 'all' of the patterns from the patterns database
	patterns, err := models.Patterns().All(ctx, db)
	if err != nil {
		logger.DatabaseSelectFailed("patterns", "All", err.Error())
	}
	for _, p := range patterns {
		pmap[p.ID] = p.SequencePattern
	}
	return pmap
}

// This gets all the patterns complete with examples and service for exporting them to file.
// The pattern numbers returned are limited by the complexity score and threshold if the values are passed/configured.
func GetPatternsWithExamplesFromDatabase(db *sql.DB, ctx context.Context, complexityLevel float64, thresholdType string, thresholdValue string) (map[string]AnalyzerResult, string) {
	var (
		patterns models.PatternSlice
		err      error
		top5     string
	)
	pmap := make(map[string]AnalyzerResult)
	if thresholdValue != "0" {
		var threshold int64
		if thresholdType == "count" {
			threshold, _ = strconv.ParseInt(config.matchThresholdValue, 10, 64)
		} else {
			total := getRecordProcessed(db, ctx)
			threshold = int64(getThreshold(total, thresholdType, thresholdValue))
		}
		patterns, err = models.Patterns(models.PatternWhere.CumulativeMatchCount.GTE(threshold), qm.And(models.PatternColumns.IgnorePattern+" =?", false), qm.And(models.PatternColumns.ComplexityScore+" <=? ", complexityLevel), qm.OrderBy(models.PatternColumns.CumulativeMatchCount+" DESC")).All(ctx, db)
		if err != nil {
			logger.DatabaseSelectFailed("patterns", "Where cumulative_match_count > threshold", err.Error())
		}
	} else {
		patterns, err = models.Patterns(models.PatternWhere.ComplexityScore.LTE(complexityLevel), qm.And(models.PatternColumns.IgnorePattern+" =?", false), qm.OrderBy(models.PatternColumns.CumulativeMatchCount+" DESC")).All(ctx, db)
		if err != nil {
			logger.DatabaseSelectFailed("patterns", "No threshold", err.Error())
		}
	}

	//get the top 5 for logging
	if len(patterns) >= 5 {
		p5 := patterns[:5]
		for _, d := range p5 {
			top5 += d.ID + ", "
		}
	} else {
		for _, d := range patterns {
			top5 += d.ID + ", "
		}
	}

	for _, p := range patterns {
		ar := AnalyzerResult{PatternId: p.ID, Pattern: p.SequencePattern, DateCreated: p.DateCreated, DateLastMatched: p.DateLastMatched, ExampleCount: int(p.CumulativeMatchCount), TagPositions: p.TagPositions.String, ComplexityScore: p.ComplexityScore}
		svc, _ := p.Service().One(ctx, db)
		ar.Service.ID = svc.ID
		ar.Service.Name = svc.Name
		ar.Service.DateCreated = svc.DateCreated
		var ex models.ExampleSlice
		ex, err = p.PatternExamples().All(ctx, db)
		if err != nil {
			logger.DatabaseSelectFailed("examples", "All", err.Error())
		}
		for _, e := range ex {
			s, _ := e.Service().One(ctx, db)
			lr := LogRecord{Message: e.ExampleDetail, Service: s.Name}
			ar.Examples = append(ar.Examples, lr)
		}
		pmap[p.ID] = ar
	}
	return pmap, top5
}

// This sums the cumulative_match_count column in the pattern table
// to allow for calculation of the whether the threshold has been reached or not.
func getRecordProcessed(db *sql.DB, ctx context.Context) int {
	// Custom struct for selecting a subset of data
	type Info struct {
		MessageSum int `boil:"message_sum"`
	}

	var info Info

	err := queries.Raw("SELECT sum(cumulative_match_count) as message_sum FROM Patterns", 5).Bind(ctx, db, &info)
	if err != nil {
		logger.DatabaseSelectFailed("patterns", "sum(cumulative_match_count)", err.Error())
	}
	return info.MessageSum
}

// This is used to build the parser trie by service from the patterns for the parsing step.
func GetPatternsFromDatabaseByService(db *sql.DB, ctx context.Context, sid string) map[string]AnalyzerResult {
	pmap := make(map[string]AnalyzerResult)
	svc, err := models.Services(models.ServiceWhere.ID.EQ(sid)).One(ctx, db)
	patterns, err := models.Patterns(models.PatternWhere.ServiceID.EQ(sid)).All(ctx, db)
	if err != nil {
		logger.DatabaseSelectFailed("patterns", "Where Serviceid = "+sid, err.Error())
	}
	for _, p := range patterns {
		ar := AnalyzerResult{PatternId: p.ID, Pattern: p.SequencePattern, TagPositions: p.TagPositions.String}
		ar.Service.Name = svc.Name
		ar.Service.ID = svc.ID
		pmap[p.ID] = ar
	}
	return pmap
}

// This returns all of the current services saved to the database.
func getServicesFromDatabase(db *sql.DB, ctx context.Context) map[string]string {
	// This pulls 'all' of the services from the services table
	smap := make(map[string]string)
	services, err := models.Services().All(ctx, db)
	if err != nil {
		logger.DatabaseSelectFailed("services", "All", err.Error())
	}
	for _, p := range services {
		smap[p.ID] = p.Name
	}
	return smap
}

// This saves an individual service record to the database.
func addService(ctx context.Context, tx *sql.Tx, id string, name string) {
	var s models.Service
	s.ID = id
	s.Name = name
	s.DateCreated = time.Now()
	err := s.Insert(ctx, tx, boil.Whitelist("id", "name", "date_created"))
	if err != nil {
		logger.DatabaseInsertFailed("service", id, err.Error())
	}
}

// this save a pattern to the database, with its example patterns.
func addPattern(ctx context.Context, tx *sql.Tx, result AnalyzerResult, tr int) bool {
	if tr > result.ExampleCount {
		//do not add the pattern
		return false
	}
	tp := null.String{String: result.TagPositions, Valid: true}
	p := models.Pattern{ID: result.PatternId, ServiceID: result.Service.ID, SequencePattern: result.Pattern, DateCreated: time.Now(),
		CumulativeMatchCount: int64(result.ExampleCount), OriginalMatchCount: int64(result.ExampleCount), DateLastMatched: time.Now(), IgnorePattern: false, TagPositions: tp, ComplexityScore: result.ComplexityScore}
	err := p.Insert(ctx, tx, boil.Whitelist("id", "service_id", "sequence_pattern", "date_created", "date_last_matched", "original_match_count", "cumulative_match_count", "ignore_pattern", "tag_positions", "complexity_score"))
	if err != nil {
		logger.DatabaseInsertFailed("pattern", result.PatternId, err.Error())
		return false
	}
	for _, e := range result.Examples {
		insertExample(ctx, tx, e, result.PatternId, result.Service.ID)
	}
	return true
}

func SaveIgnoredPatterns(pattids []string) {
	db, ctx := OpenDbandSetContext()
	defer db.Close()
	for _, p := range pattids {
		ignorePattern(ctx, db, p)
	}
}

// This updates an existing pattern record and marks it to be ignored.
func ignorePattern(ctx context.Context, db *sql.DB, patternid string) {
	p, _ := models.FindPattern(ctx, db, patternid)
	p.IgnorePattern = true
	_, err := p.Update(ctx, db, boil.Infer())
	if err != nil {
		logger.DatabaseUpdateFailed("pattern", patternid, err.Error())
	}
}

// This updates an existing pattern record and updates any related examples.
func updatePattern(ctx context.Context, tx *sql.Tx, result AnalyzerResult) {
	p, _ := models.FindPattern(ctx, tx, result.PatternId)
	p.DateLastMatched = time.Now()
	p.CumulativeMatchCount += int64(result.ExampleCount)
	_, err := p.Update(ctx, tx, boil.Infer())
	if err != nil {
		logger.DatabaseUpdateFailed("pattern", result.PatternId, err.Error())
	}

	//if the example count is less than three, add the extra ones if different
	ct, _ := p.PatternExamples().Count(ctx, tx)
	if ct < 3 {
		ex, _ := p.PatternExamples().All(ctx, tx)
		for _, e := range result.Examples {
			found := false
			for _, h := range ex {
				if h.ExampleDetail == e.Message {
					found = true
					break
				}
			}
			if !found {
				insertExample(ctx, tx, e, result.PatternId, result.Service.ID)
			}
		}
	}
}

// This inserts an example record into the database.
func insertExample(ctx context.Context, tx *sql.Tx, lr LogRecord, pid string, sid string) {
	id, err := uuid.NewV4()
	if err != nil {
		logger.DatabaseInsertFailed("example", pid, err.Error())
	}
	ex := models.Example{ExampleDetail: strings.TrimRight(lr.Message, " "), PatternID: pid, ID: id.String(), ServiceID: sid}
	err = ex.Insert(ctx, tx, boil.Infer())
	if err != nil {
		logger.DatabaseInsertFailed("example", pid, err.Error())
	}
}

// This updates the patterns. services and examples in the database.
func SaveExistingToDatabase(rmap map[string]AnalyzerResult) {
	db, ctx := OpenDbandSetContext()
	defer db.Close()
	//exisitng services
	smap := getServicesFromDatabase(db, ctx)
	//services to be added to db
	nmap := make(map[string]string)
	//add the patterns and examples
	for _, result := range rmap {
		//check the services if it exists and if not append.
		_, ok := smap[result.Service.ID]
		if !ok {
			nmap[result.Service.ID] = result.Service.Name
		}
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		logger.HandleFatal("Could not start a transaction to save to the database.")
	}
	//start with the service, so not to cause a primary key violation
	for sid, m := range nmap {
		addService(ctx, tx, sid, m)
	}
	tx.Commit()

	tx, err = db.BeginTx(ctx, nil)
	if err != nil {
		logger.HandleFatal("Could not start a transaction to save to the database.")
	}
	//here we want to update the existing patterns with count and last matched
	pmap := getPatternsFromDatabase(db, ctx)
	for _, result := range rmap {
		_, found := pmap[result.PatternId]
		if found {
			updatePattern(ctx, tx, result)
		}
	}
	tx.Commit()

}

// This saves the new patterns and related data to the database
func SaveToDatabase(amap map[string]AnalyzerResult) (int, int) {
	var (
		new   = 0
		saved = 0
	)
	db, ctx := OpenDbandSetContext()
	defer db.Close()
	//exisitng services
	smap := getServicesFromDatabase(db, ctx)
	//services to be added to db
	nmap := make(map[string]string)
	//add the patterns and examples
	for _, result := range amap {
		//check the services if it exists and if not append.
		_, ok := smap[result.Service.ID]
		if !ok {
			nmap[result.Service.ID] = result.Service.Name
		}
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		logger.HandleFatal("Could not start a transaction to save to the database.")
	}
	//start with the service, so not to cause a primary key violation
	for sid, m := range nmap {
		addService(ctx, tx, sid, m)
	}
	tx.Commit()

	tx, err = db.BeginTx(ctx, nil)
	if err != nil {
		logger.HandleFatal("Could not start a transaction to save to the database.")
	}

	tr := getSaveThreshold()
	//technically we should not have any existing patterns passed to here, but just in case
	//lets check first
	pmap := getPatternsFromDatabase(db, ctx)
	for _, result := range amap {
		_, found := pmap[result.PatternId]
		if !found {
			if addPattern(ctx, tx, result, tr) {
				saved++
			}
			new++
		} else {
			updatePattern(ctx, tx, result)
		}
	}
	tx.Commit()

	return new, saved
}
