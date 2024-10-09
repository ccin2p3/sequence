package sequence

import (
	"bufio"
	"compress/gzip"
	"io/ioutil"
	"os"
	"strings"
)

func getDirOfFiles(path string) ([]string, error) {
	filenames := make([]string, 0, 10)

	files, err := ioutil.ReadDir(path)
	if err != nil {
		return filenames, err
	}

	for _, f := range files {
		filenames = append(filenames, path+"/"+f.Name())
	}

	return filenames, err
}

// Opens an input file for reading.
func OpenInputFile(fname string) (*bufio.Scanner, *os.File, error) {
	var s *bufio.Scanner
	var f *os.File
	var err error
	//this determines the input is from the stdin
	if fname == "-" {
		f = os.Stdin
	} else {
		f, err = os.Open(fname)
		if err != nil {
			return s, f, err
		}
	}

	if strings.HasSuffix(fname, ".gz") {
		gunzip, err := gzip.NewReader(f)
		if err != nil {
			return s, f, err
		}

		s = bufio.NewScanner(gunzip)
	} else {
		s = bufio.NewScanner(f)
	}

	return s, f, err
}

// Opens and clears output file for writing.
func OpenOutputFile(fname string) (*os.File, error) {
	var (
		ofile *os.File
		err   error
	)

	if fname == "" {
		ofile = os.Stdout
	} else {
		// Open output file
		ofile, err = os.OpenFile(fname, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	}

	return ofile, err
}
