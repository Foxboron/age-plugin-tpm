package plugin

import (
	"io"
	"log"
	"os"
)

var (
	Log *log.Logger
)

func SetLogger(w io.Writer) {
	Log = log.New(os.Stderr, "", log.Lshortfile)
}
