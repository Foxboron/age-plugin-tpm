package plugin

import (
	"io"
	"log"
)

var (
	Log *log.Logger
)

func SetLogger(w io.Writer) {
	Log = log.New(w, "", log.Lshortfile)
}
