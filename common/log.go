package common

import (
	"fmt"
	"path/filepath"
	"runtime"
	"strings"

	log "github.com/sirupsen/logrus"
)

func LogInit(level string) {
	log.SetFormatter(&log.TextFormatter{
		FullTimestamp: true,
		CallerPrettyfier: func(frame *runtime.Frame) (function string, file string) {
			return "", fmt.Sprintf("%s:%d", filepath.Base(frame.File), frame.Line)
		},
	})
	log.SetReportCaller(true)

	lvl, err := log.ParseLevel(strings.ToLower(level))
	if err != nil {
		lvl = log.InfoLevel
	}
	log.SetLevel(lvl)
}
