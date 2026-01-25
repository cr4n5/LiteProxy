package logger

import (
	"strings"

	log "github.com/sirupsen/logrus"
)

func Init(level string) {
	log.SetFormatter(&log.TextFormatter{
		FullTimestamp: true,
	})
	lvl, err := log.ParseLevel(strings.ToLower(level))
	if err != nil {
		lvl = log.InfoLevel
	}
	log.SetLevel(lvl)
}
