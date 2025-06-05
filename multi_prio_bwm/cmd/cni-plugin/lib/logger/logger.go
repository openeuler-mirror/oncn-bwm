package logger

import (
	"io"
	"os"
	"path/filepath"

	"github.com/sirupsen/logrus"
	"gopkg.in/natefinch/lumberjack.v2"
)

const (
	logSubsys = "subsys"
)

var (
	defaultLogLevel = logrus.InfoLevel
	defaultLogFile  = "/var/run/bwm/bwm.log"

	defaultLogFormat = &logrus.TextFormatter{
		DisableColors:    true,
		DisableTimestamp: false,
	}
)

// InitializeDefaultLogger return a initialized logger
func InitializeDefaultLogger(onlyFile bool) *logrus.Logger {
	logger := logrus.New()
	logger.SetFormatter(defaultLogFormat)

	//logger.SetLevel(level)

	path, _ := filepath.Split(defaultLogFile)
	err := os.MkdirAll(path, 0o700)
	if err != nil {
		logger.Fatalf("failed to create log directory: %v", err)
	}

	logfile := &lumberjack.Logger{
		Filename:   defaultLogFile,
		MaxSize:    500, // megabytes
		MaxBackups: 3,
		MaxAge:     28,    //days
		Compress:   false, // disabled by default
	}

	if onlyFile {
		logger.SetOutput(io.Writer(logfile))
	} else {
		logger.SetOutput(io.MultiWriter(os.Stdout, logfile))
	}

	return logger
}

func SetLogLevel(log *logrus.Logger, levelStr string) {
	if level, err := logrus.ParseLevel(levelStr); err != nil {
		log.SetLevel(defaultLogLevel)
	} else {
		log.SetLevel(level)
	}
}

func NewLoggerField(log *logrus.Logger, subsys string) *logrus.Entry {
	return log.WithField(logSubsys, subsys)
}
