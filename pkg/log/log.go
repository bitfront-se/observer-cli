package log

import (
	"github.com/charmbracelet/log"
	"os"
)

var Logger *log.Logger

var DebugLevel = log.DebugLevel

func init() {
	Logger = log.NewWithOptions(os.Stderr, log.Options{
		ReportTimestamp: false,
		ReportCaller:    false,
	})
}

// Debug logs a debug message.
func Debug(msg interface{}, keyvals ...interface{}) {
	Logger.Debug(msg, keyvals...)
}

// Info logs an info message.
func Info(msg interface{}, keyvals ...interface{}) {
	if Logger.GetLevel() == DebugLevel {
		Logger.Info(msg, keyvals...)
		return
	}

	Logger.Print(msg, keyvals...)
}

// Print logs a message with no level.
func Print(msg interface{}, keyvals ...interface{}) {
	Info(msg, keyvals...)
}

// Warn logs a warning message.
func Warn(msg interface{}, keyvals ...interface{}) {
	Logger.Warn(msg, keyvals...)
}

// Error logs an error message.
func Error(msg interface{}, keyvals ...interface{}) {
	Logger.Error(msg, keyvals...)
}

// Fatal logs a fatal message and exit.
func Fatal(msg interface{}, keyvals ...interface{}) {
	Logger.Print("")
	Logger.Error(msg, keyvals...)
	os.Exit(1)
}

// Debugf logs a debug message with formatting.
func Debugf(format string, args ...interface{}) {
	Logger.Debugf(format, args...)
}

// Infof logs an info message with formatting.
func Infof(format string, args ...interface{}) {
	if Logger.GetLevel() == DebugLevel {
		Logger.Infof(format, args...)
		return
	}

	Logger.Printf(format, args...)
}

// Printf logs a message with formatting and no level.
func Printf(format string, args ...interface{}) {
	Infof(format, args...)
}

// Warnf logs a warning message with formatting.
func Warnf(format string, args ...interface{}) {
	Logger.Warnf(format, args...)
}

// Errorf logs an error message with formatting.
func Errorf(format string, args ...interface{}) {
	Logger.Errorf(format, args...)
}

// Fatalf logs a fatal message with formatting and exit.
func Fatalf(format string, args ...interface{}) {
	Logger.Print("")
	Logger.Errorf(format, args...)
	os.Exit(1)
}
