package cli

import (
	scalibrlog "github.com/google/osv-scalibr/log"
)

// scalibrNullLogger implements the scalibrlog.Logger interface but discards all
// log output. This is used to silence the default logging of the OSV-Scalibr
// library when running in CLI mode, where we want to control output format.
type scalibrNullLogger struct{}

func (*scalibrNullLogger) Debug(args ...any)                 {}
func (*scalibrNullLogger) Debugf(format string, args ...any) {}
func (*scalibrNullLogger) Error(args ...any)                 {}
func (*scalibrNullLogger) Errorf(format string, args ...any) {}
func (*scalibrNullLogger) Info(args ...any)                  {}
func (*scalibrNullLogger) Infof(format string, args ...any)  {}
func (*scalibrNullLogger) Warn(args ...any)                  {}
func (*scalibrNullLogger) Warnf(format string, args ...any)  {}

func init() { scalibrlog.SetLogger(&scalibrNullLogger{}) }
