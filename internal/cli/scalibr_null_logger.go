package cli

import (
    scalibrlog "github.com/google/osv-scalibr/log"
)

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

