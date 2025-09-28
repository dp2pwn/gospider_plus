package logging

import (
	"io"
	"os"

	"github.com/sirupsen/logrus"
)

type Options struct {
	Debug   bool
	Verbose bool
	Quiet   bool
	Output  io.Writer
}

func Configure(logger *logrus.Logger, opts Options) {
	if logger == nil {
		return
	}
	target := opts.Output
	if target == nil {
		target = os.Stderr
	}

	if opts.Debug {
		logger.SetLevel(logrus.DebugLevel)
		logger.SetOutput(target)
		return
	}

	logger.SetLevel(logrus.InfoLevel)

	if opts.Quiet {
		logger.SetOutput(io.Discard)
		return
	}

	if opts.Verbose {
		logger.SetOutput(target)
		return
	}

	logger.SetOutput(io.Discard)
}
