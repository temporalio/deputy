package server

// HandlerOptions holds shared configuration for all service handlers.
type HandlerOptions struct {
	// LocalMode skips remote target validation for in-process usage.
	// When true, handlers allow local filesystem paths and other
	// targets that would normally be rejected for remote servers.
	LocalMode bool
}

// DefaultHandlerOptions returns the default options for remote server mode.
func DefaultHandlerOptions() HandlerOptions {
	return HandlerOptions{
		LocalMode: false,
	}
}

// LocalHandlerOptions returns options configured for in-process/local mode.
func LocalHandlerOptions() HandlerOptions {
	return HandlerOptions{
		LocalMode: true,
	}
}
