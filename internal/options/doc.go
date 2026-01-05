// Package options provides a common validation pattern for configuration types.
//
// Any Options struct can implement the [Validator] interface to provide
// validation logic that runs before the options are used:
//
//	type ScanOptions struct {
//	    Ecosystems []string
//	    Timeout    time.Duration
//	}
//
//	func (o ScanOptions) Validate() error {
//	    if o.Timeout < 0 {
//	        return errors.New("timeout must be non-negative")
//	    }
//	    return nil
//	}
//
// The [Validate] helper function handles nil-safe validation:
//
//	if err := options.Validate(opts); err != nil {
//	    return err
//	}
package options
