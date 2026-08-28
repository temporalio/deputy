// Package aggregator declares nothing and is not documentation. Its only content
// is a blank import, which is the whole point of it: importing this package is
// what runs the imported package's initializers. Nothing imports this one, so
// those registrations never happen, which is exactly the finding check 1 exists
// to make.
package aggregator

import _ "fixture/internal/registered"
