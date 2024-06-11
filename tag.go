package aes256

import (
	"strconv"
)

// TagSize is the AES-256 GCM tag size in bytes.
const TagSize = 16

// TagSizeError indicates an invalid GCM tag size.  The integer value of the
// error is the size in bytes of the invalid tag.
type TagSizeError int

func (t TagSizeError) Error() string {
	return "aes256: invalid tag size " + strconv.Itoa(int(t))
}
