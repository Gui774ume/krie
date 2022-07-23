package events

import "bytes"

// UnmarshalString unmarshal string
func UnmarshalString(data []byte, size int) (string, error) {
	if len(data) < size {
		return "", ErrNotEnoughData
	}

	return string(bytes.SplitN(data[:size], []byte{0}, 2)[0]), nil
}
