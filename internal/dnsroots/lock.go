package dnsroots

import "os"

type fileLock struct {
	file *os.File
}

func (lock *fileLock) release() error {
	if lock == nil || lock.file == nil {
		return nil
	}
	unlockErr := unlockFile(lock.file)
	closeErr := lock.file.Close()
	lock.file = nil
	if unlockErr != nil {
		return unlockErr
	}
	return closeErr
}
