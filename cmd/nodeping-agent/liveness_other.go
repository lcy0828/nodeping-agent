//go:build !linux

package main

func checkLocalAgentLiveness() error {
	return nil
}
