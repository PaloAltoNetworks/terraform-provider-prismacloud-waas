package api

import (
	"errors"
	"fmt"
)

var (
	ExistConflict        = errors.New("resource already exists")
	NotFound             = errors.New("not found")
	MissingRequiredValue = errors.New("missing required value")
	InvalidValue         = errors.New("invalid value")
)

//type NotFound struct {
//	error
//}
//
//func (e *NotFound) Error() string {
//	return fmt.Sprintf("not found: %s", e.error)
//}
//
//func NewNotFound(err error) error {
//	return &NotFound{err}
//}

type VersionConflict struct {
	CurrentVersion string
	RequestVersion string
}

func (e VersionConflict) Error() string {
	return fmt.Sprintf("apiVersion conflict: current apiVersion: %q, request apiVersion: %q", e.CurrentVersion, e.RequestVersion)
}
