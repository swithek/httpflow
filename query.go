package httpflow

import (
	"net/http"
)

var (
	// ErrInvalidFilterKey is returned when filter key is
	// determined to be invalid.
	ErrInvalidFilterKey = NewError(nil, http.StatusBadRequest, "invalid filter key")

	// ErrInvalidSortKey is returned when sort key is
	// determined to be invalid.
	ErrInvalidSortKey = NewError(nil, http.StatusBadRequest, "invalid sort key")
)

// Query is used to filter and retrieve bulk data from
// data stores.
type Query struct {
	// Limit specifies the total amount of data elements per page.
	Limit uint64 `schema:"count"`

	// Page specifies data batch number.
	Page uint64 `schema:"page"`

	// FilterBy specifies a column by which filtering should be done.
	// If FilterVal is empty, no filtering should be done.
	// NOTE: should be checked before use.
	FilterBy string `schema:"filter_by"`

	// FilterVal specifies a string by which rows should be searched and
	// filtered.
	FilterVal string `schema:"filter_val"`

	// SortBy specifies which column should be used for sorting.
	// NOTE: should be checked before use.
	SortBy string `schema:"sort_by"`

	// Asc specifies whether ascending sorting order should be used.
	Asc bool `schema:"asc"`
}

// Validate checks whether query field values go out the bounds of
// sanity or not.
// First parameter should be sort key checking func, second - filter key
// checking func.
func (q Query) Validate(fck, sck func(v string) error) error {
	if err := fck(q.FilterBy); err != nil {
		return err
	}

	if err := sck(q.SortBy); err != nil {
		return err
	}

	if q.Limit < 1 {
		return NewError(nil, http.StatusBadRequest, "invalid limit")
	}

	if q.Page < 1 {
		return NewError(nil, http.StatusBadRequest, "invalid page")
	}

	return nil
}
