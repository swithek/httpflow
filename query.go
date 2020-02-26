package httpflow

import "net/http"

// Query is used to filter and retrieve bulk data from
// data stores.
type Query struct {
	// Count specifies the total amount of data elements per page.
	Count int

	// Page specifies data batch number.
	Page int

	// FilterBy specifies a column by which filtering should be done.
	// If FilterVal is empty, no filtering should be done.
	// NOTE: should be checked before use.
	FilterBy string

	// FilterVal specifies a string by which rows should be searched and
	// filtered.
	FilterVal string

	// SortBy specifies which column should be used for sorting.
	// NOTE: should be checked before use.
	SortBy string

	// Desc specifies whether descending sorting order should be used.
	Desc bool
}

// Validate checks whether query field values don't go out the bounds of
// sanity.
// First parameter should be sort key checking func, second - filter key
// checking func.
func (q Query) Validate(fck, sck func(v string) error) error {
	if err := fck(q.FilterBy); err != nil {
		return err
	}

	if err := sck(q.SortBy); err != nil {
		return err
	}

	if q.Count < 1 {
		return NewError(nil, http.StatusBadRequest,
			"count cannot be lower than 1")
	}

	if q.Page < 0 {
		return NewError(nil, http.StatusBadRequest,
			"page cannot be lower than 0")
	}

	return nil
}
