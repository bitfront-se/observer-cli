package types

import "fmt"

// SliceSet is useful for _small_ (i.e. <100 items) sets of strings, for larger sets use a map[string]struct{)
type SliceSet[T comparable] []T

func NewSet[T comparable](items ...T) SliceSet[T] {
	return SliceSet[T](items)
}

func (s SliceSet[T]) IsEmpty() bool {
	return len(s) == 0
}

func (s SliceSet[T]) IndexOf(needle T) int {
	for i, s := range s {
		if s == needle {
			return i
		}
	}

	return -1
}

func (s SliceSet[T]) Contains(needle T) bool {
	if len(s) == 0 {
		return false
	}

	i := s.IndexOf(needle)
	if i == -1 {
		return false
	}

	return true
}

func (s SliceSet[T]) Add(item T) SliceSet[T] {
	if s.Contains(item) {
		return s
	}
	return append(s, item)
}

func (s SliceSet[T]) AddAll(other SliceSet[T]) SliceSet[T] {
	merged := s
	for _, v := range other {
		if !merged.Contains(v) {
			merged = merged.Add(v)
		}
	}

	return merged
}

func (s SliceSet[T]) Remove(item T) SliceSet[T] {
	i := s.IndexOf(item)
	if i == -1 {
		return s
	}

	t := s
	t[i] = t[len(t)-1]
	t = t[:len(t)-1]

	if len(t) == 0 {
		return nil
	}

	return t
}

// Distinct returns items that are not present in other set (i.e. distinct items)
func (s SliceSet[T]) Distinct(other SliceSet[T]) SliceSet[T] {
	var d SliceSet[T]
	for _, i := range s {
		if !other.Contains(i) {
			d = append(d, i)
		}
	}

	return d
}

func (s SliceSet[T]) Equals(other SliceSet[T]) bool {
	if len(s) != len(other) {
		return false
	}

	for _, v := range s {
		if !other.Contains(v) {
			return false
		}
	}

	return true
}

// Strings is a convenience function to map a set to strings
func (s SliceSet[T]) Strings() []string {
	if s == nil {
		return nil
	}

	var ss []string
	for _, i := range s {
		if x, ok := any(i).(string); ok {
			ss = append(ss, x)
		} else {
			ss = append(ss, fmt.Sprintf("%v", i))
		}
	}

	return ss
}
