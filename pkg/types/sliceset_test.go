package types

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestSliceStringSet(t *testing.T) {
	r := require.New(t)
	s := SliceSet[string]{}
	r.True(s.IsEmpty())

	s2 := s.Add("tag-1")
	r.True(s.IsEmpty())
	r.False(s2.IsEmpty())

	s2 = s2.Add("tag-2")
	r.Len(s2, 2)
	r.True(s2.Contains("tag-1"))
	r.True(s2.Contains("tag-2"))

	s2 = s2.Add("tag-2")
	r.Len(s2, 2)
	r.True(s2.Contains("tag-1"))
	r.True(s2.Contains("tag-2"))

	s2 = s2.Remove("tag-2")
	r.Len(s2, 1)
	r.True(s2.Contains("tag-1"))
	r.False(s2.Contains("tag-2"))

	s2 = s2.Remove("tag-1")
	r.True(s2.IsEmpty())
	r.Len(s2, 0)
	r.False(s2.Contains("tag-1"))
	r.False(s2.Contains("tag-2"))

	s3 := SliceSet[string]{"item"}
	s3 = s3.Remove("item")
	r.Len(s3, 0)
	r.Nil(s3)
}

func TestStringStrings(t *testing.T) {
	r := require.New(t)
	s := SliceSet[string]{}
	r.True(s.IsEmpty())

	s = s.Add("1")
	s = s.Add("2")
	s = s.Add("3")
	s = s.Add("4")

	ss := s.Strings()
	r.Equal([]string{"1", "2", "3", "4"}, ss)
}

func TestIntStrings(t *testing.T) {
	r := require.New(t)
	s := SliceSet[int]{}
	r.True(s.IsEmpty())

	s = s.Add(1)
	s = s.Add(2)
	s = s.Add(3)
	s = s.Add(4)

	ss := s.Strings()
	r.Equal([]string{"1", "2", "3", "4"}, ss)
}

func TestDistinct(t *testing.T) {
	r := require.New(t)
	a := SliceSet[int]{0, 1, 2, 3}
	b := SliceSet[int]{2, 3, 4, 5}

	ab := SliceSet[int]{0, 1}
	ba := SliceSet[int]{4, 5}

	r.Equal(ab, a.Distinct(b))
	r.Equal(ba, b.Distinct(a))
}

func TestEquals(t *testing.T) {
	r := require.New(t)
	a := SliceSet[int]{1, 2, 3}
	b := SliceSet[int]{3, 2, 1}

	r.True(a.Equals(b))
}

func TestNilSet(t *testing.T) {
	r := require.New(t)
	var a SliceSet[int]
	b := SliceSet[int]{3, 2, 1}
	r.True(a.Equals(a))
	r.True(a.IsEmpty())
	r.False(a.Equals(b))
	r.False(b.Equals(a))
	r.True(a.AddAll(b).Equals(b))
}
