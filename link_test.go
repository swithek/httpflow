package httpflow

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewLinks(t *testing.T) {
	ll := map[LinkKey]string{LinkActivation: "link"}
	l := NewLinks(ll)
	assert.Equal(t, ll, l.ll)
}

func TestLinksPrep(t *testing.T) {
	l := Links{}

	assert.Zero(t, l.Prep(LinkActivation))

	ll := map[LinkKey]string{LinkActivation: "activ?token=%s"}
	l.ll = ll

	ls := l.Prep(LinkRecovery, "123")
	assert.Zero(t, ls)

	ls = l.Prep(LinkActivation, "123", "123")
	assert.NotEqual(t, "activ?token=123", ls)

	ls = l.Prep(LinkActivation, "123")
	assert.Equal(t, "activ?token=123", ls)
}

func TestLinksExist(t *testing.T) {
	l := Links{}
	assert.False(t, l.Exist(LinkActivation))

	ll := map[LinkKey]string{
		LinkActivation:   "activ?token=%s",
		LinkVerification: "",
	}

	l.ll = ll

	res := l.Exist(LinkActivation, LinkRecovery)
	assert.False(t, res)

	res = l.Exist(LinkActivation, LinkVerification)
	assert.False(t, res)

	res = l.Exist(LinkActivation)
	assert.True(t, res)
}
