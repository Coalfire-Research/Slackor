package common

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestListNoArgs(t *testing.T) {
	t.Run("ls", func(t *testing.T) {
		assert := assert.New(t)
		wd, _ := os.Getwd()
		os.Chdir("testdata/find")

		l := List{}
		output, err := l.Run("", "", []string{})
		assert.NoError(err)
		for _, sub := range []string{"a.txt", "b.pem", "c.key", "subdir"} {
			assert.Contains(output, sub)
		}
		for _, sub := range []string{"d.pem"} {
			assert.NotContains(output, sub)
		}

		os.Chdir(wd)
	})
}

func TestListWithArgs(t *testing.T) {
	t.Run("ls", func(t *testing.T) {
		assert := assert.New(t)
		wd, _ := os.Getwd()
		os.Chdir("testdata/find")

		l := List{}
		output, err := l.Run("", "", []string{"subdir"})
		assert.NoError(err)
		for _, sub := range []string{"d.pem"} {
			assert.Contains(output, sub)
		}
		for _, sub := range []string{"a.txt", "b.pem", "c.key", "subdir"} {
			assert.NotContains(output, sub)
		}

		os.Chdir(wd)
	})
}
