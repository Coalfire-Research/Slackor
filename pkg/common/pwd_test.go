package common

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPWD(t *testing.T) {
	tcs := []struct {
		name string
		path string
	}{
		{
			"original dir",
			"",
		},
		{
			"subdirectory",
			"subdir",
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			assert := assert.New(t)
			wd, _ := os.Getwd()
			os.Chdir(filepath.Join("testdata/cat/", tc.path))

			p := PWD{}
			output, err := p.Run("", "", []string{})
			assert.NoError(err)
			assert.Contains(output, filepath.Join("testdata/cat/", tc.path))
			os.Chdir(wd)
		})
	}
}
