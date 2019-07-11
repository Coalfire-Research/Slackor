package common

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFind(t *testing.T) {
	tcs := []struct {
		name                 string
		glob                 string
		expectedSubstrings   []string
		unexpectedSubstrings []string
	}{
		{
			"empty glob",
			"",
			[]string{"No matches."},
			[]string{"a.txt", "b.pem", "c.key", "d.pem"},
		},
		{
			"*.txt glob",
			"*.txt",
			[]string{"a.txt"},
			[]string{"b.pem", "c.key", "d.pem"},
		},
		{
			"*.pem glob",
			"*.pem",
			[]string{"b.pem"},
			[]string{"a.txt", "c.key", "d.pem"},
		},
		{
			"**/*.pem glob",
			"**/*.pem",
			[]string{"b.pem", "subdir/d.pem"},
			[]string{"a.txt", "c.key"},
		},
		{
			"**/*.txt glob",
			"**/*.txt",
			[]string{"a.txt"},
			[]string{"b.pem", "c.key", "d.pem", "subdir"},
		},
		{
			"**/*.*e* glob",
			"**/*.*e*",
			[]string{"b.pem", "c.key", "subdir/d.pem"},
			[]string{"a.txt"},
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			assert := assert.New(t)
			wd, _ := os.Getwd()
			os.Chdir("testdata/find")

			f := Find{}
			output, err := f.Run("", "", []string{tc.glob})
			assert.NoError(err)
			for _, sub := range tc.expectedSubstrings {
				assert.Contains(output, sub)
			}
			for _, sub := range tc.unexpectedSubstrings {
				assert.NotContains(output, sub)
			}

			os.Chdir(wd)
		})
	}
}
