package common

import (
	"errors"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCat(t *testing.T) {
	tcs := []struct {
		name          string
		filename      string
		expectedValue string
		expectedError error
	}{
		{
			"empty value",
			"",
			"",
			errors.New("open : no such file or directory"),
		},
		{
			"txt file",
			"a.txt",
			"The quick brown fox jumped over the lazy dog.\n",
			nil,
		},
		{
			"txt file in subdir",
			"subdir/b.txt",
			"Sphinx of black quartz, judge my vow.\n",
			nil,
		},
		{
			"file not found",
			"c.txt",
			"",
			errors.New("open c.txt: no such file or directory"),
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			assert := assert.New(t)
			wd, _ := os.Getwd()
			os.Chdir("testdata/cat")

			c := Cat{}
			output, err := c.Run("", "", []string{tc.filename})
			if tc.expectedError == nil {
				assert.NoError(err)
			} else {
				assert.Error(tc.expectedError, err)
			}
			assert.Equal(tc.expectedValue, output)
			os.Chdir(wd)
		})
	}
}
