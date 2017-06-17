package mgkbeans

import (
	_ "fmt"
	"testing"
)

type Databag struct {
	data   string
	iv     string
	secret string
}

type Test struct {
	in  Databag
	out string
}

var tests = []Test{
	// Test case #1: Has not been tampered with.
	Test{
		Databag{
			`Ln5ERluKQKK7wpFUaLytu5+zckb/Mp/BI9iuKk92r9OSmtN5pJEsfftpjyBaJVygSNiIqjrKgxgcTUXtrgGGE6B76S84/50ZlDgZIFuLQP9GRETSSxjg4WbUluhFSJDu`,
			`HfITED5pnX8QekwAUBICUg==`,
			`HlKAvhdScnbGiU6Nnl6hQ+ZpTZ7zvb5X7KFMXs9cbhJDZ08NMx6RjsE7cxqrCaIYkS/N/ZjkKd5n7W0L586XvIFnm5OfQV8lyPZZGymINRmcd9ftlk/L5073NRP/WMW7DqVjF+Npl5fmCQBpmf/ev9NoLZuLyNdFvi180N5DaEnjAmxspzPLPpHqluuveFTSLuvdDTeuxy5jDC/ZsFODWSj0ZIcTu5WAdXLQXxm2qPgFfBwYuAM3Ym6XxSUX7XPUCzMvvWhk1ObRjx4mPtt7/LiEO+jsrntqQ5FoD13YPxVoCE2006y1sjgT4+XB/cdB8VppAmnzoKREoWMPYu6fJTg68vJuL3cBKJT0h8WDdsVasdXjDKLY4F295BDj5ve1nrmyG/PFD+0gNQZR+p+7Eg/jGYH23mNv4e68Zdmj+Pc/jlCGzM3Vs/gA4U1gwy+rsMKYvtC1NsaokjTBdRxP3oW/tR3o1k62ZO5NZGj/Fu0drkHjoAtuTt7QhTqmV+8BPkRQcVlB9X2V5ZmqCQXbD/E9E4pAU6zI/Dyu4lhSuS0Sferkn9u9JcV/t2tKPlGKSlEPczJFhSLwksGZZ/+CEknQ4vcHIss4YqAFLuvdR7CHJhi3BhjYd0Mhvhkt6S7P8m8FefZ96mFxg88w9Nz8HUKWvKQhvfIwLIUFC35ywXE=`,
		},
		`{"json_wrapper":{"HOST":"localhost","PORT":"5432","USER":"nunya","PASSWORD":"business"}}`,
	},
	// Test case #2: &Databag{data:} has been tampered with.
	Test{
		Databag{
			`xLn5ERluKQKK7wpFUaLytu5+zckb/Mp/BI9iuKk92r9OSmtN5pJEsfftpjyBaJVygSNiIqjrKgxgcTUXtrgGGE6B76S84/50ZlDgZIFuLQP9GRETSSxjg4WbUluhFSJDu`,
			`HfITED5pnX8QekwAUBICUg==`,
			`HlKAvhdScnbGiU6Nnl6hQ+ZpTZ7zvb5X7KFMXs9cbhJDZ08NMx6RjsE7cxqrCaIYkS/N/ZjkKd5n7W0L586XvIFnm5OfQV8lyPZZGymINRmcd9ftlk/L5073NRP/WMW7DqVjF+Npl5fmCQBpmf/ev9NoLZuLyNdFvi180N5DaEnjAmxspzPLPpHqluuveFTSLuvdDTeuxy5jDC/ZsFODWSj0ZIcTu5WAdXLQXxm2qPgFfBwYuAM3Ym6XxSUX7XPUCzMvvWhk1ObRjx4mPtt7/LiEO+jsrntqQ5FoD13YPxVoCE2006y1sjgT4+XB/cdB8VppAmnzoKREoWMPYu6fJTg68vJuL3cBKJT0h8WDdsVasdXjDKLY4F295BDj5ve1nrmyG/PFD+0gNQZR+p+7Eg/jGYH23mNv4e68Zdmj+Pc/jlCGzM3Vs/gA4U1gwy+rsMKYvtC1NsaokjTBdRxP3oW/tR3o1k62ZO5NZGj/Fu0drkHjoAtuTt7QhTqmV+8BPkRQcVlB9X2V5ZmqCQXbD/E9E4pAU6zI/Dyu4lhSuS0Sferkn9u9JcV/t2tKPlGKSlEPczJFhSLwksGZZ/+CEknQ4vcHIss4YqAFLuvdR7CHJhi3BhjYd0Mhvhkt6S7P8m8FefZ96mFxg88w9Nz8HUKWvKQhvfIwLIUFC35ywXE=`,
		},
		`illegal base64 data at input byte 128`,
	},
	// Test case #3: &Databag{iv:} has been tampered with.
	Test{
		Databag{
			`Ln5ERluKQKK7wpFUaLytu5+zckb/Mp/BI9iuKk92r9OSmtN5pJEsfftpjyBaJVygSNiIqjrKgxgcTUXtrgGGE6B76S84/50ZlDgZIFuLQP9GRETSSxjg4WbUluhFSJDu`,
			`xHfITED5pnX8QekwAUBICUg==`,
			`HlKAvhdScnbGiU6Nnl6hQ+ZpTZ7zvb5X7KFMXs9cbhJDZ08NMx6RjsE7cxqrCaIYkS/N/ZjkKd5n7W0L586XvIFnm5OfQV8lyPZZGymINRmcd9ftlk/L5073NRP/WMW7DqVjF+Npl5fmCQBpmf/ev9NoLZuLyNdFvi180N5DaEnjAmxspzPLPpHqluuveFTSLuvdDTeuxy5jDC/ZsFODWSj0ZIcTu5WAdXLQXxm2qPgFfBwYuAM3Ym6XxSUX7XPUCzMvvWhk1ObRjx4mPtt7/LiEO+jsrntqQ5FoD13YPxVoCE2006y1sjgT4+XB/cdB8VppAmnzoKREoWMPYu6fJTg68vJuL3cBKJT0h8WDdsVasdXjDKLY4F295BDj5ve1nrmyG/PFD+0gNQZR+p+7Eg/jGYH23mNv4e68Zdmj+Pc/jlCGzM3Vs/gA4U1gwy+rsMKYvtC1NsaokjTBdRxP3oW/tR3o1k62ZO5NZGj/Fu0drkHjoAtuTt7QhTqmV+8BPkRQcVlB9X2V5ZmqCQXbD/E9E4pAU6zI/Dyu4lhSuS0Sferkn9u9JcV/t2tKPlGKSlEPczJFhSLwksGZZ/+CEknQ4vcHIss4YqAFLuvdR7CHJhi3BhjYd0Mhvhkt6S7P8m8FefZ96mFxg88w9Nz8HUKWvKQhvfIwLIUFC35ywXE=`,
		},
		`illegal base64 data at input byte 24`,
	},
}

func TestSpill(t *testing.T) {
	for i, test := range tests {
		dbag := test.in
		beans := Beans{[]byte(dbag.secret)}
		decrypt, err := beans.Spill(dbag.data, dbag.iv)
		if err != nil {
			if err.Error() != test.out {
				t.Errorf("#%d: Exception returned %s;\n expected %s", i, err, test.out)
			}
		} else {
			if string(decrypt) != test.out {
				t.Errorf("#%d: Spill(%s)=%s;\n want %s", i, dbag.data, decrypt, test.out)
			}
		}
	}
}
