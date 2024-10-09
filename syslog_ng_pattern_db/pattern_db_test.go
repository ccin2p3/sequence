package syslog_ng_pattern_db

import (
	"testing"

	"github.com/stretchr/testify/require"
	"gitlab.in2p3.fr/cc-in2p3-system/sequence"
)

var (
	tagtests = []struct {
		data   string
		result string
	}{
		{"%object% ", "@ESTRING:object:@"},
		{"%object%,", "@ESTRING:object:,@"},
		{"%object%:", "@ESTRING:object::@"},
		{"%object%:%string% ", "@ESTRING:object::@@ESTRING:string:@"},
		{"%srcip%,", "@IPvANY:srcip@,"},
		{"%srcip%", "@IPvANY:srcip@"},
		{"%ipv6%:", "@IPv6:ipv6@:"},
		{"%ipv6%", "@IPv6:ipv6@"},
		{"%integer% ", "@NUMBER:integer@"},
		{"%string%,%string%", "@ESTRING:string:,@@ESTRING:string1:@"},
		{"%srcmac%", "@MACADDR:srcmac@"},
		{"%dsthost% ", "@HOSTNAME:dsthost:@"},
		{"<%string%>,", "@QSTRING:string:<>@,"},
		{"\"%object%\"", "@QSTRING:object:\"@"},
	}
)

func loadConfigs() {
	file := "../sequence.toml"
	readConfig(file)
	sequence.ReadConfig(file)
}

func TestTagTransformation(t *testing.T) {
	loadConfigs()
	for _, tc := range tagtests {
		tag := replaceTags(tc.data)
		require.Equal(t, tc.result, tag, tc.data)
	}
}
