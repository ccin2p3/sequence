// Copyright (c) 2014 Dataence, LLC. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package sequence

import (
	"fmt"
	"github.com/BurntSushi/toml"
	"github.com/zhenjl/porter2"
	"strconv"
	"strings"
)

var (
	config struct {
		tagIDs   map[string]TagType
		tagNames []string
		tagTypes []TokenType
		//keep the spaces during tokenization
		//set to true if spacing matters for your output
		//format
		markSpaces           bool
		matchThresholdType   string
		matchThresholdValue  string
		saveThreshold        string
		inclBelThresholdRecs bool
		connectionInfo       string
		databaseType         string
		useDatabase          bool
	}

	timesettings struct {
		formats map[int][]string
		regex   map[string]string
		grok    map[string]string
	}

	keymaps struct {
		keywords map[string]TagType
		prekeys  map[string][]TagType
	}

	TagTypesCount   int
	TokenTypesCount = int(token__END__) + 1
	allTypesCount   int
	logger          *StandardLogger
)

// Reads the sequence.toml file and loads the values into a struct for use as the program runs.
func ReadConfig(file string) error {
	var configInfo struct {
		Version             string
		Tags                []string
		MarkSpaces          bool
		MatchThresholdType  string
		MatchThresholdValue string
		BelowThresholdPath  string
		SaveThreshold       string
		UseDatabase         bool
		ConnectionInfo      string
		DatabaseType        string

		Timesettings struct {
			Formats map[string][]string
			Regex   map[string]string
			Grok    map[string]string
		}

		Analyzer struct {
			Prekeys  map[string][]string
			Keywords map[string][]string
		}
	}

	if _, err := toml.DecodeFile(file, &configInfo); err != nil {
		return err
	}

	config.tagIDs = make(map[string]TagType, 30)
	config.tagNames = config.tagNames[:0]
	config.tagTypes = config.tagTypes[:0]
	config.markSpaces = configInfo.MarkSpaces
	config.matchThresholdType = configInfo.MatchThresholdType
	config.matchThresholdValue = configInfo.MatchThresholdValue
	config.saveThreshold = configInfo.SaveThreshold
	config.useDatabase = configInfo.UseDatabase
	config.connectionInfo = configInfo.ConnectionInfo
	config.databaseType = configInfo.DatabaseType

	timesettings.formats = make(map[int][]string, len(configInfo.Timesettings.Formats))
	for i, f := range configInfo.Timesettings.Formats {
		x, err := strconv.Atoi(i)
		if err == nil {
			timesettings.formats[x] = f
		}
	}

	timesettings.regex = configInfo.Timesettings.Regex
	timesettings.grok = configInfo.Timesettings.Grok

	timeFsmRoot = buildTimeFSM(timesettings.formats)

	keymaps.keywords = make(map[string]TagType, 30)
	keymaps.prekeys = make(map[string][]TagType, 30)

	var ftype TagType = 0
	config.tagIDs["funknown"] = ftype
	config.tagNames = append(config.tagNames, "funknown")
	config.tagTypes = append(config.tagTypes, TokenUnknown)
	ftype++

	for _, f := range configInfo.Tags {
		fs := strings.Split(f, ":")
		if len(fs) != 2 || fs[1] == "" {
			return fmt.Errorf("Error parsing tag %q: missing token type", f)
		}

		// tag type name, token type
		tt := name2TokenType(fs[1])
		if tt < TokenLiteral || tt > TokenString {
			return fmt.Errorf("Error parsing tag %q: invalid token type", f)
		}

		config.tagIDs[fs[0]] = ftype
		config.tagNames = append(config.tagNames, fs[0])
		config.tagTypes = append(config.tagTypes, tt)
		ftype++
	}

	for f, t := range config.tagIDs {
		predefineAnalyzerTags(f, t)
	}

	for w, list := range configInfo.Analyzer.Keywords {
		if f, ok := config.tagIDs[w]; ok {
			for _, kw := range list {
				pw := porter2.Stem(kw)
				keymaps.keywords[pw] = f
			}
		}
	}

	for w, m := range configInfo.Analyzer.Prekeys {
		for _, fw := range m {
			if f, ok := config.tagIDs[fw]; ok {
				keymaps.prekeys[w] = append(keymaps.prekeys[w], f)
			}
		}
	}

	TagTypesCount = len(config.tagNames)
	allTypesCount = TokenTypesCount + TagTypesCount

	return nil
}

// Returns the regular expression for patterndb matching the passed time format identifier.
func GetTimeSettingsRegExValue(id string) (string, bool) {
	f, ok := timesettings.regex[id]
	return f, ok
}

// Returns the regular expression for grok matching the passed time format identifier.
func GetTimeSettingsGrokValue(id string) (string, bool) {
	f, ok := timesettings.grok[id]
	return f, ok
}

// globally sets the logging for the application
func SetLogger(log *StandardLogger) {
	logger = log
}

// Returns the flag to signal if sequence is configured to use a database or not.
func GetUseDatabase() bool {
	return config.useDatabase
}

// Returns the type of threshold to be calculated
func GetThresholdType() string {
	return config.matchThresholdType
}

// Returns the value of threshold to be calculated
func GetThresholdValue() string {
	return config.matchThresholdValue
}

func predefineAnalyzerTags(f string, t TagType) {
	switch f {
	case "regextime":
		TagRegExTime = t
	case "msgid":
		TagMsgId = t
	case "msgtime":
		TagMsgTime = t
	case "severity":
		TagSeverity = t
	case "priority":
		TagPriority = t
	case "apphost":
		TagAppHost = t
	case "appip":
		TagAppIP = t
	case "appvendor":
		TagAppVendor = t
	case "appname":
		TagAppName = t
	case "srcdomain":
		TagSrcDomain = t
	case "srczone":
		TagSrcZone = t
	case "srchost":
		TagSrcHost = t
	case "srcip":
		TagSrcIP = t
	case "srcipnat":
		TagSrcIPNAT = t
	case "srcport":
		TagSrcPort = t
	case "srcportnat":
		TagSrcPortNAT = t
	case "srcmac":
		TagSrcMac = t
	case "srcuser":
		TagSrcUser = t
	case "srcuid":
		TagSrcUid = t
	case "srcgroup":
		TagSrcGroup = t
	case "srcgid":
		TagSrcGid = t
	case "srcemail":
		TagSrcEmail = t
	case "dstdomain":
		TagDstDomain = t
	case "dstzone":
		TagDstZone = t
	case "dsthost":
		TagDstHost = t
	case "dstip":
		TagDstIP = t
	case "dstipnat":
		TagDstIPNAT = t
	case "dstport":
		TagDstPort = t
	case "dstportnat":
		TagDstPortNAT = t
	case "dstmac":
		TagDstMac = t
	case "dstuser":
		TagDstUser = t
	case "dstuid":
		TagDstUid = t
	case "dstgroup":
		TagDstGroup = t
	case "dstgid":
		TagDstGid = t
	case "dstemail":
		TagDstEmail = t
	case "protocol":
		TagProtocol = t
	case "iniface":
		TagInIface = t
	case "outiface":
		TagOutIface = t
	case "policyid":
		TagPolicyID = t
	case "sessionid":
		TagSessionID = t
	case "object":
		TagObject = t
	case "action":
		TagAction = t
	case "command":
		TagCommand = t
	case "method":
		TagMethod = t
	case "status":
		TagStatus = t
	case "reason":
		TagReason = t
	case "bytesrecv":
		TagBytesRecv = t
	case "bytessent":
		TagBytesSent = t
	case "pktsrecv":
		TagPktsRecv = t
	case "pktssent":
		TagPktsSent = t
	case "duration":
		TagDuration = t
	}
}

var (
	TagUnknown    TagType = 0
	TagRegExTime  TagType = 1 // The timestamp that has spaces and needs a regex for matching
	TagMsgId      TagType     // The message identifier
	TagMsgTime    TagType     // The timestamp that is a string with no spaces
	TagSeverity   TagType     // The severity of the event, e.g., Emergency, …
	TagPriority   TagType     // The priority of the event
	TagAppHost    TagType     // The hostname of the host where the log message is generated
	TagAppIP      TagType     // The IP address of the host where the application that generated the log message is running on.
	TagAppVendor  TagType     // The type of application that generated the log message, e.g., Cisco, ISS
	TagAppName    TagType     // The name of the application that generated the log message, e.g., asa, snort, sshd
	TagSrcDomain  TagType     // The domain name of the initiator of the event, usually a Windows domain
	TagSrcZone    TagType     // The originating zone
	TagSrcHost    TagType     // The hostname of the originator of the event or connection.
	TagSrcIP      TagType     // The IPv4 address of the originator of the event or connection.
	TagSrcIPNAT   TagType     // The natted (network address translation) IP of the originator of the event or connection.
	TagSrcPort    TagType     // The port number of the originating connection.
	TagSrcPortNAT TagType     // The natted port number of the originating connection.
	TagSrcMac     TagType     // The mac address of the host that originated the connection.
	TagSrcUser    TagType     // The user that originated the session.
	TagSrcUid     TagType     // The user id that originated the session.
	TagSrcGroup   TagType     // The group that originated the session.
	TagSrcGid     TagType     // The group id that originated the session.
	TagSrcEmail   TagType     // The originating email address
	TagDstDomain  TagType     // The domain name of the destination of the event, usually a Windows domain
	TagDstZone    TagType     // The destination zone
	TagDstHost    TagType     // The hostname of the destination of the event or connection.
	TagDstIP      TagType     // The IPv4 address of the destination of the event or connection.
	TagDstIPNAT   TagType     // The natted (network address translation) IP of the destination of the event or connection.
	TagDstPort    TagType     // The destination port number of the connection.
	TagDstPortNAT TagType     // The natted destination port number of the connection.
	TagDstMac     TagType     // The mac address of the destination host.
	TagDstUser    TagType     // The user at the destination.
	TagDstUid     TagType     // The user id that originated the session.
	TagDstGroup   TagType     // The group that originated the session.
	TagDstGid     TagType     // The group id that originated the session.
	TagDstEmail   TagType     // The destination email address
	TagProtocol   TagType     // The protocol, such as TCP, UDP, ICMP, of the connection
	TagInIface    TagType     // The incoming TagTypeerface
	TagOutIface   TagType     // The outgoing TagTypeerface
	TagPolicyID   TagType     // The policy ID
	TagSessionID  TagType     // The session or process ID
	TagObject     TagType     // The object affected.
	TagAction     TagType     // The action taken
	TagCommand    TagType     // The command executed
	TagMethod     TagType     // The method in which the action was taken, for example, public key or password for ssh
	TagStatus     TagType     // The status of the action taken
	TagReason     TagType     // The reason for the action taken or the status returned
	TagBytesRecv  TagType     // The number of bytes received
	TagBytesSent  TagType     // The number of bytes sent
	TagPktsRecv   TagType     // The number of packets received
	TagPktsSent   TagType     // The number of packets sent
	TagDuration   TagType     // The duration of the session
)
