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
	"io"
	"strconv"
)

// Scanner is a sequential lexical analyzer that breaks a log message into a
// sequence of tokens. It is sequential because it goes through log message
// sequentially tokentizing each part of the message, without the use of regular
// expressions. The scanner currently recognizes time stamps, IPv4 addresses, URLs,
// MAC addresses, integers and floating point numbers.
//
// For example, the following message
//
//   Jan 12 06:49:42 irc sshd[7034]: Failed password for root from 218.161.81.238 port 4228 ssh2
//
// Returns the following Sequence:
//
// 	Sequence{
// 		Token{TokenTime, TagUnknown, "Jan 12 06:49:42"},
// 		Token{TokenLiteral, TagUnknown, "irc"},
// 		Token{TokenLiteral, TagUnknown, "sshd"},
// 		Token{TokenLiteral, TagUnknown, "["},
// 		Token{TokenInteger, TagUnknown, "7034"},
// 		Token{TokenLiteral, TagUnknown, "]"},
// 		Token{TokenLiteral, TagUnknown, ":"},
// 		Token{TokenLiteral, TagUnknown, "Failed"},
// 		Token{TokenLiteral, TagUnknown, "password"},
// 		Token{TokenLiteral, TagUnknown, "for"},
// 		Token{TokenLiteral, TagUnknown, "root"},
// 		Token{TokenLiteral, TagUnknown, "from"},
// 		Token{TokenIPv4, TagUnknown, "218.161.81.238"},
// 		Token{TokenLiteral, TagUnknown, "port"},
// 		Token{TokenInteger, TagUnknown, "4228"},
// 		Token{TokenLiteral, TagUnknown, "ssh2"},
// 	},
//
// The following message
//
//   id=firewall time="2005-03-18 14:01:43" fw=TOPSEC priv=4 recorder=kernel type=conn policy=504 proto=TCP rule=deny src=210.82.121.91 sport=4958 dst=61.229.37.85 dport=23124 smac=00:0b:5f:b2:1d:80 dmac=00:04:c1:8b:d8:82
//
// Will return
// 	Sequence{
// 		Token{TokenLiteral, TagUnknown, "id"},
// 		Token{TokenLiteral, TagUnknown, "="},
// 		Token{TokenLiteral, TagUnknown, "firewall"},
// 		Token{TokenLiteral, TagUnknown, "time"},
// 		Token{TokenLiteral, TagUnknown, "="},
// 		Token{TokenLiteral, TagUnknown, "\""},
// 		Token{TokenTime, TagUnknown, "2005-03-18 14:01:43"},
// 		Token{TokenLiteral, TagUnknown, "\""},
// 		Token{TokenLiteral, TagUnknown, "fw"},
// 		Token{TokenLiteral, TagUnknown, "="},
// 		Token{TokenLiteral, TagUnknown, "TOPSEC"},
// 		Token{TokenLiteral, TagUnknown, "priv"},
// 		Token{TokenLiteral, TagUnknown, "="},
// 		Token{TokenInteger, TagUnknown, "4"},
// 		Token{TokenLiteral, TagUnknown, "recorder"},
// 		Token{TokenLiteral, TagUnknown, "="},
// 		Token{TokenLiteral, TagUnknown, "kernel"},
// 		Token{TokenLiteral, TagUnknown, "type"},
// 		Token{TokenLiteral, TagUnknown, "="},
// 		Token{TokenLiteral, TagUnknown, "conn"},
// 		Token{TokenLiteral, TagUnknown, "policy"},
// 		Token{TokenLiteral, TagUnknown, "="},
// 		Token{TokenInteger, TagUnknown, "504"},
// 		Token{TokenLiteral, TagUnknown, "proto"},
// 		Token{TokenLiteral, TagUnknown, "="},
// 		Token{TokenLiteral, TagUnknown, "TCP"},
// 		Token{TokenLiteral, TagUnknown, "rule"},
// 		Token{TokenLiteral, TagUnknown, "="},
// 		Token{TokenLiteral, TagUnknown, "deny"},
// 		Token{TokenLiteral, TagUnknown, "src"},
// 		Token{TokenLiteral, TagUnknown, "="},
// 		Token{TokenIPv4, TagUnknown, "210.82.121.91"},
// 		Token{TokenLiteral, TagUnknown, "sport"},
// 		Token{TokenLiteral, TagUnknown, "="},
// 		Token{TokenInteger, TagUnknown, "4958"},
// 		Token{TokenLiteral, TagUnknown, "dst"},
// 		Token{TokenLiteral, TagUnknown, "="},
// 		Token{TokenIPv4, TagUnknown, "61.229.37.85"},
// 		Token{TokenLiteral, TagUnknown, "dport"},
// 		Token{TokenLiteral, TagUnknown, "="},
// 		Token{TokenInteger, TagUnknown, "23124"},
// 		Token{TokenLiteral, TagUnknown, "smac"},
// 		Token{TokenLiteral, TagUnknown, "="},
// 		Token{TokenMac, TagUnknown, "00:0b:5f:b2:1d:80"},
// 		Token{TokenLiteral, TagUnknown, "dmac"},
// 		Token{TokenLiteral, TagUnknown, "="},
// 		Token{TokenMac, TagUnknown, "00:04:c1:8b:d8:82"},
// 	}
type Scanner struct {
	seq Sequence
	msg *Message
}

func NewScanner() *Scanner {
	return &Scanner{
		seq: make(Sequence, 0, 20),
		msg: &Message{},
	}
}

// Scan returns a Sequence, or a list of tokens, for the data string supplied.
// Scan is not concurrent-safe, and the returned Sequence is only valid until
// the next time any Scan*() method is called. The best practice would be to
// create one Scanner for each goroutine.
func (this *Scanner) Scan(s string, isParse bool, pos []int) (Sequence, error) {
	this.msg.Data = s
	this.msg.reset()
	this.seq = this.seq[:0]

	var (
		err error
		tok Token
	)

	spaceBefore := false
	for tok, err = this.msg.Tokenize(isParse, pos); err == nil; tok, err = this.msg.Tokenize(isParse, pos) {

		//ignore space tokens but mark the token before as needing a space
		if config.markSpaces {
			if tok.Value == " " {
				spaceBefore = true
				continue
			} else {
				tok.IsSpaceBefore = spaceBefore
				spaceBefore = false
				this.insertToken(tok)
			}
		} else {
			this.insertToken(tok)
		}

		// special case for %r, or request, token in apache logs, which is comprised
		// of method, url, and protocol like "GET http://blah HTTP/1.0"
		//TODO: find the equivalent code in the parser
		if len(tok.Value) == 1 && tok.Value == "\"" && this.msg.state.inquote && this.msg.state.start != len(s) && s[this.msg.state.start] != ' ' {
			l := matchRequestMethods(s[this.msg.state.start:])
			if l > 0 {
				this.insertToken(Token{
					Tag:   TagUnknown,
					Type:  TokenLiteral,
					Value: s[this.msg.state.start : this.msg.state.start+l],
				})

				this.msg.state.inquote = false
				this.msg.state.nxquote = false
				this.msg.state.start += l
			}
		}
	}

	if err != nil && err != io.EOF {
		return nil, err
	}

	return this.seq, nil
}

const (
	jsonStart = iota
	jsonObjectStart
	jsonObjectKey
	jsonObjectColon
	jsonObjectValue
	jsonObjectEnd
	jsonArrayStart
	jsonArrayValue
	jsonArraySeparator
	jsonArrayEnd
)

// ScanJson returns a Sequence, or a list of tokens, for the json string supplied.
// Scan is not concurrent-safe, and the returned Sequence is only valid until the
// next time any Scan*() method is called. The best practice would be to create
// one Scanner for each goroutine.
//
// ScanJson flattens a json string into key=value pairs, and it performs the
// following transformation:
//   - all {, }, [, ], ", characters are removed
//   - colon between key and value are changed to "="
//   - nested objects have their keys concatenated with ".", so a json string like
//   		"userIdentity": {"type": "IAMUser"}
//     will be returned as
//   		userIdentity.type=IAMUser
//   - arrays are flattened by appending an index number to the end of the key,
//     starting with 0, so a json string like
//   		{"value":[{"open":"2014-08-16T13:00:00.000+0000"}]}
//     will be returned as
//   		value.0.open = 2014-08-16T13:00:00.000+0000
//   - skips any key that has an empty value, so json strings like
//   		"reference":""		or		"filterSet": {}
//     will not show up in the Sequence
func (this *Scanner) ScanJson(s string) (Sequence, error) {
	this.msg.Data = s
	this.msg.reset()
	this.seq = this.seq[:0]

	var (
		err error
		tok Token
		pos []int

		keys = make([]string, 0, 20) // collection keys
		arrs = make([]int64, 0, 20)  // array index

		state          = jsonStart // state
		kquote, vquote bool        // quoted key, quoted value
	)

	for tok, err = this.msg.Tokenize(false, pos); err == nil; tok, err = this.msg.Tokenize(false, pos) {
		// glog.Debugf("1. tok=%s, state=%d, kquote=%t, vquote=%t, depth=%d", tok, state, kquote, vquote, len(keys))
		// glog.Debugln(keys)
		// glog.Debugln(arrs)

		//ignore space tokens completely for now, unsure if needed to be marked for json
		if config.markSpaces && tok.Value == " " {
			continue
		}

		switch state {
		case jsonStart:
			switch tok.Value {
			case "{":
				state = jsonObjectStart
				keys = append(keys, "")

			default:
				return nil, fmt.Errorf("Invalid message. Expecting \"{\", got %q.", tok.Value)
			}

		case jsonObjectStart:
			switch tok.Value {
			case "{":
				// Only reason this could happen is if we encountered an array of
				// objects like [{"a":1}, {"b":2}]
				arrs[len(arrs)-1]++
				keys[len(keys)-1] = keys[len(keys)-2] + "." + strconv.FormatInt(arrs[len(arrs)-1], 10)
				keys = append(keys, "")

			case "\"":
				// start quote, ignore, move on
				//state = jsonObjectStart
				if kquote = !kquote; !kquote {
					return nil, fmt.Errorf("Invalid message. Expecting start quote for key, got end quote.")
				}

			case "}":
				// got something like {}, ignore this key
				if len(keys)-1 < 0 {
					return nil, fmt.Errorf("Invalid message. Too many } characters.")
				}

				keys = keys[:len(keys)-1]
				state = jsonObjectEnd

			default:
				if tok.Type == TokenLiteral {
					//glog.Debugf("depth=%d, keys=%v", len(keys), keys)
					switch len(keys) {
					case 0:
						return nil, fmt.Errorf("Invalid message. Expecting inside object, not so.")

					case 1:
						keys[0] = tok.Value

					default:
						keys[len(keys)-1] = keys[len(keys)-2] + "." + tok.Value
					}

					tok.Value = keys[len(keys)-1]
					tok.isKey = true
					tok.Type = TokenLiteral
					this.insertToken(tok)
					state = jsonObjectKey

				} else {
					return nil, fmt.Errorf("Invalid message. Expecting string key, got %q.", tok.Value)
				}
			}

		case jsonObjectKey:
			switch tok.Value {
			case "\"":
				// end quote, ignore, move on
				//state = jsonObjectKey
				if kquote = !kquote; kquote {
					return nil, fmt.Errorf("Invalid message. Expecting end quote for key, got start quote.")
				}

			case ":":
				if kquote {
					return nil, fmt.Errorf("Invalid message. Expecting end quote for key, got %q.", tok.Value)
				}

				tok.Value = "="
				this.insertToken(tok)
				state = jsonObjectColon

			default:
				return nil, fmt.Errorf("Invalid message. Expecting colon or quote, got %q.", tok.Value)
			}

		case jsonObjectColon:
			switch tok.Value {
			case "\"":
				if vquote {
					// if vquote is already true, that means we encountered something like ""
					vquote = false

					// let's remove the key and "="
					if len(this.seq) >= 2 {
						this.seq = this.seq[:len(this.seq)-2]
					}

					state = jsonObjectValue
				} else {
					// start quote, ignore, move on
					vquote = true
				}

			case "[":
				// Start of an array
				state = jsonArrayStart
				arrs = append(arrs, 0)
				keys = append(keys, keys[len(keys)-1]+"."+strconv.FormatInt(arrs[len(arrs)-1], 10))

				// let's remove the key and "="
				if len(this.seq) >= 2 {
					this.seq = this.seq[:len(this.seq)-2]
				}

			case "{":
				state = jsonObjectStart
				keys = append(keys, "")

				if len(this.seq) >= 2 {
					this.seq = this.seq[:len(this.seq)-2]
				}

			default:
				state = jsonObjectValue
				tok.isValue = true
				this.insertToken(tok)
			}

		case jsonObjectValue:
			switch tok.Value {
			case "\"":
				// end quote, ignore, move on
				//state = jsonObjectKey
				if vquote = !vquote; vquote {
					return nil, fmt.Errorf("Invalid message. Expecting end quote for value, got start quote.")
				}

			case "}":
				// End of an object
				if len(keys)-1 < 0 {
					return nil, fmt.Errorf("Invalid message. Too many } characters.")
				}

				keys = keys[:len(keys)-1]
				state = jsonObjectEnd

			case ",":
				state = jsonObjectStart

			default:
				return nil, fmt.Errorf("Invalid message. Expecting '}', ',' or '\"', got %q.", tok.Value)
			}

		case jsonObjectEnd, jsonArrayEnd:
			switch tok.Value {
			case "}":
				// End of an object
				if len(keys)-1 < 0 {
					return nil, fmt.Errorf("Invalid message. Too many } characters.")
				}

				keys = keys[:len(keys)-1]
				state = jsonObjectEnd

			case "]":
				// End of an object
				if len(arrs)-1 < 0 || len(keys)-1 < 0 {
					return nil, fmt.Errorf("Invalid message. Mismatched ']' or '}' characters.")
				}

				keys = keys[:len(keys)-1]
				arrs = arrs[:len(arrs)-1]
				state = jsonArrayEnd

			case ",":
				state = jsonObjectStart
				// state = jsonArraySeparator
				// arrs[len(arrs)-1]++
				// keys[len(keys)-2] = keys[len(keys)-3] + "." + strconv.FormatInt(arrs[len(arrs)-1], 10)

			default:
				return nil, fmt.Errorf("Invalid message. Expecting '}' or ',', got %q.", tok.Value)
			}

		case jsonArraySeparator:
			switch tok.Value {
			case "{":
				state = jsonObjectStart
				keys = append(keys, "")

			default:
				return nil, fmt.Errorf("Invalid message. Expecting '{', got %q.", tok.Value)
			}

		case jsonArrayStart:
			switch tok.Value {
			case "\"":
				// start quote, ignore, move on
				//state = jsonArrayStart
				if kquote = !kquote; !kquote {
					return nil, fmt.Errorf("Invalid message. Expecting start quote for value, got end quote.")
				}

			case "{":
				state = jsonObjectStart
				keys = append(keys, "")

			default:
				if tok.Type == TokenLiteral {
					//glog.Debugf("depth=%d, keys=%v", depth, keys)
					this.insertToken(Token{
						Tag:     TagUnknown,
						Type:    TokenLiteral,
						Value:   keys[len(keys)-1],
						isKey:   true,
						isValue: false,
					})

					this.insertToken(Token{
						Tag:     TagUnknown,
						Type:    TokenLiteral,
						Value:   "=",
						isKey:   false,
						isValue: false,
					})

					tok.Value = keys[len(keys)-1]
					tok.isValue = true
					this.insertToken(tok)
					state = jsonArrayValue

				} else {
					return nil, fmt.Errorf("Invalid message. Expecting string key, got %q.", tok.Value)
				}
			}

		case jsonArrayValue:
			switch tok.Value {
			case "\"":
				// end quote, ignore, move on
				//state = jsonObjectKey
				if vquote = !vquote; vquote {
					return nil, fmt.Errorf("Invalid message. Expecting end quote for value, got start quote.")
				}

			case "]":
				// End of an object
				if len(arrs)-1 < 0 || len(keys)-1 < 0 {
					return nil, fmt.Errorf("Invalid message. Mismatched ']' or '}' characters.")
				}

				keys = keys[:len(keys)-1]
				arrs = arrs[:len(arrs)-1]
				state = jsonArrayEnd

			case ",":
				state = jsonArrayStart
				arrs[len(arrs)-1]++
				keys[len(keys)-1] = keys[len(keys)-2] + "." + strconv.FormatInt(arrs[len(arrs)-1], 10)

			default:
				return nil, fmt.Errorf("Invalid message. Expecting ']', ',' or '\"', got %q.", tok.Value)
			}
		}
		//glog.Debugf("2. tok=%s, state=%d, kquote=%t, vquote=%t, depth=%d", tok, state, kquote, vquote, len(keys))
	}

	if err != nil && err != io.EOF {
		return nil, err
	}

	return this.seq, nil
}

//This is essentially the same function as Scan Json about but it preserves the structure of the message for text matching.
//It does not remove spaces, commas or brackets.
func (this *Scanner) ScanJson_Preserve(s string) (Sequence, error) {
	var (
		err error
		tok Token
		pos []int

		keys = make([]string, 0, 20) // collection keys
		arrs = make([]int64, 0, 20)  // array index

		state          = jsonStart // state
		kquote, vquote bool        // quoted key, quoted value
	)

	this.msg.Data = s
	this.msg.reset()
	this.seq = this.seq[:0]

	spaceBefore := false
	for tok, err = this.msg.Tokenize(false, pos); err == nil; tok, err = this.msg.Tokenize(false, pos) {

		//ignore space tokens but mark the token before as needing a space
		if config.markSpaces {
			if tok.Value == " " {
				spaceBefore = true
				continue
			} else {
				tok.IsSpaceBefore = spaceBefore
				spaceBefore = false
			}
		}

		switch state {
		case jsonStart:
			switch tok.Value {
			case "{":
				state = jsonObjectStart
				keys = append(keys, "")
				this.insertToken(tok)

			default:
				return nil, fmt.Errorf("Invalid message. Expecting \"{\", got %q.", tok.Value)
			}

		case jsonObjectStart:
			switch tok.Value {
			case "{":
				// Only reason this could happen is if we encountered an array of
				// objects like [{"a":1}, {"b":2}]
				arrs[len(arrs)-1]++
				keys = append(keys, "")

			case "\"":
				// start quote, add token, move on
				this.insertToken(tok)
				if kquote = !kquote; !kquote {
					return nil, fmt.Errorf("Invalid message. Expecting start quote for key, got end quote.")
				}

			case "}":
				// got something like {}
				if len(keys)-1 < 0 {
					return nil, fmt.Errorf("Invalid message. Too many } characters.")
				}

				this.insertToken(tok)
				keys = keys[:len(keys)-1]
				state = jsonObjectEnd

			default:
				if tok.Type == TokenLiteral {
					//glog.Debugf("depth=%d, keys=%v", len(keys), keys)
					switch len(keys) {
					case 0:
						return nil, fmt.Errorf("Invalid message. Expecting inside object, not so.")

					default:
						keys[len(keys)-1] = tok.Value
					}

					tok.Value = keys[len(keys)-1]
					tok.isKey = true
					tok.Type = TokenLiteral
					tok.IsSpaceBefore = spaceBefore
					this.insertToken(tok)
					state = jsonObjectKey

				} else {
					return nil, fmt.Errorf("Invalid message. Expecting string key, got %q.", tok.Value)
				}
			}

		case jsonObjectKey:
			switch tok.Value {
			case "\"":
				// end quote
				this.insertToken(tok)
				if kquote = !kquote; kquote {
					return nil, fmt.Errorf("Invalid message. Expecting end quote for key, got start quote.")
				}

			case ":":
				if kquote {
					return nil, fmt.Errorf("Invalid message. Expecting end quote for key, got %q.", tok.Value)
				}

				this.insertToken(tok)
				state = jsonObjectColon

			default:
				return nil, fmt.Errorf("Invalid message. Expecting colon or quote, got %q.", tok.Value)
			}

		case jsonObjectColon:
			switch tok.Value {
			case "\"":
				if vquote {
					// if vquote is already true, that means we encountered something like ""
					vquote = false
					state = jsonObjectValue
				} else {
					// start quote, ignore, move on
					vquote = true
				}

			case "[":
				// Start of an array
				state = jsonArrayStart
				arrs = append(arrs, 0)

			case "{":
				state = jsonObjectStart
				keys = append(keys, "")

			default:
				state = jsonObjectValue
				tok.isValue = true
				if tok.Type == TokenLiteral{
					tok.Type = TokenString
				}
			}
			this.insertToken(tok)

		case jsonObjectValue:
			switch tok.Value {
			case "\"":
				// end quote
				this.insertToken(tok)
				if vquote = !vquote; vquote {
					return nil, fmt.Errorf("Invalid message. Expecting end quote for value, got start quote.")
				}

			case "}":
				// End of an object
				this.insertToken(tok)
				if len(keys)-1 < 0 {
					return nil, fmt.Errorf("Invalid message. Too many } characters.")
				}

				keys = keys[:len(keys)-1]
				state = jsonObjectEnd

			case ",":
				this.insertToken(tok)
				state = jsonObjectStart

			default:
				return nil, fmt.Errorf("Invalid message. Expecting '}', ',' or '\"', got %q.", tok.Value)
			}

		case jsonObjectEnd, jsonArrayEnd:
			switch tok.Value {
			case "}":
				// End of an object
				if len(keys)-1 < 0 {
					return nil, fmt.Errorf("Invalid message. Too many } characters.")
				}
				this.insertToken(tok)
				keys = keys[:len(keys)-1]
				state = jsonObjectEnd

			case "]":
				// End of an object
				if len(arrs)-1 < 0 || len(keys)-1 < 0 {
					return nil, fmt.Errorf("Invalid message. Mismatched ']' or '}' characters.")
				}

				//keys = keys[:len(keys)-1]
				arrs = arrs[:len(arrs)-1]
				state = jsonArrayEnd
				this.insertToken(tok)

			case ",":
				state = jsonObjectStart
				this.insertToken(tok)

			default:
				return nil, fmt.Errorf("Invalid message. Expecting '}' or ',', got %q.", tok.Value)
			}

		case jsonArraySeparator:
			switch tok.Value {
			case "{":
				state = jsonObjectStart
				keys = append(keys, "")

			default:
				return nil, fmt.Errorf("Invalid message. Expecting '{', got %q.", tok.Value)
			}

		case jsonArrayStart:
			switch tok.Value {
			case "\"":
				this.insertToken(tok)
				if vquote {
					// if vquote is already true, that means we encountered something like ""
					vquote = false

					state = jsonArrayValue
				} else {
					// start quote, ignore, move on
					vquote = true
				}

			case "{":
				state = jsonObjectStart
				keys = append(keys, "")
				this.insertToken(tok)

			default:
				state = jsonArrayValue
				tok.isValue = true
				if tok.Type == TokenLiteral{
					tok.Type = TokenString
				}
				this.insertToken(tok)
			}

		case jsonArrayValue:
			switch tok.Value {
			case "\"":
				// end quote, ignore, move on
				//state = jsonObjectKey
				this.insertToken(tok)
				if vquote = !vquote; vquote {
					return nil, fmt.Errorf("Invalid message. Expecting end quote for value, got start quote.")
				}

			case "]":
				// End of an object
				if len(arrs)-1 < 0 || len(keys)-1 < 0 {
					return nil, fmt.Errorf("Invalid message. Mismatched ']' or '}' characters.")
				}

				//keys = keys[:len(keys)-1]
				arrs = arrs[:len(arrs)-1]
				state = jsonArrayEnd
				this.insertToken(tok)

			case ",":
				state = jsonArrayStart
				this.insertToken(tok)
				arrs[len(arrs)-1]++

			default:
				return nil, fmt.Errorf("Invalid message. Expecting ']', ',' or '\"', got %q.", tok.Value)
			}
		}
		//glog.Debugf("2. tok=%s, state=%d, kquote=%t, vquote=%t, depth=%d", tok, state, kquote, vquote, len(keys))
	}
	if err != nil && err != io.EOF {
		return nil, err
	}

	return this.seq, nil
}

func (this *Scanner) insertToken(tok Token) {
	// For some reason this is consistently slightly faster than just append
	if len(this.seq) >= cap(this.seq) {
		this.seq = append(this.seq, tok)
	} else {
		i := len(this.seq)
		this.seq = this.seq[:i+1]
		this.seq[i] = tok
	}
}
