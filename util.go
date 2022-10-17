package iris_security_util

import (
	"github.com/pelletier/go-toml"
	"log"
	"strconv"
	"strings"
	"time"
)

func GetString(tree *toml.Tree, key string, values ...string) string {
	value := tree.Get(key)
	if value != nil {
		return ParseString(value)
	} else if len(values) > 0 {
		return values[0]
	}
	return ""

}

func ParseString(value interface{}, values ...string) string {
	switch value.(type) {
	case string:
		return value.(string)
	case int64:
		return strconv.FormatInt(value.(int64), 10)
	case uint64:
		return strconv.FormatUint(value.(uint64), 10)
	case float64:
		return strconv.FormatFloat(value.(float64), "f", -1, 64)
	case bool:
		return strconv.FormatBool(value.(bool))
	case []string:
		return strings.Join(value.([]string), ",")
	case []byte:
		return string(value.([]byte))
	case time.Time:
		return StringifyTime(value.(time.Time))
	case []int64:
		numbers := make([]string, 0)
		for _, number := range value.([]int64) {
			numbers = append(numbers, strconv.FormatInt(number, 10))
		}
		return strings.Join(numbers, ",")
	case []uint64:
		numbers := make([]string, 0)
		for _, number := range value.([]uint64) {
			numbers = append(numbers, strconv.FormatUint(number, 10))
		}
		return strings.Join(numbers, ",")
	}
}

func StringifyTime(t time.Time) string {
	layout := "2006-01-02"
	return t.Format(layout)
}

func GetBool(tree *toml.Tree, key string, values ...bool) bool {
	value := tree.Get(key)
	if value != nil {
		switch value.(type) {
		case bool:
			return value.(bool)
		case string:
			value, err := strconv.ParseBool(value.(string))
			if err != nil {
				log.Println(err)
			} else {
				return value
			}
		}
	}
	if len(values) > 0 {
		return values[0]
	}
	return false
}
