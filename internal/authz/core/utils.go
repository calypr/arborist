package core

import (
	"encoding/json"
	"fmt"
	"net/url"
	"reflect"
	"regexp"
	"strings"
)

var regSlashes = regexp.MustCompile(`/+`)

func UnderscoreEncode(decoded string) string {
	encoded := decoded
	encoded = strings.ReplaceAll(encoded, "_", "_S0")
	encoded = strings.ReplaceAll(encoded, "-", "_S1")
	encoded = strings.ReplaceAll(encoded, ".", "_S2")
	encoded = strings.ReplaceAll(encoded, "~", "_S3")
	encoded = url.QueryEscape(encoded)
	encoded = strings.ReplaceAll(encoded, "%2F", "/")
	encoded = strings.ReplaceAll(encoded, "%", "__")
	return encoded
}

func UnderscoreDecode(encoded string) string {
	decoded := encoded
	decoded = strings.ReplaceAll(decoded, "_S1", "-")
	decoded = strings.ReplaceAll(decoded, "_S2", ".")
	decoded = strings.ReplaceAll(decoded, "_S3", "~")
	decoded = strings.ReplaceAll(decoded, "__", "%")
	decoded = strings.ReplaceAll(decoded, "_S0", "_")
	decoded, _ = url.QueryUnescape(decoded)
	return decoded
}

func CleanResourcePath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	return regSlashes.ReplaceAllLiteralString("/"+strings.Trim(path, "/"), "/")
}

func FormatPathForDb(path string) string {
	result := strings.TrimLeft(strings.Replace(UnderscoreEncode(path), "/", ".", -1), ".")
	return result
}

func FormatDbPath(path string) string {
	return UnderscoreDecode("/" + strings.Replace(path, ".", "/", -1))
}

// Return the list of JSON tags which are defined in this struct.
//
// **Example**
//
// ```go
//
//	type City struct {
//	    Name       string `json:"name"`
//	    Population int    `json:"population,omitempty"`
//	}
//
// c := City{"Chicago", 2700000}
// structJSONFields(c)
// // => {"name", "population,omitempty"}
// ```
func structJSONFields(x interface{}) map[string]struct{} {
	var structValue reflect.Value = reflect.ValueOf(x)
	if structValue.Kind() == reflect.Ptr {
		structValue = structValue.Elem()
	}
	var structType reflect.Type = structValue.Type()
	result := make(map[string]struct{})
	for i := 0; i < structValue.NumField(); i++ {
		field := structType.Field(i)
		jsonTag := field.Tag.Get("json")
		result[jsonTag] = struct{}{}
	}
	return result
}

// validateJSON checks that the input struct `x` has fields with JSON tags
// that exactly match the given content. If there are any fields in one and
// not the other an error is returned.
//
// Use this function to deserialize JSON when the JSON must contain exactly the
// fields specified in a given struct, by first unmarshalling some bytes to a
// `map[string]interface{}`, then calling this function on the struct in
// question and the map, and then finally assigning fields on the struct
// directly from the map.
func ValidateJSON(
	structName string,
	x interface{},
	content map[string]interface{},
	optionalFields map[string]struct{},
) error {
	if structName == "" {
		structName = reflect.ValueOf(x).Elem().Type().Name()
	}
	if optionalFields == nil {
		optionalFields = make(map[string]struct{})
	}

	expectFields := structJSONFields(x)
	// Because the fields might contain extra stuff like `omitempty`, we have
	// to clean these up to make sure it's just the tag names.
	for field := range expectFields {
		// If there's a field like `"tag,omitempty"` then delete that from
		// `expectFields`, and insert just `"tag"` back.
		split := strings.Split(field, ",")
		if len(split) > 1 {
			delete(expectFields, field)
		}
		expectFields[split[0]] = struct{}{}
	}

	// First, check that the content contains an entry for every field in the
	// input with a JSON tag.
	missingFields := []string{}
	for field := range expectFields {
		_, exists := content[field]
		_, optional := optionalFields[field]
		if !exists && !optional {
			missingFields = append(missingFields, field)
		}
	}
	if len(missingFields) > 0 {
		return MissingRequiredFields(structName, missingFields)
	}

	// Now, check that the content does not contain any unexpected fields.
	unexpectedFields := []string{}
	for field := range content {
		if _, exists := expectFields[field]; !exists {
			unexpectedFields = append(unexpectedFields, field)
		}
	}
	if len(unexpectedFields) > 0 {
		return ContainsUnexpectedFields(structName, unexpectedFields)
	}

	return nil
}

func Unmarshal(body []byte, x interface{}) *ErrorResponse {
	var structValue reflect.Value = reflect.ValueOf(x)
	if structValue.Kind() == reflect.Ptr {
		structValue = structValue.Elem()
	}
	var structType reflect.Type = structValue.Type()
	err := json.Unmarshal(body, x)
	if err != nil {
		msg := fmt.Sprintf(
			"could not parse %s from JSON; make sure input has correct types",
			structType,
		)
		response := NewErrorResponse(msg, 400, &err)
		response.Log.Info(
			"tried to create %s but input was invalid; offending JSON: %s",
			structType,
			LoggableJSON(body),
		)
		return response
	}
	return nil
}

func LoggableJSON(body []byte) []byte {
	result := make([]byte, len(body))
	for i, b := range body {
		if b >= 32 {
			result[i] = b
		} else {
			result[i] = ' '
		}
	}
	return result
}
