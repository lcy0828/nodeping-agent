package main

import (
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

func TestAddJSONSchemaResourceDecodesDocument(t *testing.T) {
	t.Parallel()

	compiler := jsonschema.NewCompiler()
	const schemaURL = "https://example.invalid/schema.json"
	value := []byte(`{
		"$schema": "https://json-schema.org/draft/2020-12/schema",
		"type": "object",
		"required": ["ready"],
		"properties": {"ready": {"type": "boolean"}},
		"additionalProperties": false
	}`)
	if err := addJSONSchemaResource(compiler, schemaURL, value); err != nil {
		t.Fatalf("add schema resource: %v", err)
	}
	schema, err := compiler.Compile(schemaURL)
	if err != nil {
		t.Fatalf("compile schema resource: %v", err)
	}
	if err := schema.Validate(map[string]any{"ready": true}); err != nil {
		t.Fatalf("validate document: %v", err)
	}
}

func TestDecodeJSONValueRejectsTrailingDocument(t *testing.T) {
	t.Parallel()

	if _, err := decodeJSONValue([]byte(`{} {}`)); err == nil {
		t.Fatal("decodeJSONValue accepted multiple JSON values")
	}
}
