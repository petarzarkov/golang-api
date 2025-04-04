package repository

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"

	"gorm.io/gorm"
)

// getStructField retrieves a field value from a struct using reflection.
// It handles pointer-to-struct inputs.
func getStructField(target any, fieldName string) (reflect.Value, error) {
	val := reflect.ValueOf(target)

	// If it's a pointer, get the element it points to
	if val.Kind() == reflect.Ptr {
		if val.IsNil() {
			return reflect.Value{}, fmt.Errorf("cannot get field '%s' from nil pointer", fieldName)
		}
		val = val.Elem()
	}

	// It must be a struct to have fields
	if val.Kind() != reflect.Struct {
		return reflect.Value{}, fmt.Errorf("target must be a struct or pointer to struct, got %T", target)
	}

	field := val.FieldByName(fieldName)
	if !field.IsValid() {
		return reflect.Value{}, fmt.Errorf("field '%s' not found in struct %s", fieldName, val.Type())
	}

	return field, nil
}

// MockRepository is a mock implementation of the repository using reflection for ID field.
// T is the type of the struct being stored (e.g., User, Product).
// The repository stores pointers to T (e.g., *User, *Product).
// T MUST have a field named "ID" of type string.
type MockRepository[T any] struct {
	data      map[string]*T // Store pointers to the struct type T
	idCounter int
	mu        sync.RWMutex
}

// T must be a struct type with a field named "ID" of type string.
func NewMockRepository[T any]() (*MockRepository[T], error) {
	// --- Upfront Validation using Reflection ---
	var zero T // Create a zero value of type T to inspect its type
	typ := reflect.TypeOf(zero)

	// If T is defined as a pointer type itself (e.g., NewMockRepository[*User]()),
	// we need the type it points to.
	// Usually, you'd call NewMockRepository[User]() and the repo stores *User.
	isPtrTypeArg := false
	if typ != nil && typ.Kind() == reflect.Ptr {
		typ = typ.Elem() // Get the type the pointer points to
		isPtrTypeArg = true
	}

	// T must represent a struct type.
	if typ == nil || typ.Kind() != reflect.Struct {
		// Constructing a helpful error message
		typeName := "nil"
		if reflect.TypeOf(zero) != nil {
			typeName = reflect.TypeOf(zero).String()
		}
		return nil, fmt.Errorf("mock repo: type argument T must be a struct type (e.g., User), got %s", typeName)
	}
	if isPtrTypeArg {
		// Discourage passing pointer types directly as T if the repo stores pointers anyway
		// Optional: Depends on how strict you want to be.
		// fmt.Printf("Warning: MockRepository created with pointer type '%s' as T. Storing as map[string]%s\n", reflect.TypeOf(zero), typ.String())
	}

	// Check for the 'ID' field
	idField, found := typ.FieldByName("ID")
	if !found {
		return nil, fmt.Errorf("mock repo: type %s must have an 'ID' field", typ.Name())
	}

	// Check if 'ID' field is of type string
	if idField.Type.Kind() != reflect.String {
		return nil, fmt.Errorf("mock repo: field 'ID' in type %s must be of type string, got %s", typ.Name(), idField.Type.Kind())
	}

	// Check if 'ID' field is exported (starts with uppercase)
	if !idField.IsExported() {
		return nil, fmt.Errorf("mock repo: field 'ID' in type %s must be exported (start with uppercase)", typ.Name())
	}
	// --- End of Upfront Validation ---

	// If checks pass, create and return the repository
	return &MockRepository[T]{
		data:      make(map[string]*T), // Store pointers *T where T is the struct type
		idCounter: 0,
	}, nil
}

func (m *MockRepository[T]) Create(entity *T) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// We can be more confident getting the field due to NewMockRepository check
	// but defensive check is still okay. Error here would indicate logic bug.
	idField, _ := getStructField(entity, "ID") // Error check less critical now

	currentID := idField.String()
	finalID := currentID

	if currentID == "" {
		// Still need CanSet check
		if !idField.CanSet() {
			// This error might still happen if T is an unexported struct type from another package,
			// even if the ID field itself is exported.
			return fmt.Errorf("mock repo create: field 'ID' cannot be set")
		}
		m.idCounter++
		finalID = fmt.Sprintf("mock-id-%d", m.idCounter)
		idField.SetString(finalID)
	}

	if _, exists := m.data[finalID]; exists {
		return fmt.Errorf("mock repo: entity with ID %s already exists", finalID)
	}
	m.data[finalID] = entity
	return nil
}

func (m *MockRepository[T]) GetByID(id string) (*T, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if entity, exists := m.data[id]; exists {
		return entity, nil
	}

	return nil, gorm.ErrRecordNotFound
}

// GetAll retrieves all entity pointers, optionally with limit and offset.
func (m *MockRepository[T]) GetAll(limit, offset int) ([]*T, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Slice for deterministic results (optional but good for tests)
	ids := make([]string, 0, len(m.data))
	for id := range m.data {
		ids = append(ids, id)
	}

	// Apply limit/offset logic
	start := max(offset, 0)
	if start >= len(ids) {
		return []*T{}, nil
	}

	end := start + limit
	if limit <= 0 || end > len(ids) {
		end = len(ids)
	}

	pagedIDs := ids[start:end]
	data := make([]*T, 0, len(pagedIDs))
	for _, id := range pagedIDs {
		data = append(data, m.data[id])
	}

	return data, nil
}

func (m *MockRepository[T]) Update(entity *T) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Assume ID field exists and is string due to constructor check
	idField, _ := getStructField(entity, "ID")
	id := idField.String()

	if id == "" {
		// Still useful to prevent updates with empty ID
		return fmt.Errorf("mock repo update: entity has empty ID field")
	}

	if _, exists := m.data[id]; exists {
		m.data[id] = entity
		return nil
	}
	return gorm.ErrRecordNotFound
}

func (m *MockRepository[T]) Delete(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.data[id]; exists {
		delete(m.data, id)
		return nil
	}
	return gorm.ErrRecordNotFound
}

// Get finds the *first* entity pointer that matches all criteria in the filter map.
// Filter keys are matched against struct field names (case-insensitive first letter).
func (m *MockRepository[T]) Get(filter map[string]any) (*T, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if len(filter) == 0 {
		return nil, errors.New("mock repo: filter cannot be empty for Get")
	}

	for _, entity := range m.data {
		entityValue := reflect.ValueOf(entity)

		// Get the struct value the pointer points to
		if entityValue.Kind() == reflect.Ptr {
			if entityValue.IsNil() {
				continue
			}
			entityValue = entityValue.Elem()
		}
		// Ensure we are checking a struct
		if entityValue.Kind() != reflect.Struct {
			continue
		}

		match := true // Assume match until proven otherwise
		for filterKey, filterValue := range filter {
			if filterKey == "" {
				continue
			}

			// Convert filter key (e.g., "email") to struct field name (e.g., "Email")
			fieldName := strings.ToUpper(string(filterKey[0])) + filterKey[1:]
			fieldValue := entityValue.FieldByName(fieldName)

			if !fieldValue.IsValid() {
				// Field doesn't exist in the struct T
				match = false
				break
			}

			// Compare the field's value with the filter value
			// Use reflect.DeepEqual for robust comparison of potentially complex types
			// fieldValue.Interface() gets the value as interface{}
			if !reflect.DeepEqual(fieldValue.Interface(), filterValue) {
				match = false
				break // Value doesn't match, move to the next entity
			}
		}

		// If all filter criteria matched for this entity
		if match {
			return entity, nil // Return the pointer *T
		}
	}

	// No entity matched all filter criteria
	return nil, gorm.ErrRecordNotFound
}

// Exists checks if at least one entity matches the filter criteria.
func (m *MockRepository[T]) Exists(filter map[string]any) (bool, error) {
	_, err := m.Get(filter)
	if err == nil {
		return true, nil // Found
	}
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return false, nil // Not found is not an error for Exists
	}
	// Propagate other errors (e.g., reflection issues from Get)
	return false, err
}
