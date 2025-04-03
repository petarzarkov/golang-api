package repository

import "gorm.io/gorm"

type Repository[T any] interface {
	Create(dto *T) error
	GetByID(id string) (*T, error)
	GetAll(limit, offset int) ([]*T, error)
	Update(dto *T) error
	Delete(id string) error
	Get(filter map[string]any) (*T, error)
	Exists(filter map[string]any) (bool, error)
}

type GormRepository[T any] struct {
    db *gorm.DB
}

func NewGormRepository[T any](db *gorm.DB) *GormRepository[T] {
    return &GormRepository[T]{db: db}
}

func (r *GormRepository[T]) Create(entity *T) error {
    return r.db.Create(entity).Error
}

func (r *GormRepository[T]) Get(condition map[string]any) (*T, error) {
    var entity T
    err := r.db.Where(condition).First(&entity).Error
    if err != nil {
        return nil, err
    }
    return &entity, nil
}

func (r *GormRepository[T]) Exists(condition map[string]any) (bool, error) {
    var count int64
    err := r.db.Model(new(T)).Where(condition).Count(&count).Error
    return count > 0, err
}

func (r *GormRepository[T]) GetByID(id string) (*T, error) {
    var entity T
    if err := r.db.First(&entity, "id = ?", id).Error; err != nil {
        return nil, err
    }
    return &entity, nil
}

func (r *GormRepository[T]) GetAll(limit, offset int) ([]*T, error) {
    var entities []*T
    query := r.db.Limit(limit).Offset(offset).Find(&entities)
    return entities, query.Error
}

func (r *GormRepository[T]) Update(entity *T) error {
    return r.db.Save(entity).Error
}

func (r *GormRepository[T]) Delete(id string) error {
    return r.db.Delete(new(T), id).Error
}
