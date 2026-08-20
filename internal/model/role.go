package model

// Role, bir hedef kümesine erişim yetkisi.
//
// S3 şemasında roles + role_targets tablolarının karşılığı.
type Role struct {
	Name string

	// Targets, bu rolün erişebildiği hedef adları.
	Targets []string
}
