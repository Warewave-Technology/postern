package config

import "testing"

func rolesConfig() *Config {
	return &Config{
		Roles: []RoleConfig{
			{Name: "ops", Targets: []string{"web01", "db01"}},
			{Name: "readonly", Targets: []string{"web01"}},
		},
		Users: []UserConfig{
			{Name: "yigit", OSUser: "yigit", Roles: []string{"ops", "readonly"}},
			{Name: "ayse", OSUser: "ayse", Roles: []string{"readonly"}},
			{Name: "mehmet", OSUser: "mehmet"},
		},
	}
}

func TestModelUser(t *testing.T) {
	c := rolesConfig()

	t.Run("rol adlari hedef listelerine cozuluyor", func(t *testing.T) {
		u, ok := c.ModelUser("yigit")
		if !ok {
			t.Fatal("kullanıcı bulunamadı")
		}
		if u.Name != "yigit" || u.OSUser != "yigit" {
			t.Fatalf("Name=%q OSUser=%q", u.Name, u.OSUser)
		}
		if len(u.Roles) != 2 {
			t.Fatalf("rol sayısı = %d, beklenen 2", len(u.Roles))
		}

		// Rol adı değil, rolün HEDEFLERİ taşınmalı — policy karar verirken
		// hedef listesine bakıyor.
		var targets []string
		for _, r := range u.Roles {
			targets = append(targets, r.Targets...)
		}
		for _, want := range []string{"web01", "db01"} {
			var found bool
			for _, got := range targets {
				if got == want {
					found = true
				}
			}
			if !found {
				t.Errorf("%q hedefi çözülmemiş; gelen: %v", want, targets)
			}
		}
	})

	t.Run("rolsuz kullanici", func(t *testing.T) {
		u, ok := c.ModelUser("mehmet")
		if !ok {
			t.Fatal("kullanıcı bulunamadı")
		}
		if len(u.Roles) != 0 {
			t.Errorf("rolsuz kullanıcıya rol atanmış: %v", u.Roles)
		}
	})

	t.Run("olmayan kullanici", func(t *testing.T) {
		if _, ok := c.ModelUser("boyle-biri-yok"); ok {
			t.Fatal("olmayan kullanıcı için ok=true döndü")
		}
	})
}
