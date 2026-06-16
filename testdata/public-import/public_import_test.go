package publicimport_test

import (
	"testing"

	"github.com/calypr/arborist/pkg/arborist"
)

func TestPublicPackageCompiles(t *testing.T) {
	_ = arborist.Action{Service: "fence", Method: "read"}
	_ = arborist.Permission{Name: "read", Action: arborist.Action{Service: "fence", Method: "read"}, Constraints: arborist.Constraints{}}
	_ = arborist.ResourceOut{}
	_ = arborist.PolicyOut{}
	_ = arborist.Role{}
	_ = arborist.User{}
	_ = arborist.Client{}
	_ = arborist.Group{}
	_ = arborist.AuthRequest{}
}
