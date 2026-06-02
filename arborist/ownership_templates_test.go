package arborist

import (
	"database/sql"
	"testing"
)

func TestOwnershipTargetConstructors(t *testing.T) {
	template := &ownershipTemplate{Name: "gen3-program"}

	managed := newManagedOwnershipTarget(template, 42, "programs/example")
	if managed.Kind != ownershipTargetManagedResourceKind {
		t.Fatalf("expected managed target kind, got %q", managed.Kind)
	}
	if managed.ResourcePath != "/programs/example" || managed.AnchorPath != "/programs/example" || managed.PolicyPath != "/programs/example" {
		t.Fatalf("unexpected managed target paths: %#v", managed)
	}

	container := newChildContainerOwnershipTarget(template, 43, "programs/example/projects", "programs/example")
	if container.Kind != ownershipTargetChildContainerKind {
		t.Fatalf("expected child-container target kind, got %q", container.Kind)
	}
	if container.ResourcePath != "/programs/example/projects" || container.AnchorPath != "/programs/example" || container.PolicyPath != "/programs/example/projects" {
		t.Fatalf("unexpected child-container target paths: %#v", container)
	}
}

func TestMatchChildContainerTemplate(t *testing.T) {
	templates := []ownershipTemplate{
		{
			Name:              "gen3-project",
			ParentPathPattern: "^/programs/[^/]+/projects$",
			ChildContainerName: sql.NullString{
				Valid: false,
			},
		},
		{
			Name:              "gen3-program",
			ParentPathPattern: "^/programs$",
			ChildContainerName: sql.NullString{
				String: "projects",
				Valid:  true,
			},
		},
	}

	template, err := matchChildContainerTemplate(templates, "projects", "/programs")
	if err != nil {
		t.Fatalf("matchChildContainerTemplate returned error: %v", err)
	}
	if template == nil || template.Name != "gen3-program" {
		t.Fatalf("expected gen3-program template, got %#v", template)
	}

	template, err = matchChildContainerTemplate(templates, "projects", "/programs/example")
	if err != nil {
		t.Fatalf("matchChildContainerTemplate returned error: %v", err)
	}
	if template != nil {
		t.Fatalf("expected no template for non-create parent path, got %#v", template)
	}
}
