package jail

import (
	"os"
	"testing"
	"time"

	"github.com/ChristianF88/cidrx/config"
)

func TestFillJail_NewPrisoner(t *testing.T) {
	jail := NewJail()
	cidr := "192.168.1.0/24"

	jail.Fill(cidr)

	if len(jail.Cells[0].Prisoners) != 1 {
		t.Errorf("Expected 1 prisoner in the first cell, got %d", len(jail.Cells[0].Prisoners))
	}

	if jail.Cells[0].Prisoners[0].CIDR != cidr {
		t.Errorf("Expected CIDR %s, got %s", cidr, jail.Cells[0].Prisoners[0].CIDR)
	}

	if !jail.Cells[0].Prisoners[0].BanActive {
		t.Errorf("Expected BanActive to be true, got false")
	}
}

func TestFillJail_MovePrisonerToNextCell(t *testing.T) {
	jail := NewJail()
	cidr := "192.168.1.0/24"

	// Add prisoner to the first cell
	jail.Fill(cidr)

	// Simulate ban duration expiration
	jail.Cells[0].Prisoners[0].BanStart = time.Now().Add(-jail.Cells[0].BanDuration - 11*time.Minute)
	jail.Cells[0].Prisoners[0].BanActive = false

	// Move prisoner to the next cell
	jail.Fill(cidr)

	if len(jail.Cells[0].Prisoners) != 0 {
		t.Errorf("Expected 0 prisoners in the first cell, got %d", len(jail.Cells[0].Prisoners))
	}

	if len(jail.Cells[1].Prisoners) != 1 {
		t.Errorf("Expected 1 prisoner in the second cell, got %d", len(jail.Cells[1].Prisoners))
	}

	if jail.Cells[1].Prisoners[0].CIDR != cidr {
		t.Errorf("Expected CIDR %s in the second cell, got %s", cidr, jail.Cells[1].Prisoners[0].CIDR)
	}
}

func TestFillJail_RenewBanInLastCell(t *testing.T) {
	jail := NewJail()
	cidr := "192.168.1.0/24"

	// Add prisoner to the last cell
	for i := 0; i < len(jail.Cells); i++ {
		jail.Fill(cidr)
		jail.Cells[i].Prisoners[0].BanStart = time.Now().Add(-jail.Cells[i].BanDuration - time.Minute)
		jail.Cells[i].Prisoners[0].BanActive = false
	}

	jail.Fill(cidr)

	lastCellIndex := len(jail.Cells) - 1
	if len(jail.Cells[lastCellIndex].Prisoners) != 1 {
		t.Errorf("Expected 1 prisoner in the last cell, got %d", len(jail.Cells[lastCellIndex].Prisoners))
	}

	if jail.Cells[lastCellIndex].Prisoners[0].CIDR != cidr {
		t.Errorf("Expected CIDR %s in the last cell, got %s", cidr, jail.Cells[lastCellIndex].Prisoners[0].CIDR)
	}

	if !jail.Cells[lastCellIndex].Prisoners[0].BanActive {
		t.Errorf("Expected BanActive to be true in the last cell, got false")
	}
}
func TestUpdateBanActiveStatus(t *testing.T) {
	jail := NewJail()
	cidr := "192.168.1.0/24"

	// Add a prisoner to the first cell
	jail.Fill(cidr)

	// Simulate ban duration expiration
	jail.Cells[0].Prisoners[0].BanStart = time.Now().Add(-jail.Cells[0].BanDuration - time.Minute)
	jail.Cells[0].Prisoners[0].BanActive = false

	// Update ban active status
	jail.UpdateBanActiveStatus()

	if jail.Cells[0].Prisoners[0].BanActive {
		t.Errorf("Expected BanActive to be false, got true")
	}

	// Add another prisoner with an active ban
	cidr2 := "192.168.2.0/24"
	jail.Fill(cidr2)

	// Ensure the second prisoner's ban is still active
	jail.UpdateBanActiveStatus()

	if !jail.Cells[0].Prisoners[1].BanActive {
		t.Errorf("Expected BanActive to be true, got false")
	}
}
func TestInitJail_FileExists(t *testing.T) {
	// Mock the config.JailFile path
	config.JailFile = "test_jail_file.json"

	// Create a mock jail file
	mockJail := NewJail()
	mockJail.Fill(
		"192.218.1.0/24",
	)
	err := JailToFile(mockJail, config.JailFile)
	if err != nil {
		t.Fatalf("Failed to create mock jail file: %v", err)
	}
	defer os.Remove(config.JailFile) // Clean up after test

	// Verify the jail was loaded from the file
	if len(mockJail.Cells) == 0 {
		t.Errorf("Expected jail to be loaded from file, got 0 cells")
	}
}

func TestActiveBansFromJail_NoPrisoners(t *testing.T) {
	jail := NewJail()
	activeBans := jail.ListActiveBans()
	if len(activeBans) != 0 {
		t.Errorf("Expected 0 active bans, got %d", len(activeBans))
	}
}

func TestActiveBansFromJail_SingleActiveBan(t *testing.T) {
	jail := NewJail()
	cidr := "10.0.0.0/24"
	jail.Fill(cidr)
	activeBans := jail.ListActiveBans()
	if len(activeBans) != 1 {
		t.Errorf("Expected 1 active ban, got %d", len(activeBans))
	}
	if activeBans[0] != cidr {
		t.Errorf("Expected CIDR %s, got %s", cidr, activeBans[0])
	}
}

func TestActiveBansFromJail_MultipleActiveBans(t *testing.T) {
	jail := NewJail()
	cidr1 := "10.0.0.0/24"
	cidr2 := "192.168.0.0/24"
	jail.Fill(cidr1)
	jail.Fill(cidr2)
	activeBans := jail.ListActiveBans()
	if len(activeBans) != 2 {
		t.Errorf("Expected 2 active bans, got %d", len(activeBans))
	}
	found1, found2 := false, false
	for _, cidr := range activeBans {
		if cidr == cidr1 {
			found1 = true
		}
		if cidr == cidr2 {
			found2 = true
		}
	}
	if !found1 || !found2 {
		t.Errorf("Expected to find both CIDRs in active bans")
	}
}

func TestActiveBansFromJail_ExpiredBan(t *testing.T) {
	jail := NewJail()
	cidr := "172.16.0.0/16"
	jail.Fill(cidr)
	// Expire the ban
	jail.Cells[0].Prisoners[0].BanStart = time.Now().Add(-jail.Cells[0].BanDuration - time.Minute)
	jail.Cells[0].Prisoners[0].BanActive = false
	activeBans := jail.ListActiveBans()
	if len(activeBans) != 0 {
		t.Errorf("Expected 0 active bans after expiration, got %d", len(activeBans))
	}
}

func TestActiveBansFromJail_MixedActiveAndInactive(t *testing.T) {
	jail := NewJail()
	cidrActive := "8.8.8.0/24"
	cidrInactive := "8.8.4.0/24"
	jail.Fill(cidrActive)
	jail.Fill(cidrInactive)
	// Expire the second ban
	jail.Cells[0].Prisoners[1].BanStart = time.Now().Add(-jail.Cells[0].BanDuration - time.Minute)
	jail.Cells[0].Prisoners[1].BanActive = false
	activeBans := jail.ListActiveBans()
	if len(activeBans) != 1 {
		t.Errorf("Expected 1 active ban, got %d", len(activeBans))
	}
	if activeBans[0] != cidrActive {
		t.Errorf("Expected CIDR %s, got %s", cidrActive, activeBans[0])
	}
}

func TestFill_NewPrisonerAdded(t *testing.T) {
	jail := NewJail()
	cidr := "192.168.100.0/24"
	jail.Fill(cidr)
	if len(jail.Cells[0].Prisoners) != 1 {
		t.Errorf("Expected 1 prisoner in first cell, got %d", len(jail.Cells[0].Prisoners))
	}
	if jail.Cells[0].Prisoners[0].CIDR != cidr {
		t.Errorf("Expected prisoner CIDR %s, got %s", cidr, jail.Cells[0].Prisoners[0].CIDR)
	}
	if !jail.Cells[0].Prisoners[0].BanActive {
		t.Errorf("Expected BanActive true, got false")
	}
	if len(jail.AllCIDRs) != 1 || jail.AllCIDRs[0] != cidr {
		t.Errorf("Expected AllCidrs to contain %s", cidr)
	}
}

func TestFill_ExistingPrisonerBanExpired_MovesToNextCell(t *testing.T) {
	jail := NewJail()
	cidr := "10.10.10.0/24"
	jail.Fill(cidr)
	// Simulate ban expired
	jail.Cells[0].Prisoners[0].BanStart = time.Now().Add(-jail.Cells[0].BanDuration - time.Minute)
	jail.Cells[0].Prisoners[0].BanActive = false
	jail.Fill(cidr)
	if len(jail.Cells[0].Prisoners) != 0 {
		t.Errorf("Expected 0 prisoners in first cell after move, got %d", len(jail.Cells[0].Prisoners))
	}
	if len(jail.Cells[1].Prisoners) != 1 {
		t.Errorf("Expected 1 prisoner in second cell, got %d", len(jail.Cells[1].Prisoners))
	}
	if jail.Cells[1].Prisoners[0].CIDR != cidr {
		t.Errorf("Expected CIDR %s in second cell, got %s", cidr, jail.Cells[1].Prisoners[0].CIDR)
	}
}

func TestFill_InvalidCIDR_DoesNotPanic(t *testing.T) {
	jail := NewJail()
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("Fill panicked on invalid CIDR: %v", r)
		}
	}()
	err := jail.Fill("invalid-cidr")
	if err == nil {
		t.Errorf("Expected error for invalid CIDR, got nil")
	}
	// Should not add to jail
	for _, cell := range jail.Cells {
		for _, prisoner := range cell.Prisoners {
			if prisoner.CIDR == "invalid-cidr" {
				t.Errorf("Expected invalid CIDR not to be added, but found in jail")
			}
		}
	}
}

func TestIsSubRange(t *testing.T) {
	tests := []struct {
		cidr1    string
		cidr2    string
		expected bool
	}{
		// cidr1 is a subrange of cidr2
		{"192.168.1.0/25", "192.168.1.0/24", true},
		{"10.0.0.128/25", "10.0.0.0/24", true},
		{"10.0.0.0/24", "10.0.0.0/16", true},
		// cidr1 is equal to cidr2
		{"192.168.1.0/24", "192.168.1.0/24", true},
		// cidr1 is not a subrange of cidr2
		{"192.168.2.0/24", "192.168.1.0/24", false},
		{"10.0.1.0/24", "10.0.0.0/24", false},
		// cidr1 is larger than cidr2
		{"192.168.1.0/24", "192.168.1.0/25", false},
		// invalid CIDRs
		{"invalid", "192.168.1.0/24", false},
		{"192.168.1.0/24", "invalid", false},
		{"invalid", "invalid", false},
	}

	for _, tt := range tests {
		result := isSubRange(tt.cidr1, tt.cidr2)
		if result != tt.expected {
			t.Errorf("isSubRange(%q, %q) = %v; want %v", tt.cidr1, tt.cidr2, result, tt.expected)
		}
	}
}
func TestFill_AddsNewPrisonerToFirstCell(t *testing.T) {
	jail := NewJail()
	cidr := "192.0.2.0/24"
	jail.Fill(cidr)

	if len(jail.Cells[0].Prisoners) != 1 {
		t.Errorf("Expected 1 prisoner in first cell, got %d", len(jail.Cells[0].Prisoners))
	}
	if jail.Cells[0].Prisoners[0].CIDR != cidr {
		t.Errorf("Expected prisoner CIDR %s, got %s", cidr, jail.Cells[0].Prisoners[0].CIDR)
	}
	if !jail.Cells[0].Prisoners[0].BanActive {
		t.Errorf("Expected BanActive true, got false")
	}
	if len(jail.AllCIDRs) != 1 || jail.AllCIDRs[0] != cidr {
		t.Errorf("Expected AllCidrs to contain %s", cidr)
	}
}

func TestFill_DoesNotAddInvalidCIDR(t *testing.T) {
	jail := NewJail()
	err := jail.Fill("invalid-cidr")
	if err == nil {
		t.Errorf("Expected error for invalid CIDR, got nil")
	}
	for _, cell := range jail.Cells {
		for _, prisoner := range cell.Prisoners {
			if prisoner.CIDR == "invalid-cidr" {
				t.Errorf("Expected invalid CIDR not to be added, but found in jail")
			}
		}
	}
}

func TestFill_MovesPrisonerToNextCellOnRepeatOffense(t *testing.T) {
	jail := NewJail()
	cidr := "203.0.113.0/24"
	jail.Fill(cidr)
	// Simulate ban expired
	jail.Cells[0].Prisoners[0].BanStart = time.Now().Add(-jail.Cells[0].BanDuration - time.Minute)
	jail.Cells[0].Prisoners[0].BanActive = false
	jail.Fill(cidr)
	if len(jail.Cells[0].Prisoners) != 0 {
		t.Errorf("Expected 0 prisoners in first cell after move, got %d", len(jail.Cells[0].Prisoners))
	}
	if len(jail.Cells[1].Prisoners) != 1 {
		t.Errorf("Expected 1 prisoner in second cell, got %d", len(jail.Cells[1].Prisoners))
	}
	if jail.Cells[1].Prisoners[0].CIDR != cidr {
		t.Errorf("Expected CIDR %s in second cell, got %s", cidr, jail.Cells[1].Prisoners[0].CIDR)
	}
}

func TestFill_SubRangeHandling(t *testing.T) {
	jail := NewJail()
	parent := "10.0.0.0/24"
	sub := "10.0.0.128/25"
	jail.Fill(sub)
	// Simulate ban expired for sub
	jail.Cells[0].Prisoners[0].BanStart = time.Now().Add(-jail.Cells[0].BanDuration - time.Minute)
	jail.Cells[0].Prisoners[0].BanActive = false
	jail.Fill(parent)
	// Parent should be in first cell, sub should be removed
	foundParent := false
	foundSub := false
	for _, prisoner := range jail.Cells[0].Prisoners {
		if prisoner.CIDR == parent {
			foundParent = true
		}
		if prisoner.CIDR == sub {
			foundSub = true
		}
	}
	if !foundParent {
		t.Errorf("Expected parent CIDR %s in jail", parent)
	}
	if foundSub {
		t.Errorf("Expected sub CIDR %s to be removed from jail", sub)
	}
}

func TestFill_DoesNotDuplicatePrisoner(t *testing.T) {
	jail := NewJail()
	cidr := "198.51.100.0/24"
	jail.Fill(cidr)
	jail.Fill(cidr)
	count := 0
	for _, cell := range jail.Cells {
		for _, prisoner := range cell.Prisoners {
			if prisoner.CIDR == cidr {
				count++
			}
		}
	}
	if count != 1 {
		t.Errorf("Expected prisoner to appear only once, got %d", count)
	}
}

func cidrExistsInJail(jail Jail, cidr string) bool {
	for _, cell := range jail.Cells {
		for _, prisoner := range cell.Prisoners {
			if prisoner.CIDR == cidr {
				return true
			}
		}
	}
	return false
}

func findCellIndex(jail Jail, cidr string) int {
	for idx, cell := range jail.Cells {
		for _, prisoner := range cell.Prisoners {
			if prisoner.CIDR == cidr {
				return idx
			}
		}
	}
	return -1
}

func TestJail_Fill_Behaviors(t *testing.T) {
	jail := NewJail()

	parent := "10.0.0.0/24"
	sub1 := "10.0.0.0/25"
	sub2 := "10.0.0.128/25"
	unrelated := "192.168.1.0/24"

	// 1. Add subrange 1
	jail.Fill(sub1)
	if !cidrExistsInJail(jail, sub1) {
		t.Errorf("Expected %s to be added to jail", sub1)
	}

	// 2. Add subrange 2
	jail.Fill(sub2)
	if !cidrExistsInJail(jail, sub2) {
		t.Errorf("Expected %s to be added to jail", sub2)
	}

	// Simulate expired bans
	for i := range jail.Cells {
		for j := range jail.Cells[i].Prisoners {
			jail.Cells[i].Prisoners[j].BanStart = time.Now().Add(-jail.Cells[i].BanDuration - time.Minute)
			jail.Cells[i].Prisoners[j].BanActive = false
		}
	}

	// 3. Add parent -> should replace sub1 and sub2
	jail.Fill(parent)

	if !cidrExistsInJail(jail, parent) {
		t.Errorf("Expected %s to be added to jail", parent)
	}
	if cidrExistsInJail(jail, sub1) || cidrExistsInJail(jail, sub2) {
		t.Errorf("Expected subranges %s and %s to be removed from jail", sub1, sub2)
	}

	// 4. Re-add parent -> should move it to next cell
	before := findCellIndex(jail, parent)
	jail.Cells[before].Prisoners[0].BanActive = false
	jail.Fill(parent)
	after := findCellIndex(jail, parent)
	if after != before+1 {
		t.Errorf("Expected %s to move from cell %d to %d", parent, before, after)
	}

	// 5. Add a range that is subrange of parent
	jail.Fill(sub1)
	// parent should not move again
	newCell := findCellIndex(jail, parent)
	if newCell != after {
		t.Errorf("Expected %s to stay in cell %d, but moved to %d", parent, after, newCell)
	}

	// 6. Add completely unrelated range
	jail.Fill(unrelated)
	if !cidrExistsInJail(jail, unrelated) {
		t.Errorf("Expected unrelated range %s to be added to jail", unrelated)
	}
}
