package jail

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/ChristianF88/cidrx/config"
)

type Cell struct {
	Id          int
	Description string
	BanDuration time.Duration
	Prisoners   []Prisoner
}

type Prisoner struct {
	Cidr      string
	BanStart  time.Time
	BanActive bool
}

type Jail struct {
	Cells    []Cell
	AllCidrs []string // this is used to store all ranges that are in jail
}

func (jail *Jail) RemovePrisoner(cellIdx, prisonerIdx int) {
	if cellIdx < 0 || cellIdx >= len(jail.Cells) {
		return
	}
	if prisonerIdx < 0 || prisonerIdx >= len(jail.Cells[cellIdx].Prisoners) {
		return
	}

	// Get CIDR before removal
	cidr := jail.Cells[cellIdx].Prisoners[prisonerIdx].Cidr

	// Remove the prisoner from the cell
	jail.Cells[cellIdx].Prisoners = append(
		jail.Cells[cellIdx].Prisoners[:prisonerIdx],
		jail.Cells[cellIdx].Prisoners[prisonerIdx+1:]...,
	)

	// Remove the CIDR from the AllCidrs slice
	for i, cidrInJail := range jail.AllCidrs {
		if cidrInJail == cidr {
			jail.AllCidrs = append(
				jail.AllCidrs[:i],
				jail.AllCidrs[i+1:]...,
			)
			break
		}
	}
}

func NewCell(id int, description string, banDuration time.Duration) Cell {
	return Cell{
		Id:          id,
		Description: description,
		BanDuration: banDuration,
		Prisoners:   []Prisoner{},
	}
}

func NewJail() Jail {
	return Jail{
		Cells: []Cell{
			NewCell(1, "Stage 1 Ban -> 10min", 10*time.Minute),
			NewCell(2, "Stage 2 Ban -> 4h", 4*time.Hour),
			NewCell(3, "Stage 3 Ban -> 7d", 7*24*time.Hour),
			NewCell(4, "Stage 4 Ban -> 30d", 30*24*time.Hour),
			NewCell(5, "Stage 5 Ban -> 180d", 180*24*time.Hour),
		},
		AllCidrs: []string{},
	}
}

func (jail Jail) rangeInJail(cidr string) (bool, int, int) {
	for cId, cell := range jail.Cells {
		for pId, prisoner := range cell.Prisoners {
			if prisoner.Cidr == cidr {
				return true, cId, pId
			}
		}
	}
	return false, -1, -1
}

func BanDurationIsOver(banStart time.Time, banDuration time.Duration) bool {
	return time.Since(banStart) > banDuration
}

// Fix logic from here on
func ThrowPrisonerInCell(jail *Jail, cellIndex int, prisoner Prisoner) {
	prisoner.BanStart = time.Now()
	prisoner.BanActive = true
	if cellIndex < len(jail.Cells) {
		jail.Cells[cellIndex].Prisoners = append(
			jail.Cells[cellIndex].Prisoners, prisoner,
		)
	} else {
		fmt.Printf("Cell index %d out of bounds for jail with %d cells\n", cellIndex, len(jail.Cells))
	}
}

func MovePrisonerToNextCell(jail *Jail, cellIndex int, prisonerIndex int) {

	jail.Cells[cellIndex].Prisoners[prisonerIndex].BanStart = time.Now()
	jail.Cells[cellIndex].Prisoners[prisonerIndex].BanActive = true

	// If prisoner is not the last in the cell and there is a next cell
	if cellIndex < len(jail.Cells)-1 {

		// Move the prisoner to the next cell
		jail.Cells[cellIndex+1].Prisoners = append(
			jail.Cells[cellIndex+1].Prisoners,
			jail.Cells[cellIndex].Prisoners[prisonerIndex],
		)
		// Remove the prisoner from the current cell
		jail.Cells[cellIndex].Prisoners = append(
			jail.Cells[cellIndex].Prisoners[:prisonerIndex],
			jail.Cells[cellIndex].Prisoners[prisonerIndex+1:]...,
		)
	}
}

func isSubRange(cidr1, cidr2 string) bool {
	ip1, net1, err1 := net.ParseCIDR(cidr1)
	ip2, net2, err2 := net.ParseCIDR(cidr2)
	if err1 != nil || err2 != nil {
		return false
	}
	ip1u := binary.BigEndian.Uint32(ip1.To4())
	mask1u := binary.BigEndian.Uint32(net1.Mask)
	end1u := ip1u | ^mask1u

	ip2u := binary.BigEndian.Uint32(ip2.To4())
	mask2u := binary.BigEndian.Uint32(net2.Mask)
	end2u := ip2u | ^mask2u

	return ip1u >= ip2u && end1u <= end2u
}

func (jail Jail) SubRangesInJail(cidr string) (bool, []int, []int) {
	var matchedCells []int
	var matchedPrisoners []int
	found := false

	for cellIdx, cell := range jail.Cells {
		for prisonerIdx, prisoner := range cell.Prisoners {
			if isSubRange(prisoner.Cidr, cidr) {
				matchedCells = append(matchedCells, cellIdx)
				matchedPrisoners = append(matchedPrisoners, prisonerIdx)
				found = true
			}
		}
	}
	return found, matchedCells, matchedPrisoners
}

func (Jail Jail) ParentRangeInJail(cidr string) (bool, int, int) {
	for cellIdx, cell := range Jail.Cells {
		for prisonerIdx, prisoner := range cell.Prisoners {
			if isSubRange(cidr, prisoner.Cidr) {
				return true, cellIdx, prisonerIdx
			}
		}
	}
	return false, -1, -1
}

func maxInList(list []int) int {
	if len(list) == 0 {
		return -1 // or some other default value
	}
	max := list[0]
	for _, v := range list {
		if v > max {
			max = v
		}
	}
	return max
}

func (jail *Jail) Fill(cidr string) {
	// Validate CIDR string is not empty or nil
	if cidr == "" {
		fmt.Printf("Error: Empty CIDR string provided to Fill function\n")
		return
	}

	_, _, err := net.ParseCIDR(cidr)
	if err != nil {
		fmt.Printf("error parsing CIDR %s: %v\n", cidr, err)
		return
	}

	if inJail, cellIdx, prisonerIdx := jail.rangeInJail(cidr); inJail {
		// CIDR already in jail: move prisoner only if current ban is inactive
		if !jail.Cells[cellIdx].Prisoners[prisonerIdx].BanActive {
			MovePrisonerToNextCell(jail, cellIdx, prisonerIdx)
		}

	} else if present, cellIdxs, prisonerIdxs := jail.SubRangesInJail(cidr); present {
		// Check if CIDR is a parent range to 1 or more ranges in jail
		if present {
			maxCellIdx := maxInList(cellIdxs)
			banStart := time.Now()
			banActive := true
			for i := len(cellIdxs) - 1; i >= 0; i-- {
				if cellIdxs[i] == maxCellIdx {
					banActive = banActive || jail.Cells[cellIdxs[i]].Prisoners[prisonerIdxs[i]].BanActive
					banStart = jail.Cells[cellIdxs[i]].Prisoners[prisonerIdxs[i]].BanStart
				}
				jail.RemovePrisoner(cellIdxs[i], prisonerIdxs[i])
			}
			if !banActive {
				idx := maxCellIdx
				if maxCellIdx < len(jail.Cells)-1 {
					idx = maxCellIdx + 1
				}
				ThrowPrisonerInCell(jail, idx, Prisoner{
					Cidr:      cidr,
					BanStart:  time.Now(),
					BanActive: true,
				})
			} else {
				ThrowPrisonerInCell(jail, maxCellIdx, Prisoner{
					Cidr:      cidr,
					BanStart:  banStart,
					BanActive: true,
				})
			}
			jail.AllCidrs = append(jail.AllCidrs, cidr)

		}

	} else if parent, cellIdx, prisonerIdx := jail.ParentRangeInJail(cidr); parent {
		// Check if range is a subrange to a range in jail
		if !jail.Cells[cellIdx].Prisoners[prisonerIdx].BanActive {
			MovePrisonerToNextCell(jail, cellIdx, prisonerIdx)
		}
	} else {
		// If CIDR is not in jail, add it to the first cell
		ThrowPrisonerInCell(jail, 0, Prisoner{
			Cidr:      cidr,
			BanStart:  time.Now(),
			BanActive: true,
		})
		jail.AllCidrs = append(jail.AllCidrs, cidr)
	}

}

func (jail *Jail) UpdateBanActiveStatus() {
	for i := 0; i < len(jail.Cells); i++ {
		for j := 0; j < len(jail.Cells[i].Prisoners); j++ {
			if BanDurationIsOver(jail.Cells[i].Prisoners[j].BanStart, jail.Cells[i].BanDuration) {
				jail.Cells[i].Prisoners[j].BanActive = false
			}
		}
	}
}

// this func needs to be smarter and possibly combine cidr ranges, or should this happen later?
func (jail *Jail) Update(cidrs []string) {

	jail.UpdateBanActiveStatus()

	// Write the jail to the file
	for _, cidr := range cidrs {
		jail.Fill(cidr)
	}
	err := JailToFile(*jail, config.JailFile)
	if err != nil {
		fmt.Printf("Error writing jail to file: %v\n", err)
	}
}

// retrieve active bans (cidrs) from the jail
func (jail *Jail) ListActiveBans() []string {
	cidrs := []string{}
	for _, cell := range jail.Cells {
		for _, prisoner := range cell.Prisoners {
			if prisoner.BanActive {
				cidrs = append(cidrs, prisoner.Cidr)
			}
		}
	}
	return cidrs
}
