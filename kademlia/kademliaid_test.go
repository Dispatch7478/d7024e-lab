package kademlia

import (
	"testing"
)

func TestKademliaIDCalcDistance(t *testing.T) {
	t.Run("Identity", func(t *testing.T) {
		id1 := NewKademliaID("0000000000000000000000000000000000000000000000000000000000000001")

		dist := id1.CalcDistance(id1)
		expected := NewKademliaID("0000000000000000000000000000000000000000000000000000000000000000")
		if !dist.Equals(expected) {
			t.Errorf("expected d(x, x) == 0, got %s", dist)
		}
	})

	t.Run("Symmetry", func(t *testing.T) {
		id1 := NewKademliaID("0000000000000000000000000000000000000000000000000000000000000001")
		id2 := NewKademliaID("0000000000000000000000000000000000000000000000000000000000000003")

		dist12 := id1.CalcDistance(id2)
		dist21 := id2.CalcDistance(id1)

		if !dist12.Equals(dist21) {
			t.Errorf("expected d(x, y) == d(y, x)")
		}
	})

	t.Run("TriangleInequality", func(t *testing.T) {
		x := NewKademliaID("1111111100000000000000000000000000000000000000000000000000000000")
		y := NewKademliaID("2222222200000000000000000000000000000000000000000000000000000000")
		z := NewKademliaID("3333333300000000000000000000000000000000000000000000000000000000")

		dXZ := x.CalcDistance(z)
		dXY := x.CalcDistance(y)
		dYZ := y.CalcDistance(z)

		expected := dXY.CalcDistance(dYZ)
		if !dXZ.Equals(expected) {
			t.Errorf("expected d(x, z) == d(x, y) ^ d(y, z)")
		}
	})
}

func TestKademliaLess(t *testing.T) {
	idSmall := NewKademliaID("0000000000000000000000000000000000000000000000000000000000000001")
	idLarge := NewKademliaID("0000000000000000000000000000000000000000000000000000000000000002")

	t.Run("Small is less than Large", func(t *testing.T) {
		if !idSmall.Less(idLarge) {
			t.Errorf("expected idSmall < idLarge")
		}
	})

	t.Run("Large is not less than Small", func(t *testing.T) {
		if idLarge.Less(idSmall) {
			t.Errorf("expected idLarge NOT < idSmall")
		}
	})

	t.Run("Inequality for same ID", func(t *testing.T) {
		if idSmall.Less(idSmall) {
			t.Errorf("Less must return false for equal IDs")
		}
	})

	t.Run("Most significant byte determines order", func(t *testing.T) {
		// large has 0x01 in byte 0
		large := NewKademliaID("0100000000000000000000000000000000000000000000000000000000000000")
		// small has 0x00 in byte 0 and 0xff in byte 31 (value = 255)
		small := NewKademliaID("00000000000000000000000000000000000000000000000000000000000000ff")

		if !small.Less(large) {
			t.Errorf("expected %s < %s", small, large)
		}
	})
}

func TestKademliaIDEquals(t *testing.T) {
	id1 := NewKademliaID("0000000000000000000000000000000000000000000000000000000002000000")
	id2 := NewKademliaID("0000000000000000000000000000000000000000000000000000000002000000")
	idDiffFirst := NewKademliaID("ff00000000000000000000000000000000000000000000000000000002000000")
	idDiffLast := NewKademliaID("0000000000000000000000000000000000000000000000000000000002000001")

	t.Run("Identical IDs", func(t *testing.T) {
		if !id1.Equals(id2) {
			t.Errorf("expected id1 and id2 to be equal")
		}
	})

	t.Run("Different in first byte", func(t *testing.T) {
		if id1.Equals(idDiffFirst) {
			t.Errorf("expected IDs to not be equal")
		}
	})

	t.Run("Different in last byte", func(t *testing.T) {
		if id1.Equals(idDiffLast) {
			t.Errorf("expected IDs to not be equal")
		}
	})
}

func TestNewRandomKademliaID(t *testing.T) {
	id1 := NewRandomKademliaID()
	id2 := NewRandomKademliaID()

	if id1 == nil || id2 == nil {
		t.Fatalf("generated ID should not be nil")
	}
	if id1.Equals(id2) {
		t.Errorf("two consecutive random IDs should almost always not be equal")
	}
}

func TestKademliaIDString(t *testing.T) {
	hexID := "1111111122222222333333334444444455555555666666667777777788888888"
	id := NewKademliaID(hexID)
	if id.String() != hexID {
		t.Errorf("expected %s, got %s", hexID, id.String())
	}
}
