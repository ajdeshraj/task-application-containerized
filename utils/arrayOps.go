package utils

func ElementInArray(ar []uint, se uint) (bool) {
    for i:= 0; i < len(ar); i++ {
        if se == ar[i] {
            return true
        }
    }
    return false
}

func ArrayIntersection(ar1, ar2 []uint) (ar3 []uint) {
    m := make(map[uint]bool)

    for _, item := range ar1 {
        m[item] = true
    }

    for _, item := range ar2 {
        if _, ok := m[item]; ok {
            ar3 = append(ar3, item)
        }
    }

    return
}
