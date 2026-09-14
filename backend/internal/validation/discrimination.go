package validation

// Discrimination is the third claim a surfaced path carries, and the one the calibration
// report did not measure. Precision/recall ask whether a path is real; Brier and ECE ask
// whether "0.8" happens about 80% of the time. Neither asks whether the dangerous paths
// sit ABOVE the harmless ones - and that ordering is what an operator actually works
// through. A model can rank perfectly while every number it prints is wrong, or print
// honest numbers and still bury the path that matters at position forty.
//
// The measure is AUC: the probability that a randomly chosen confirmed path outranks a
// randomly chosen refuted one, with ties counted as half. 0.5 is a coin, 1.0 is perfect
// separation, below 0.5 the order is inverted. It is rank-based, so it applies equally to
// a probability (S(P)) and to a score that is not one (Priority in [0,100]).
//
// Two decisions here change the number, so they are stated:
//
//   - Partial verdicts are excluded. AUC compares two classes, and half credit is not a
//     class; calibration keeps them at 0.5 because a scoring rule can consume a fraction,
//     a ranking comparison cannot.
//   - The interval does not collapse on small samples. The Hanley-McNeil standard error
//     is exactly zero at perfect separation, so ten confirmed paths all scored above ten
//     refuted ones would be reported as AUC 1.00 ± 0.00. The separation is genuine
//     evidence - under a random ordering it happens once in ~185,000 draws - but the
//     precision of the value is not, so the error is evaluated at a half-count shrunk
//     AUC. The published AUC is never shrunk; only its interval is widened.

import (
	"math"
	"sort"
)

// minDiscriminationPerClass is the floor below which the discrimination verdict is
// withheld: the AUC and its interval are still reported, labelled "insufficient-data".
// It is per class rather than total, because thirty refuted verdicts and one confirmed
// one make an AUC that is just the rank of a single point.
const minDiscriminationPerClass = 10

// Discrimination reports how well a score orders confirmed paths above refuted ones.
type Discrimination struct {
	Positives int `json:"positives"` // confirmed verdicts carrying the score
	Negatives int `json:"negatives"` // refuted verdicts carrying the score
	// AUC is P(a confirmed path outranks a refuted one), ties counted half. Meaningful
	// only when HasData; 0.5 is chance.
	AUC float64 `json:"auc"`
	// AUCLow and AUCHigh are an approximate 95% interval (Hanley-McNeil, widened on
	// small samples - see the package comment). An interval that contains 0.5 means the
	// ordering cannot yet be told apart from a coin.
	AUCLow  float64 `json:"auc_low"`
	AUCHigh float64 `json:"auc_high"`
	// Verdict is "discriminates" | "indistinguishable-from-chance" | "inverted" |
	// "insufficient-data".
	Verdict string `json:"verdict"`
	// HasData is false until there is at least one confirmed AND one refuted verdict;
	// before that no AUC is defined at all.
	HasData bool `json:"has_data"`
}

// rankPair is one scored verdict as the AUC sees it: the score and a binary label.
type rankPair struct {
	score, y float64
}

// discriminationOf grades how well the scores in pairs order y=1 above y=0.
func discriminationOf(pairs []rankPair) Discrimination {
	d := Discrimination{Verdict: "insufficient-data"}
	auc, u, pos, neg := aucMidRank(pairs)
	d.Positives, d.Negatives = pos, neg
	if pos == 0 || neg == 0 {
		return d
	}
	d.HasData = true
	d.AUC = auc

	// Half-count shrinkage toward 0.5 for the error term only.
	shrunk := (u + 0.5) / (float64(pos)*float64(neg) + 1)
	se := hanleyMcNeilSE(shrunk, pos, neg)
	d.AUCLow = clamp(auc-1.96*se, 0, 1)
	d.AUCHigh = clamp(auc+1.96*se, 0, 1)

	if pos < minDiscriminationPerClass || neg < minDiscriminationPerClass {
		return d
	}
	switch {
	case d.AUCLow > 0.5:
		d.Verdict = "discriminates"
	case d.AUCHigh < 0.5:
		d.Verdict = "inverted"
	default:
		d.Verdict = "indistinguishable-from-chance"
	}
	return d
}

// aucMidRank computes the Mann-Whitney AUC with mid-ranks for ties. It returns the AUC,
// the U statistic behind it, and the class counts. Partial labels and non-finite scores
// are skipped - a NaN would make the ordering undefined rather than merely noisy.
//
// Deterministic by construction: ranks are integers or half-integers, so the rank sum is
// exact in float64 whatever order the samples arrive in, and the only inexact operation
// is the final division. Two backends holding the same evidence publish the same bits.
func aucMidRank(pairs []rankPair) (auc, u float64, pos, neg int) {
	xs := make([]rankPair, 0, len(pairs))
	for _, p := range pairs {
		if math.IsNaN(p.score) || math.IsInf(p.score, 0) {
			continue
		}
		switch p.y {
		case 1:
			pos++
		case 0:
			neg++
		default:
			continue
		}
		xs = append(xs, p)
	}
	if pos == 0 || neg == 0 {
		return 0, 0, pos, neg
	}
	sort.Slice(xs, func(i, j int) bool { return xs[i].score < xs[j].score })

	var rankSumPos float64
	for i := 0; i < len(xs); {
		j := i
		for j+1 < len(xs) && xs[j+1].score == xs[i].score {
			j++
		}
		mid := float64(i+j+2) / 2 // 1-based ranks i+1..j+1 share their average
		for k := i; k <= j; k++ {
			if xs[k].y == 1 {
				rankSumPos += mid
			}
		}
		i = j + 1
	}
	u = rankSumPos - float64(pos)*float64(pos+1)/2
	return u / (float64(pos) * float64(neg)), u, pos, neg
}

// hanleyMcNeilSE is the standard error of an AUC (Hanley & McNeil, Radiology 1982).
func hanleyMcNeilSE(a float64, pos, neg int) float64 {
	q1 := a / (2 - a)
	q2 := 2 * a * a / (1 + a)
	v := (a*(1-a) + float64(pos-1)*(q1-a*a) + float64(neg-1)*(q2-a*a)) / (float64(pos) * float64(neg))
	if v < 0 {
		v = 0
	}
	return math.Sqrt(v)
}

// scoreDiscrimination grades a calibration track's own predicted score.
func scoreDiscrimination(samples []calSample) Discrimination {
	pairs := make([]rankPair, 0, len(samples))
	for _, s := range samples {
		pairs = append(pairs, rankPair{score: s.p, y: s.y})
	}
	return discriminationOf(pairs)
}
