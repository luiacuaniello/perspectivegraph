package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"runtime"
	"sync"
	"time"

	"github.com/luiacuaniello/perspectivegraph/internal/metrics"
)

// Heavy analysis: what one GraphQL request, and the whole process, may spend on it.
//
// The query guard prices a document before it runs, and it cannot see how long a list
// will be. One `verification` inside `remediationPlan` is one field in the document and
// one what-if per fix at run time - each of them two path searches and two simulations
// over the whole graph. Measured on a genload estate of 4,344 nodes (920 paths, a 75-fix
// plan), the dashboard's own "verify this fix" query, which asked for every fix's proof
// to show one, did not finish in five minutes; `attackPaths { remediations { verification
// } }` asks for 6,440. On a read-only public instance any visitor can send either.
//
// So heavy work is also bounded where it happens, three ways:
//
//   - a budget per request: past requestComputeBudget computations, or requestComputeTime
//     of them, the rest of the request's heavy fields answer with an error instead of
//     running, and one still running when the time is up is stopped;
//   - identical computations within a request run once, so aliasing the same selection
//     a hundred times costs one;
//   - a cap on how many run at once across the process, so a burst of heavy requests
//     queues instead of taking every core from the cheap ones, which read the analysis
//     the analyzer has already cached.

// requestComputeBudget is how many heavy computations one request may run: a what-if, a
// risk simulation with its own iterations or seed, a k-shortest-paths search, a fix's
// verification. The dashboard asks for one at a time; twenty leaves room for a script
// checking a short list of fixes in one request.
const requestComputeBudget = 20

// requestComputeTime is how long one request's heavy analyses may run in total, counted
// from the moment the request arrives. The count above bounds many cheap analyses; this
// bounds a few expensive ones, which on a large graph is what they are - one fix's proof
// is two Monte Carlo runs, measured at 9 s each on a 4,000-node graph. It stays under the
// dashboard proxy's 60 s timeout, so an answer arrives while someone is still waiting.
const requestComputeTime = 45 * time.Second

// heavyWait is how long a heavy computation waits for a free slot before the request is
// told the server is busy. Short enough that a flood is refused rather than queued for
// minutes, long enough to ride out a burst of real use.
const heavyWait = 20 * time.Second

var (
	errComputeBudget = fmt.Errorf("this request asks for more heavy analyses than one request may run "+
		"(%d, or %s of them: what-ifs, fix verifications, risk simulations with custom iterations or seed, "+
		"k-shortest-paths searches); ask for fewer at a time - one fix's proof is "+
		"remediationPlan(title: \"…\") { verification }", requestComputeBudget, requestComputeTime)
	errServerBusy = errors.New("the server is busy with other analyses; retry in a few seconds")
)

// heavyConcurrency is the process-wide number of heavy computations allowed at once:
// half the cores, so the analyzer and the cheap queries always have the other half.
func heavyConcurrency() int {
	if n := runtime.GOMAXPROCS(0) / 2; n > 1 {
		return n
	}
	return 1
}

// computeScope is one request's budget and the results it has already computed.
type computeScope struct {
	mu        sync.Mutex
	remaining int
	deadline  time.Time
	memo      map[string]any
}

type computeCtxKey struct{}

// withComputeScope gives every GraphQL request its own budget.
func withComputeScope(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		scope := &computeScope{
			remaining: requestComputeBudget,
			deadline:  time.Now().Add(requestComputeTime),
			memo:      map[string]any{},
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), computeCtxKey{}, scope)))
	})
}

// heavy runs fn under the request's budget and the process-wide cap. key identifies the
// computation within the request - the same key returns the first result without
// spending budget again. Outside an HTTP request (tests, embedded use) there is no
// budget, only the cap.
func (a *API) heavy(ctx context.Context, key string, fn func(context.Context) (any, error)) (any, error) {
	scope, _ := ctx.Value(computeCtxKey{}).(*computeScope)
	if scope != nil {
		scope.mu.Lock()
		if v, ok := scope.memo[key]; ok {
			scope.mu.Unlock()
			return v, nil
		}
		if scope.remaining <= 0 || !time.Now().Before(scope.deadline) {
			scope.mu.Unlock()
			metrics.APIHeavyRefused.WithLabelValues("budget").Inc()
			return nil, errComputeBudget
		}
		scope.remaining--
		scope.mu.Unlock()
		// The analysis stops when the request's time is up, not only when the client
		// goes away: the simulations check their context as they run.
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, scope.deadline)
		defer cancel()
	}

	release, err := a.acquireHeavy(ctx)
	if err != nil {
		return nil, a.budgetOr(ctx, err)
	}
	v, err := fn(ctx)
	release()
	if err != nil {
		return nil, a.budgetOr(ctx, err)
	}
	if scope != nil {
		scope.mu.Lock()
		scope.memo[key] = v
		scope.mu.Unlock()
	}
	return v, nil
}

// budgetOr reports a heavy analysis stopped by the request's time budget as the budget
// error, which says what to do about it, rather than as a bare deadline.
func (a *API) budgetOr(ctx context.Context, err error) error {
	if errors.Is(err, context.DeadlineExceeded) && ctx.Value(computeCtxKey{}) != nil {
		metrics.APIHeavyRefused.WithLabelValues("budget").Inc()
		return errComputeBudget
	}
	return err
}

// acquireHeavy takes one of the process-wide slots, waiting up to heavyWait.
func (a *API) acquireHeavy(ctx context.Context) (release func(), err error) {
	if a.heavySlots == nil {
		return func() {}, nil
	}
	release = func() { <-a.heavySlots }
	select {
	case a.heavySlots <- struct{}{}:
		return release, nil
	default:
	}
	t := time.NewTimer(heavyWait)
	defer t.Stop()
	select {
	case a.heavySlots <- struct{}{}:
		return release, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-t.C:
		metrics.APIHeavyRefused.WithLabelValues("busy").Inc()
		return nil, errServerBusy
	}
}
