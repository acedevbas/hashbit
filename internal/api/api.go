package api

import (
	"bufio"
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/acedevbas/hashbit/internal/db"
	"github.com/acedevbas/hashbit/internal/scheduler"
	"github.com/acedevbas/hashbit/internal/trackers"
)

var hashRE = regexp.MustCompile(`^[0-9a-fA-F]{40}$`)

type Server struct {
	Pool     *pgxpool.Pool
	Log      *slog.Logger
	APIToken string
	// Per-tracker scrapers, used for on-demand ("force") scrape.
	Scrapers        map[string]scheduler.Scraper
	OnDemandTimeout time.Duration
}

func (s *Server) Routes() http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.RealIP)
	r.Use(middleware.RequestID)
	r.Use(requestLogger(s.Log))
	r.Use(middleware.Recoverer)

	// Public endpoint (no auth) — health check.
	r.Get("/health", s.health)

	// Authenticated endpoints.
	r.Group(func(r chi.Router) {
		r.Use(s.auth)
		r.Get("/stats", s.globalStats)
		r.Post("/hashes", s.addHashes)
		r.Post("/hashes/query", s.queryHashes)
		r.Get("/hash/{infohash}", s.getHash)
	})

	return r
}

// ------------- middleware -------------

func requestLogger(log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
			next.ServeHTTP(ww, r)
			log.Info("http",
				"method", r.Method,
				"path", r.URL.Path,
				"status", ww.Status(),
				"bytes", ww.BytesWritten(),
				"took", time.Since(start).String(),
				"ip", r.RemoteAddr,
			)
		})
	}
}

func (s *Server) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := r.Header.Get("Authorization")
		const pfx = "Bearer "
		if !strings.HasPrefix(h, pfx) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing Bearer token"})
			return
		}
		token := strings.TrimSpace(strings.TrimPrefix(h, pfx))
		if subtle.ConstantTimeCompare([]byte(token), []byte(s.APIToken)) != 1 {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid token"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ------------- handlers -------------

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	if err := s.Pool.Ping(r.Context()); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"status": "unhealthy", "err": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}

func (s *Server) globalStats(w http.ResponseWriter, r *http.Request) {
	g, err := db.GetGlobalStats(r.Context(), s.Pool)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"total":              g.Total,
		"scraped_at_least_1": g.Scraped,
		"with_seeders":       g.WithSeeders,
		"with_peers_only":    g.WithPeersOnly,
		"due_now_by_tracker": g.DueNow,
	})
}

// POST /hashes
//
// Body formats accepted:
//
//	JSON:      {"hashes": [{"infohash":"abc...", "source_tracker":"rutracker"}, ...]}
//	JSON flat: {"hashes": ["abc...", "def..."]}   ← source_tracker is optional
//	text/plain: one hash per line, optional "HASH<space>source" or "HASH,source"
//
// Responds with counts of added vs already-known.
func (s *Server) addHashes(w http.ResponseWriter, r *http.Request) {
	inputs, err := parseAddBody(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if len(inputs) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "no valid hashes"})
		return
	}
	// Chunk inserts so we don't submit pgx batches with millions of queued items.
	const chunk = 2000
	added := 0
	for i := 0; i < len(inputs); i += chunk {
		end := i + chunk
		if end > len(inputs) {
			end = len(inputs)
		}
		n, err := db.AddHashes(r.Context(), s.Pool, inputs[i:end])
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{
				"error":        err.Error(),
				"added_so_far": added,
			})
			return
		}
		added += n
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"received":      len(inputs),
		"newly_added":   added,
		"already_known": len(inputs) - added,
	})
}

func parseAddBody(r *http.Request) ([]db.HashInput, error) {
	ct := r.Header.Get("Content-Type")
	body, err := io.ReadAll(io.LimitReader(r.Body, 500*1024*1024)) // 500 MB cap
	if err != nil {
		return nil, err
	}
	var inputs []db.HashInput

	if strings.HasPrefix(ct, "text/plain") {
		sc := bufio.NewScanner(bytes.NewReader(body))
		sc.Buffer(make([]byte, 1024), 1024*1024)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" {
				continue
			}
			parts := strings.FieldsFunc(line, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' })
			if len(parts) == 0 {
				continue
			}
			h := strings.ToLower(parts[0])
			if !hashRE.MatchString(h) {
				continue
			}
			src := ""
			if len(parts) >= 2 {
				src = normalizeTracker(parts[1])
			}
			inputs = append(inputs, db.HashInput{Infohash: h, SourceTracker: src})
		}
		return inputs, nil
	}

	// Try typed JSON: {"hashes": [{"infohash":"...", "source_tracker":"..."}]}
	var typed struct {
		Hashes []db.HashInput `json:"hashes"`
	}
	if err := json.Unmarshal(body, &typed); err == nil && len(typed.Hashes) > 0 {
		// But some users send {"hashes": ["abc", "def"]} — strings, not objects.
		// That case will not unmarshal successfully above (string != struct).
		for _, h := range typed.Hashes {
			h.Infohash = strings.ToLower(strings.TrimSpace(h.Infohash))
			h.SourceTracker = normalizeTracker(h.SourceTracker)
			if hashRE.MatchString(h.Infohash) {
				inputs = append(inputs, h)
			}
		}
		return inputs, nil
	}

	// Fallback: {"hashes": ["abc", "def"]}
	var flat struct {
		Hashes []string `json:"hashes"`
	}
	if err := json.Unmarshal(body, &flat); err != nil {
		return nil, errors.New("cannot parse body as JSON or text/plain")
	}
	for _, h := range flat.Hashes {
		h = strings.ToLower(strings.TrimSpace(h))
		if hashRE.MatchString(h) {
			inputs = append(inputs, db.HashInput{Infohash: h})
		}
	}
	return inputs, nil
}

func normalizeTracker(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	switch s {
	case "rutor", "nnm-club", "nnmclub", "nnm", "kinozal", "rutracker":
		// normalize aliases
		switch s {
		case "nnmclub", "nnm":
			return "nnm-club"
		}
		return s
	case "":
		return ""
	default:
		return ""
	}
}

// POST /hashes/query
// Body: {"hashes": ["abc...", "def...", ...]}
// Returns map hash → stats.
func (s *Server) queryHashes(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Hashes []string `json:"hashes"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 50*1024*1024)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	valid := make([]string, 0, len(req.Hashes))
	for _, h := range req.Hashes {
		h = strings.ToLower(strings.TrimSpace(h))
		if hashRE.MatchString(h) {
			valid = append(valid, h)
		}
	}
	if len(valid) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "no valid hashes"})
		return
	}
	if len(valid) > 5000 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "too many hashes; max 5000 per query"})
		return
	}
	stats, err := db.GetBulkStats(r.Context(), s.Pool, valid)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	// Build response preserving requested order
	resp := make([]map[string]any, 0, len(valid))
	for _, h := range valid {
		st := stats[h]
		if st == nil {
			resp = append(resp, map[string]any{
				"infohash": h,
				"known":    false,
			})
			continue
		}
		resp = append(resp, map[string]any{
			"infohash":       st.Infohash,
			"known":          true,
			"source_tracker": st.SourceTracker,
			"seeders":        st.Seeders,
			"leechers":       st.Leechers,
			"peer_count":     st.PeerCount,
			"last_update_at": st.LastUpdateAt,
			"added_at":       st.AddedAt,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"results": resp})
}

// GET /hash/{infohash}?force=1
func (s *Server) getHash(w http.ResponseWriter, r *http.Request) {
	h := strings.ToLower(chi.URLParam(r, "infohash"))
	if !hashRE.MatchString(h) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid infohash"})
		return
	}

	// auto-insert on first query so on-demand scrape works even for unknown hashes
	_, _ = db.AddHashes(r.Context(), s.Pool, []db.HashInput{{Infohash: h}})

	if r.URL.Query().Get("force") == "1" {
		ctx, cancel := context.WithTimeout(r.Context(), s.OnDemandTimeout)
		s.forceScrape(ctx, h)
		cancel()
	}

	stats, err := db.GetStats(r.Context(), s.Pool, h)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	per := make([]map[string]any, 0, len(stats.PerTracker))
	for _, t := range stats.PerTracker {
		per = append(per, map[string]any{
			"tracker":        t.Tracker,
			"seeders":        t.Seeders,
			"leechers":       t.Leechers,
			"completed":      t.Completed,
			"peer_count":     t.PeerCount,
			"status":         t.Status,
			"last_scrape_at": t.LastScrapeAt,
			"last_err":       t.LastErr,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"infohash":       stats.Infohash,
		"source_tracker": stats.SourceTracker,
		"seeders":        stats.Seeders,
		"leechers":       stats.Leechers,
		"peer_count":     stats.PeerCount,
		"last_update_at": stats.LastUpdateAt,
		"added_at":       stats.AddedAt,
		"per_tracker":    per,
	})
}

// forceScrape runs all configured scrapers on the given hash and persists results.
func (s *Server) forceScrape(ctx context.Context, hash string) {
	results := make([]db.TrackerResult, 0, len(trackers.All))
	for name, sc := range s.Scrapers {
		r := sc.Scrape(ctx, []string{hash})[hash]
		tr := db.TrackerResult{Infohash: hash, Tracker: name}
		switch r.Status {
		case trackers.StatusOK:
			tr.Status = "ok"
			tr.Seeders = nilable(r.Result.Seeders)
			tr.Leechers = nilable(r.Result.Leechers)
			tr.Completed = nilable(r.Result.Completed)
			tr.PeerCount = nilable(r.Result.PeerCount)
		case trackers.StatusNotFound:
			tr.Status = "not_found"
		case trackers.StatusError:
			tr.Status = "error"
			tr.Err = r.Err
		}
		results = append(results, tr)
	}
	_ = db.WriteTrackerResults(ctx, s.Pool, results, db.SchedulerIntervals{
		Alive:    30 * time.Minute,
		Dead1:    1 * time.Hour,
		Dead2:    6 * time.Hour,
		DeadLong: 24 * time.Hour,
	})
}

func nilable(v int32) *int32 {
	if v < 0 {
		return nil
	}
	return &v
}

// ------------- helpers -------------

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
