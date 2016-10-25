package server

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/bouk/httprouter"
	"github.com/influxdata/chronograf"
)

type layoutResponse struct {
	chronograf.Layout
	Link link `json:"link"`
}

func newLayoutResponse(layout chronograf.Layout) layoutResponse {
	href := fmt.Sprintf("%s/%s", httpAPILayouts, layout.ID)
	rel := "self"

	return layoutResponse{
		Layout: layout,
		Link: link{
			Href: href,
			Rel:  rel,
		},
	}
}

func (h *Store) NewLayout(w http.ResponseWriter, r *http.Request) {
	var layout chronograf.Layout
	if err := json.NewDecoder(r.Body).Decode(&layout); err != nil {
		invalidJSON(w)
		return
	}

	if err := ValidLayoutRequest(layout); err != nil {
		invalidData(w, err)
		return
	}

	var err error
	if layout, err = h.LayoutStore.Add(r.Context(), layout); err != nil {
		msg := fmt.Errorf("Error storing layout %v: %v", layout, err)
		unknownErrorWithMessage(w, msg)
	}

	res := newLayoutResponse(layout)
	w.Header().Add("Location", res.Link.Href)
	encodeJSON(w, http.StatusCreated, res, h.Logger)
}

type getLayoutsResponse struct {
	Layouts []layoutResponse `json:"layouts"`
}

func (h *Store) Layouts(w http.ResponseWriter, r *http.Request) {
	// Construct a filter sieve for both applications and measurements
	filtered := map[string]bool{}
	for _, a := range r.URL.Query()["app"] {
		filtered[a] = true
	}

	for _, m := range r.URL.Query()["measurement"] {
		filtered[m] = true
	}

	ctx := r.Context()
	layouts, err := h.LayoutStore.All(ctx)
	if err != nil {
		Error(w, http.StatusInternalServerError, "Error loading layouts")
		return
	}

	filter := func(layout *chronograf.Layout) bool {
		// If the length of the filter is zero then all values are acceptable.
		if len(filtered) == 0 {
			return true
		}

		// If filter contains either measurement or application
		return filtered[layout.Measurement] || filtered[layout.Application]
	}

	res := getLayoutsResponse{
		Layouts: []layoutResponse{},
	}
	for _, layout := range layouts {
		if filter(&layout) {
			res.Layouts = append(res.Layouts, newLayoutResponse(layout))
		}
	}
	encodeJSON(w, http.StatusOK, res, h.Logger)
}

func (h *Store) LayoutsID(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := httprouter.GetParamFromContext(ctx, "id")

	layout, err := h.LayoutStore.Get(ctx, id)
	if err != nil {
		Error(w, http.StatusNotFound, fmt.Sprintf("ID %s not found", id))
		return
	}

	res := newLayoutResponse(layout)
	encodeJSON(w, http.StatusOK, res, h.Logger)
}

func (h *Store) RemoveLayout(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := httprouter.GetParamFromContext(ctx, "id")

	layout := chronograf.Layout{
		ID: id,
	}

	if err := h.LayoutStore.Delete(ctx, layout); err != nil {
		unknownErrorWithMessage(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *Store) UpdateLayout(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := httprouter.GetParamFromContext(ctx, "id")

	_, err := h.LayoutStore.Get(ctx, id)
	if err != nil {
		Error(w, http.StatusNotFound, fmt.Sprintf("ID %s not found", id))
		return
	}

	var req chronograf.Layout
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		invalidJSON(w)
		return
	}
	req.ID = id

	if err := ValidLayoutRequest(req); err != nil {
		invalidData(w, err)
		return
	}

	if err := h.LayoutStore.Update(ctx, req); err != nil {
		msg := fmt.Sprintf("Error updating layout ID %s: %v", id, err)
		Error(w, http.StatusInternalServerError, msg)
		return
	}

	res := newLayoutResponse(req)
	encodeJSON(w, http.StatusOK, res, h.Logger)
}

func ValidLayoutRequest(l chronograf.Layout) error {
	if l.Application == "" || l.Measurement == "" || len(l.Cells) == 0 {
		return fmt.Errorf("app, measurement, and cells required")
	}

	for _, c := range l.Cells {
		if c.W == 0 || c.H == 0 {
			return fmt.Errorf("w, and h required")
		}
		for _, q := range c.Queries {
			if q.Command == "" {
				return fmt.Errorf("query required")
			}
		}
	}
	return nil
}
