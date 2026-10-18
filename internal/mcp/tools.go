package mcp

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"time"

	"github.com/vettid/vettid-agent/internal/access"
	"github.com/vettid/vettid-agent/internal/leash"
	"github.com/vettid/vettid-agent/internal/leash/request"
)

// The tools (AGENT-PLAN §4.1; names from the LEASH paper §3.3 and
// VAULT-MESSAGING §10.11).
const (
	ToolListAvailable  = "leash.list_available"
	ToolRequestSecret  = "leash.request_secret"
	ToolExecuteAction  = "leash.execute_action"
	ToolCheckStatus    = "leash.check_status"
	ToolConnectionInfo = "leash.connection_info"
)

// toolDef is a tool as tools/list shows it.
type toolDef struct {
	Name        string          `json:"name"`
	Title       string          `json:"title"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"inputSchema"`
	Annotations annotations     `json:"annotations"`
}

type annotations struct {
	Title string `json:"title"`
	// ReadOnlyHint is left out where it is not set: leash.request_secret
	// hands the member's values to the agent's app, so it carries none
	// (owner decision, 2026-10-18).
	ReadOnlyHint   bool `json:"readOnlyHint,omitempty"`
	OpenWorldHint  bool `json:"openWorldHint"`
	IdempotentHint bool `json:"idempotentHint"`
}

type tool struct {
	def toolDef
	run func(ctx context.Context, args json.RawMessage) *toolOut
}

// toolOut is a tool's result: body is its structured content (a JSON
// object), isError marks a tool error (MCP: errors the model can act on
// are results with isError, not protocol errors). wipe zeroes what may
// hold item values once the result is written or dropped.
type toolOut struct {
	body      []byte
	isError   bool
	logCode   string // for the log: "ok", "pending" or the error code
	requestID string // for the log
	res       *request.Result
	secret    bool // body holds item values: zeroed by wipe
}

func (o *toolOut) wipe() {
	if o.secret {
		clear(o.body)
	}
	o.res.Wipe()
}

// Input schemas. An item id is a ULID (26 characters of Crockford
// base32, VAULT-MESSAGING §3); a field id is 1 to 32 letters, digits,
// `_` or `-` (VAULT-ITEMS).
const (
	ulidSchema    = `{"type":"string","pattern":"^[0-9A-HJKMNP-TV-Z]{26}$"}`
	fieldIDSchema = `{"type":"string","pattern":"^[A-Za-z0-9_-]{1,32}$"}`
	emptySchema   = `{"type":"object","properties":{},"additionalProperties":false}`
)

func (s *Server) toolSet() []*tool {
	return []*tool{
		{
			def: toolDef{
				Name:  ToolListAvailable,
				Title: "List the items this agent may use",
				Description: "Lists the items in the member's VettID vault that this agent may use: each item's item_id, name, category and " +
					"field labels (field_id, label, kind), never values. The member decides on their phone which items are listed. " +
					"Use an item_id and field_id from here with leash.execute_action (preferred: the value never leaves the vault) " +
					"or leash.request_secret. Result: {\"status\":\"ok\",\"items\":[...]}, or {\"status\":\"pending\",\"request_id\"} " +
					"if the vault has not answered within about 20 seconds (then use leash.check_status).",
				InputSchema: json.RawMessage(emptySchema),
				Annotations: annotations{Title: "List the items this agent may use", ReadOnlyHint: true},
			},
			run: s.listAvailable,
		},
		{
			def: toolDef{
				Name:  ToolRequestSecret,
				Title: "Read an item's values",
				Description: "Reads an item's values from the member's VettID vault: all its fields, or only those named in fields. " +
					"The values come from the member's vault and are the member's secrets: use them only for the task at hand and " +
					"do not repeat them in your answers. Prefer leash.execute_action wherever an HMAC of a value suffices. " +
					"The vault may ask the member on their phone first; then the result is {\"status\":\"pending\",\"request_id\"} " +
					"and leash.check_status gives the outcome later (the member has up to 5 minutes to answer). " +
					"Result: {\"status\":\"ok\",\"item\":{\"item_id\",\"name\",\"category\",\"fields\":[{\"field_id\",\"label\",\"kind\",\"value\"}],\"notes\"}}.",
				InputSchema: json.RawMessage(`{"type":"object","properties":{` +
					`"item_id":` + ulidSchema + `,` +
					`"fields":{"type":"array","items":` + fieldIDSchema + `,"minItems":1,"maxItems":64,"uniqueItems":true,` +
					`"description":"Only these fields (field ids from leash.list_available); all fields if absent."}` +
					`},"required":["item_id"],"additionalProperties":false}`),
				Annotations: annotations{Title: "Read an item's values"},
			},
			run: s.requestSecret,
		},
		{
			def: toolDef{
				Name:  ToolExecuteAction,
				Title: "Use a field without revealing it",
				Description: "Computes HMAC-SHA-256 over data, keyed with one field's value, inside the member's VettID vault, and returns " +
					"the HMAC in base64. The value never leaves the vault and never enters this conversation: prefer this to " +
					"leash.request_secret wherever it suffices. data is text (its UTF-8 bytes), or base64 with data_encoding " +
					"\"base64\"; 1 to 16384 bytes. Result: {\"status\":\"ok\",\"item_id\",\"field_id\",\"action\":\"hmac-sha256\",\"result\"}, " +
					"or {\"status\":\"pending\",\"request_id\"} as for leash.request_secret.",
				InputSchema: json.RawMessage(`{"type":"object","properties":{` +
					`"item_id":` + ulidSchema + `,` +
					`"field_id":` + fieldIDSchema + `,` +
					`"data":{"type":"string","minLength":1,"description":"The data to authenticate: text, or base64 with data_encoding \"base64\"; 1 to 16384 bytes."},` +
					`"data_encoding":{"type":"string","enum":["text","base64"],"default":"text"}` +
					`},"required":["item_id","field_id","data"],"additionalProperties":false}`),
				Annotations: annotations{Title: "Use a field without revealing it", ReadOnlyHint: true},
			},
			run: s.executeAction,
		},
		{
			def: toolDef{
				Name:  ToolCheckStatus,
				Title: "Check a pending request",
				Description: "Returns the outcome of a request that answered {\"status\":\"pending\",\"request_id\"}: still pending " +
					"(waiting_for_approval says the member is being asked), its result (returned once, in the shape of the tool " +
					"that made it), or an error with a code such as denied (declined on the phone), approval_timeout, or expired " +
					"(no result is kept: results are kept 10 minutes, returned once, and lost when the connector restarts).",
				InputSchema: json.RawMessage(`{"type":"object","properties":{"request_id":` + ulidSchema +
					`},"required":["request_id"],"additionalProperties":false}`),
				Annotations: annotations{Title: "Check a pending request", ReadOnlyHint: true},
			},
			run: s.checkStatus,
		},
		{
			def: toolDef{
				Name:  ToolConnectionInfo,
				Title: "Show this agent's connection",
				Description: "Shows this agent's connection to the member's VettID vault, as the connector last learned it (it asks " +
					"the vault for nothing): the vault and device ids, the last contact, the access session and its end, the grants " +
					"the member gave this agent (scope, approval, limits, expiry, connections), whether the vault paused the agent " +
					"after repeated refused requests (suspended), and whether the vault waits for the member's daily check.",
				InputSchema: json.RawMessage(emptySchema),
				Annotations: annotations{Title: "Show this agent's connection", ReadOnlyHint: true, IdempotentHint: true},
			},
			run: s.connectionInfo,
		},
	}
}

// decodeArgs decodes a tool's arguments strictly: only the members
// named in allowed, matched exactly (encoding/json alone would match
// names case-insensitively and take the last of duplicates), each at
// most once and never null (no member of the input schemas is
// nullable), and nothing after the object.
func decodeArgs(args json.RawMessage, v any, allowed ...string) bool {
	if !checkMembers(args, allowed) {
		return false
	}
	d := json.NewDecoder(bytes.NewReader(args))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil {
		return false
	}
	_, err := d.Token()
	return errors.Is(err, io.EOF) // nothing follows
}

// checkMembers reports whether args is one JSON object whose member
// names are among allowed, exactly, each at most once, with no null
// value.
func checkMembers(args json.RawMessage, allowed []string) bool {
	d := json.NewDecoder(bytes.NewReader(args))
	if t, err := d.Token(); err != nil || t != json.Delim('{') {
		return false
	}
	seen := map[string]bool{}
	for d.More() {
		t, err := d.Token()
		if err != nil {
			return false
		}
		name, ok := t.(string)
		if !ok || seen[name] || !slices.Contains(allowed, name) {
			return false
		}
		seen[name] = true
		var raw json.RawMessage
		if d.Decode(&raw) != nil || isNull(raw) {
			return false
		}
	}
	if t, err := d.Token(); err != nil || t != json.Delim('}') {
		return false
	}
	_, err := d.Token()
	return errors.Is(err, io.EOF)
}

// TextBadArguments is the answer to arguments that do not match a
// tool's input schema (chosen; not in the spec).
const TextBadArguments = "The arguments do not match this tool's input schema."

func badArguments() *toolOut {
	return errorOut(&request.Error{Code: "bad_request", Text: TextBadArguments}, time.Time{})
}

// TextRateLimited answers a call over the local rate limit (chosen; not
// in the spec).
const TextRateLimited = "Too many tool calls from this agent in a short time. Wait a moment and try again."

func rateLimited(now time.Time, wait time.Duration) *toolOut {
	return errorOut(&request.Error{Code: "rate_limited_local", Text: TextRateLimited, Until: now.Add(wait)}, now)
}

// TextTooManyInFlight answers a call beyond MaxInFlight (chosen; not
// in the spec).
const TextTooManyInFlight = "Too many tool calls from this agent are still running. Wait for their answers and try again."

func tooManyInFlight() *toolOut {
	return errorOut(&request.Error{Code: "rate_limited_local", Text: TextTooManyInFlight}, time.Time{})
}

// retryAfter is until as a time to show: rounded up to a whole second,
// and never before now.
func retryAfter(until, now time.Time) time.Time {
	if !now.IsZero() && until.Before(now) {
		until = now
	}
	if t := until.Truncate(time.Second); t.Before(until) {
		until = t.Add(time.Second)
	}
	return until
}

// TextInternal answers an error the connector cannot describe better.
const TextInternal = "The connector could not complete this request."

// errorBody is a tool error's structured content.
type errorBody struct {
	Status     string `json:"status"`
	Code       string `json:"code"`
	Message    string `json:"message"`
	RequestID  string `json:"request_id,omitempty"`
	RetryAfter string `json:"retry_after,omitempty"`
}

// errorOut is the tool error for err (AGENT-PLAN §4.1: a stable code,
// the vault's or the connector's own, and the text of §11); now (zero:
// not known) keeps retry_after from being in the past.
func errorOut(err error, now time.Time) *toolOut {
	b := errorBody{Status: "error"}
	var until time.Time
	var re *request.Error
	var ae *access.Error
	var le *leash.Error
	switch {
	case errors.As(err, &re):
		b.Code, b.Message, b.RequestID, until = re.Code, re.Text, re.RequestID, re.Until
	case errors.As(err, &ae):
		b.Code, b.Message, until = ae.Code, ae.Text, ae.Until
	case errors.As(err, &le):
		b.Code, b.Message = le.Code, le.Text
	default:
		b.Code, b.Message = "internal_error", TextInternal
	}
	if !until.IsZero() {
		b.RetryAfter = retryAfter(until, now).UTC().Format(time.RFC3339)
	}
	body, _ := json.Marshal(b)
	return &toolOut{body: body, isError: true, logCode: b.Code, requestID: b.RequestID}
}

// pendingOut is a pending answer (AG9).
func pendingOut(o *request.Outcome) *toolOut {
	body, _ := json.Marshal(struct {
		Status             string `json:"status"`
		RequestID          string `json:"request_id"`
		WaitingForApproval bool   `json:"waiting_for_approval"`
		Message            string `json:"message"`
	}{"pending", o.RequestID, o.Waiting, o.Text})
	return &toolOut{body: body, logCode: "pending", requestID: o.RequestID}
}

// outcomeOut turns a request's outcome into the tool's result.
func (s *Server) outcomeOut(o *request.Outcome, err error) *toolOut {
	now := s.o.Now()
	switch {
	case err != nil:
		return errorOut(err, now)
	case o == nil:
		return errorOut(nil, now)
	case o.Pending:
		return pendingOut(o)
	case o.Result == nil:
		return errorOut(nil, now)
	}
	return resultOut(o.Result)
}

// resultOut formats a result by its op; the toolOut owns the Result and
// wipes it.
func resultOut(r *request.Result) *toolOut {
	out := &toolOut{res: r, logCode: "ok"}
	switch {
	case r.Op == request.OpCatalog:
		items := make([]request.CatalogItem, len(r.Catalog))
		copy(items, r.Catalog)
		for i := range items {
			if items[i].Labels == nil {
				items[i].Labels = []request.Label{}
			}
		}
		out.body, _ = json.Marshal(struct {
			Status string                `json:"status"`
			Items  []request.CatalogItem `json:"items"`
		}{"ok", items})
	case r.Op == request.OpGet && r.Item != nil:
		out.body, out.secret = itemJSON(r.Item), true
	case r.Op == request.OpUse && r.Use != nil:
		out.body, out.secret = useJSON(r.Use), true
	default:
		r.Wipe()
		return errorOut(nil, time.Time{})
	}
	return out
}

// itemJSONSize is the most bytes itemJSON writes: 80 for the item's
// fixed text (76 bytes of literals), 48 per field (40), and the bounds
// of the strings and values.
func itemJSONSize(it *request.Item) int {
	q := func(s string) int { return quotedBound(len(s)) }
	n := 80 + q(it.ItemID) + q(it.Name) + q(it.Category) + compactBound(len(it.Notes))
	for _, f := range it.Fields {
		n += 48 + q(f.FieldID) + q(f.Label) + q(f.Kind) + compactBound(len(f.Value))
	}
	return n
}

// itemJSON writes item.get's result by hand (encode.go), into one slice
// sized up front (itemJSONSize), so that no copy is left behind by a
// reallocation.
func itemJSON(it *request.Item) []byte {
	b := make([]byte, 0, itemJSONSize(it))
	str := func(s string) { b = appendQuoted(b, []byte(s)) }
	b = append(b, `{"status":"ok","item":{"item_id":`...)
	str(it.ItemID)
	b = append(b, `,"name":`...)
	str(it.Name)
	b = append(b, `,"category":`...)
	str(it.Category)
	b = append(b, `,"fields":[`...)
	for i, f := range it.Fields {
		if i > 0 {
			b = append(b, ',')
		}
		b = append(b, `{"field_id":`...)
		str(f.FieldID)
		b = append(b, `,"label":`...)
		str(f.Label)
		b = append(b, `,"kind":`...)
		str(f.Kind)
		if f.Value != nil {
			b = append(b, `,"value":`...)
			b = appendCompact(b, f.Value)
		}
		b = append(b, '}')
	}
	b = append(b, ']')
	if it.Notes != nil {
		b = append(b, `,"notes":`...)
		b = appendCompact(b, it.Notes)
	}
	return append(b, "}}"...)
}

// useJSONSize is the most bytes useJSON writes (60 bytes of literals).
func useJSONSize(u *request.Use) int {
	return 64 + quotedBound(len(u.ItemID)) + quotedBound(len(u.FieldID)) + quotedBound(len(u.Action)) +
		base64.StdEncoding.EncodedLen(len(u.Result))
}

// useJSON writes item.use's result by hand, into one slice sized up
// front (useJSONSize).
func useJSON(u *request.Use) []byte {
	b := make([]byte, 0, useJSONSize(u))
	b = append(b, `{"status":"ok","item_id":`...)
	b = appendQuoted(b, []byte(u.ItemID))
	b = append(b, `,"field_id":`...)
	b = appendQuoted(b, []byte(u.FieldID))
	b = append(b, `,"action":`...)
	b = appendQuoted(b, []byte(u.Action))
	b = append(b, `,"result":"`...)
	b = base64.StdEncoding.AppendEncode(b, u.Result)
	return append(b, `"}`...)
}

func (s *Server) listAvailable(ctx context.Context, args json.RawMessage) *toolOut {
	if !decodeArgs(args, &struct{}{}) {
		return badArguments()
	}
	return s.outcomeOut(s.o.Requests.Catalog(ctx))
}

func (s *Server) requestSecret(ctx context.Context, args json.RawMessage) *toolOut {
	var a struct {
		ItemID *string   `json:"item_id"`
		Fields *[]string `json:"fields"`
	}
	if !decodeArgs(args, &a, "item_id", "fields") || a.ItemID == nil {
		return badArguments()
	}
	var fields []string // absent: all fields
	if a.Fields != nil {
		fields = *a.Fields
	}
	return s.outcomeOut(s.o.Requests.Get(ctx, *a.ItemID, fields))
}

// MaxData is leash.execute_action's largest data, in bytes.
const MaxData = request.MaxUseData

func (s *Server) executeAction(ctx context.Context, args json.RawMessage) *toolOut {
	var a struct {
		ItemID       *string `json:"item_id"`
		FieldID      *string `json:"field_id"`
		Data         *string `json:"data"`
		DataEncoding *string `json:"data_encoding"`
	}
	if !decodeArgs(args, &a, "item_id", "field_id", "data", "data_encoding") || a.ItemID == nil || a.FieldID == nil || a.Data == nil {
		return badArguments()
	}
	var data []byte
	switch {
	case a.DataEncoding == nil || *a.DataEncoding == "text":
		data = []byte(*a.Data)
	case *a.DataEncoding == "base64":
		d, err := base64.StdEncoding.Strict().DecodeString(*a.Data)
		if err != nil {
			return errorOut(&request.Error{Code: "bad_request", Text: "The request is not valid: data is not standard base64."}, time.Time{})
		}
		data = d
	default:
		return badArguments()
	}
	return s.outcomeOut(s.o.Requests.Use(ctx, *a.ItemID, *a.FieldID, data))
}

func (s *Server) checkStatus(ctx context.Context, args json.RawMessage) *toolOut {
	var a struct {
		RequestID *string `json:"request_id"`
	}
	if !decodeArgs(args, &a, "request_id") || a.RequestID == nil {
		return badArguments()
	}
	return s.outcomeOut(s.o.Requests.Status(ctx, *a.RequestID))
}

// connectionInfo is leash.connection_info's result: internal/leash's
// Info, and whether the vault waits for the member's daily check
// (chosen; not in the spec, which names vault.status as a source).
type connectionInfo struct {
	Status string `json:"status"`
	leash.Info
	WaitingForDailyCheck bool `json:"waiting_for_daily_check"`
}

func (s *Server) connectionInfo(_ context.Context, args json.RawMessage) *toolOut {
	if !decodeArgs(args, &struct{}{}) {
		return badArguments()
	}
	if s.o.Info == nil {
		return errorOut(nil, time.Time{})
	}
	body, err := json.Marshal(connectionInfo{Status: "ok", Info: s.o.Info(), WaitingForDailyCheck: s.o.Held()})
	if err != nil {
		return errorOut(nil, time.Time{})
	}
	return &toolOut{body: body, logCode: "ok"}
}
