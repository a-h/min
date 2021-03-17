package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"mime"
	"net/url"
	"os"
	"os/signal"
	"path"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode"

	"github.com/a-h/gemini"
	"github.com/a-h/gemini/cert"
	"github.com/gdamore/tcell"
	"github.com/mattn/go-runewidth"
	"github.com/natefinch/atomic"
	"github.com/pkg/browser"
	"golang.org/x/text/encoding/ianaindex"
	"golang.org/x/text/transform"
)

var version string

type ClientCertPrefix string

func (cc ClientCertPrefix) fileName() string {
	ss := sha256.New()
	ss.Write([]byte(cc))
	fn := hex.EncodeToString(ss.Sum(nil))
	return path.Join(configPath, fn)
}

func (cc ClientCertPrefix) Load() (tls.Certificate, error) {
	fn := cc.fileName()
	return tls.LoadX509KeyPair(fn+".cert", fn+".key")
}

func (cc ClientCertPrefix) Save(cert, key []byte) error {
	fn := cc.fileName()
	if err := atomic.WriteFile(fn+".cert", bytes.NewReader(cert)); err != nil {
		return err
	}
	return atomic.WriteFile(fn+".key", bytes.NewReader(key))
}

var configPath = func() string {
	configPath, _ := os.UserConfigDir()
	return path.Join(configPath, ".min")
}()

type Config struct {
	Home               string
	Width              int
	MaximumHistory     int
	HostCertificates   map[string]string
	ClientCertPrefixes map[ClientCertPrefix]struct{}
}

func (c *Config) Save() error {
	b := new(bytes.Buffer)
	fmt.Fprintf(b, "home=%v\n", c.Home)
	fmt.Fprintf(b, "width=%v\n", c.Width)
	fmt.Fprintf(b, "maxhistory=%v\n", c.MaximumHistory)
	for prefix := range c.ClientCertPrefixes {
		fmt.Fprintf(b, "clientcert=%v\n", prefix)
	}
	for host, cert := range c.HostCertificates {
		fmt.Fprintf(b, "hostcert/%v=%v\n", host, cert)
	}
	fn := path.Join(configPath, "config.ini")
	return atomic.WriteFile(fn, b)
}

func NewConfig() (c *Config, err error) {
	c = &Config{
		Home:               "gemini://gus.guru",
		Width:              80,
		MaximumHistory:     128,
		HostCertificates:   map[string]string{},
		ClientCertPrefixes: map[ClientCertPrefix]struct{}{},
	}
	os.MkdirAll(configPath, os.ModePerm)
	lines, err := readLines(path.Join(configPath, "config.ini"))
	if err != nil {
		return
	}
	for _, l := range lines {
		kv := strings.SplitN(l, "=", 2)
		if len(kv) != 2 {
			continue
		}
		k, v := strings.ToLower(strings.TrimSpace(kv[0])), strings.TrimSpace(kv[1])
		switch k {
		case "home":
			c.Home = v
		case "width":
			w, err := strconv.ParseInt(v, 10, 64)
			if err != nil {
				return c, err
			}
			c.Width = int(w)
		case "maxhistory":
			m, err := strconv.ParseInt(v, 10, 64)
			if err != nil {
				return c, err
			}
			c.MaximumHistory = int(m)
		case "clientcert":
			c.ClientCertPrefixes[ClientCertPrefix(v)] = struct{}{}
		}
		if strings.HasPrefix(k, "hostcert/") {
			host := strings.TrimPrefix(k, "hostcert/")
			c.HostCertificates[host] = v
		}
	}
	return
}

func readLines(fn string) (lines []string, err error) {
	f, err := os.Open(fn)
	if err != nil {
		if os.IsNotExist(err) {
			err = nil
		}
		return
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	err = scanner.Err()
	return
}

var defaultStyle = tcell.StyleDefault.
	Foreground(tcell.ColorWhite).
	Background(tcell.ColorBlack)

var preformattedStyle = tcell.StyleDefault.
	Foreground(tcell.ColorGray).
	Background(tcell.ColorBlack)

func main() {
	if len(os.Args) > 1 && strings.TrimLeft(os.Args[1], "-") == "version" {
		fmt.Println(version)
		return
	}

	// Configure the context to handle SIGINT.
	ctx, cancel := context.WithCancel(context.Background())
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	defer func() {
		signal.Stop(c)
		cancel()
	}()
	go func() {
		select {
		case <-c:
			cancel()
		case <-ctx.Done():
		}
		os.Exit(2)
	}()

	// Setup config.
	conf, err := NewConfig()
	if err != nil {
		fmt.Println("Error loading config:", err)
		os.Exit(1)
	}

	// Create the history file.
	h, historyCloser, err := NewHistory(conf.MaximumHistory, path.Join(configPath, "history.tsv"))
	if err != nil {
		fmt.Println("Error loading history:", err)
		os.Exit(1)
	}
	defer historyCloser()

	// Create the boookmarks file.
	b, bookmarksCloser, err := NewBookmarks(path.Join(configPath, "bookmarks.tsv"))
	if err != nil {
		fmt.Println("Error loading bookmarks:", err)
		os.Exit(1)
	}
	defer bookmarksCloser()

	// State.
	state := &State{
		URL:       conf.Home,
		History:   h,
		Bookmarks: b,
		Conf:      conf,
		Context:   ctx,
	}

	// Use a URL passed via the command-line URL, if provided.
	if len(os.Args) > 1 {
		state.URL = strings.Join(os.Args[1:], "")
	}

	// Create client.
	state.Client = gemini.NewClient()
	for host, cert := range conf.HostCertificates {
		state.Client.AddServerCertificate(host, cert)
	}
	for prefix := range conf.ClientCertPrefixes {
		cert, err := prefix.Load()
		if err != nil {
			NewOptions(state.Screen, fmt.Sprintf("Error loading client certificate\n\nURL: %v\nMessage: %v", prefix, err), "Continue").Focus()
			continue
		}
		state.Client.AddClientCertificate(string(prefix), cert)
	}

	// Create a screen.
	tcell.SetEncodingFallback(tcell.EncodingFallbackASCII)
	s, err := tcell.NewScreen()
	if err != nil {
		fmt.Println("Error creating screen:", err)
		os.Exit(1)
	}
	if err = s.Init(); err != nil {
		fmt.Println("Error initializing screen:", err)
		os.Exit(1)
	}
	defer s.Fini()
	s.SetStyle(defaultStyle)
	state.Screen = s
	run(state)
}

type State struct {
	URL           string
	History       *History
	Bookmarks     *Bookmarks
	Screen        tcell.Screen
	Client        *gemini.Client
	Conf          *Config
	RedirectCount int
	U             *url.URL
	Response      *gemini.Response
	Context       context.Context
}

type Action string

const (
	ActionHome           Action = ""
	ActionAskForURL      Action = "AskForURL"
	ActionNavigate       Action = "Navigate"
	ActionDisplay        Action = "Display"
	ActionToggleBookmark Action = "ToggleBookmark"
	ActionViewHistory    Action = "ViewHistory"
	ActionViewBookmarks  Action = "ViewBookmarks"
	ActionGoBack         Action = "Back"
	ActionGoForward      Action = "Forward"
	ActionViewHelp       Action = "Help"
	ActionExit           Action = "Exit"
)

func run(state *State) {
	var action Action
	for {
		switch action {
		case ActionExit:
			return
		case ActionHome:
			action = handleActionHome(state)
		case ActionGoBack:
			state.History.Back()
			action = ActionDisplay
		case ActionGoForward:
			state.History.Forward()
			action = ActionDisplay
		case ActionViewBookmarks:
			action = handleActionView(state, action)
		case ActionViewHelp:
			action = handleActionView(state, action)
		case ActionViewHistory:
			action = handleActionView(state, action)
		case ActionToggleBookmark:
			action = handleActionToggleBookmark(state)
		case ActionAskForURL:
			action = handleActionAskForURL(state)
		case ActionNavigate:
			action = handleActionNavigate(state)
		case ActionDisplay:
			action = handleActionDisplay(state)
		}
	}
}

func handleActionHome(state *State) Action {
	switch NewOptions(state.Screen, "Welcome to the min browser", "Enter URL", "View History", "View Bookmarks", "Help", "Exit").Focus() {
	case "Enter URL":
		return ActionAskForURL
	case "View History":
		return ActionViewHistory
	case "View Bookmarks":
		return ActionViewBookmarks
	case "Help":
		return ActionViewHelp
	case "Exit":
		return ActionExit
	}
	return ActionExit
}

func handleActionView(state *State, action Action) Action {
	var vu *url.URL
	var vr *gemini.Response
	switch action {
	case ActionViewHistory:
		vu, vr = state.History.All()
	case ActionViewBookmarks:
		vu, vr = state.Bookmarks.All()
	case ActionViewHelp:
		vu, vr = Help()
	}
	b, err := NewBrowser(state.Screen, state.Conf.Width, vu, vr.Body)
	if err != nil {
		NewOptions(state.Screen, fmt.Sprintf("Error loading %v: %v", b.URL.String(), err), "Continue").Focus()
		return action
	}
	if err = state.History.Add(b); err != nil {
		NewOptions(state.Screen, fmt.Sprintf("Unable to persist history to disk: %v", err), "OK").Focus()
	}
	return ActionDisplay
}

func handleActionToggleBookmark(state *State) Action {
	if state.Bookmarks.Contains(state.U) {
		if NewOptions(state.Screen, fmt.Sprintf("Remove bookmark: %v", state.U), "Yes", "No").Focus() == "Yes" {
			state.Bookmarks.Remove(state.U)
		}
	} else {
		if NewOptions(state.Screen, fmt.Sprintf("Add bookmark: %v", state.U), "Yes", "No").Focus() == "Yes" {
			state.Bookmarks.Add(state.U)
		}
	}
	return ActionDisplay
}

func handleActionAskForURL(state *State) (action Action) {
	var ok bool
	state.URL, ok = NewInput(state.Screen, "Enter URL:", state.URL).Focus()
	if !ok {
		return ActionHome
	}
	var err error
	state.U, err = url.Parse(state.URL)
	if err != nil {
		NewOptions(state.Screen, fmt.Sprintf("Error parsing URL\n\nURL: %v\nMessage: %v", state.URL, err), "Continue").Focus()
		return ActionAskForURL
	}
	return ActionNavigate
}

func handleActionNavigate(state *State) (action Action) {
	var certificates []string
out:
	for {
		var ok bool
		var err error
		state.Response, certificates, _, ok, err = state.Client.RequestURL(state.Context, state.U)
		if err != nil {
			switch NewOptions(state.Screen, fmt.Sprintf("Error making request\n\nURL: %v\nMessage: %v", state.U, err), "Retry", "Cancel").Focus() {
			case "Retry":
				continue
			case "Cancel":
				break out
			}
		}
		if !ok {
			// TOFU check required.
			switch NewOptions(state.Screen, fmt.Sprintf("Accept server certificate?\n  %v", certificates[0]), "Accept (Permanent)", "Accept (Temporary)", "Reject").Focus() {
			case "Accept (Permanent)":
				state.Conf.HostCertificates[state.U.Host] = certificates[0]
				state.Conf.Save()
				state.Client.AddServerCertificate(state.U.Host, certificates[0])
				continue
			case "Accept (Temporary)":
				state.Client.AddServerCertificate(state.U.Host, certificates[0])
				continue
			case "Reject":
				break out
			}
		}
		break
	}
	if state.Response == nil {
		return ActionGoBack
	}
	if strings.HasPrefix(string(state.Response.Header.Code), "3") { // Redirect
		return handleRedirectResponse(state)
	}
	state.RedirectCount = 0
	if strings.HasPrefix(string(state.Response.Header.Code), "6") { // Client certificate required
		return handleClientCertificateResponse(state)
	}
	if strings.HasPrefix(string(state.Response.Header.Code), "1") { // Input
		text, ok := NewInput(state.Screen, state.Response.Header.Meta, "").Focus()
		if !ok {
			return ActionDisplay
		}
		// Post the input back.
		state.U.RawQuery = url.QueryEscape(text)
		state.URL = state.U.String()
		return ActionNavigate
	}
	if strings.HasPrefix(string(state.Response.Header.Code), "2") { // Success
		handleSuccessResponse(state)
		return ActionDisplay
	}
	NewOptions(state.Screen, fmt.Sprintf("Error returned by server\n\nURL: %v\nCode: %v\nMeta: %s", state.U.String(), state.Response.Header.Code, state.Response.Header.Meta), "OK").Focus()
	return ActionDisplay
}

func handleActionDisplay(state *State) (action Action) {
	if state.History.Current() == nil {
		return ActionHome
	}
	browserAction, navigateTo, err := state.History.Current().Focus()
	if err != nil {
		NewOptions(state.Screen, fmt.Sprintf("Error displaying URL\n\nURL: %v\nMessage: %v", navigateTo, err), "OK").Focus()
		return ActionGoBack
	}
	if browserAction == ActionNavigate {
		if navigateTo != nil {
			if navigateTo.Scheme != "gemini" {
				if open := NewOptions(state.Screen, fmt.Sprintf("Open in browser?\n\n %v", navigateTo.String()), "Yes", "No").Focus(); open == "Yes" {
					browser.OpenURL(navigateTo.String())
				}
				state.History.Back()
				return ActionNavigate
			}
			state.URL = navigateTo.String()
			state.U = navigateTo
		}
	}
	return browserAction
}

func handleClientCertificateResponse(state *State) Action {
	msg := fmt.Sprintf("The server has requested a certificate\n\nURL: %s\nCode: %s\nMeta: %s", state.U.String(), state.Response.Header.Code, state.Response.Header.Meta)
	certificateOption := NewOptions(state.Screen, msg, "Create (Permanent)", "Create (Temporary)", "Cancel").Focus()
	if certificateOption == "Cancel" {
		return ActionDisplay
	}
	permanent := strings.Contains(certificateOption, "Permanent")
	duration := time.Hour * 24
	if permanent {
		duration *= 365 * 200
	}
	cert, key, _ := cert.Generate("", "", "", duration)
	keyPair, err := tls.X509KeyPair(cert, key)
	if err != nil {
		NewOptions(state.Screen, fmt.Sprintf("Error creating certificate: %v", err), "Continue").Focus()
		return ActionDisplay
	}
	prefix := ClientCertPrefix(state.U.Scheme + "://" + state.U.Host + state.U.Path)
	state.Client.AddClientCertificate(string(prefix), keyPair)
	if permanent {
		if err = prefix.Save(cert, key); err != nil {
			NewOptions(state.Screen, fmt.Sprintf("Error saving certificate: %v", err), "Continue").Focus()
			return ActionDisplay
		}
		state.Conf.ClientCertPrefixes[prefix] = struct{}{}
		if err = state.Conf.Save(); err != nil {
			NewOptions(state.Screen, fmt.Sprintf("Error saving configuration: %v", err), "Continue").Focus()
			return ActionDisplay
		}
	}
	return ActionNavigate
}

func handleRedirectResponse(state *State) Action {
	state.RedirectCount++
	if state.RedirectCount >= 5 {
		if keepTrying := NewOptions(state.Screen, fmt.Sprintf("The server issued 5 redirects, keep trying?"), "Keep Trying", "Cancel").Focus(); keepTrying == "Keep Trying" {
			state.RedirectCount = 0
			return ActionNavigate
		}
		return ActionDisplay
	}
	redirectTo, err := url.Parse(state.Response.Header.Meta)
	if err != nil {
		NewOptions(state.Screen, fmt.Sprintf("The server returned an invalid redirect URL\n\nURL: %v\nCode: %v\nMeta: %s", state.U.String(), state.Response.Header.Code, state.Response.Header.Meta), "Cancel").Focus()
		return ActionDisplay
	}
	// Check with the user if the redirect is to another protocol or domain.
	redirectTo = state.U.ResolveReference(redirectTo)
	if redirectTo.Scheme != "gemini" {
		if open := NewOptions(state.Screen, fmt.Sprintf("Follow non-gemini redirect?\n\n %v", redirectTo.String()), "Yes", "No").Focus(); open == "Yes" {
			browser.OpenURL(redirectTo.String())
		}
		return ActionDisplay
	}
	if redirectTo.Host != state.U.Host {
		if open := NewOptions(state.Screen, fmt.Sprintf("Follow cross-domain redirect?\n\n %v", redirectTo.String()), "Yes", "No").Focus(); open == "No" {
			return ActionAskForURL
		}
	}
	state.URL = redirectTo.String()
	state.U = redirectTo
	return ActionNavigate
}

func handleSuccessResponse(state *State) {
	meta := state.Response.Header.Meta
	if meta == "" {
		meta = "text/gemini; charset=utf-8"
	}
	mediaType, params, err := mime.ParseMediaType(meta)
	if err != nil {
		NewOptions(state.Screen, fmt.Sprintf("Server returned invalid MIME type: %v", err), "OK").Focus()
		return
	}
	if !(mediaType == "text/gemini" || mediaType == "text/plain") {
		fileName := getFileNameFromURL(state.U, mediaType)
		tmp := path.Join(os.TempDir(), fileName)
		err := atomic.WriteFile(tmp, state.Response.Body)
		if err != nil {
			NewOptions(state.Screen, fmt.Sprintf("Failed to save file: %v", err), "OK").Focus()
			return
		}
		switch NewOptions(state.Screen, fmt.Sprintf("Server returned a %q file (%v)\n\n%s", meta, fileName, state.U.String()), "Open", "Keep", "Discard").Focus() {
		case "Open":
			browser.OpenFile(tmp)
		case "Keep":
			_, err = copy(tmp, fileName)
			if err != nil {
				NewOptions(state.Screen, fmt.Sprintf("Failed to save file: %v", err), "OK").Focus()
				return
			}
		case "Discard":
			os.Remove(tmp)
		}
		return
	}
	// Use the charset to load the content.
	var cs string
	cs, ok := params["charset"]
	if !ok || cs == "us-ascii" { // Remove us-ascii check at next Go release https://github.com/golang/text/commit/a8b4671254579a87fadf9f7fa577dc7368e9d009
		cs = "utf-8"
	}
	e, err := ianaindex.MIME.Encoding(cs)
	if err != nil || e == nil {
		NewOptions(state.Screen, fmt.Sprintf("Unsupported character set %q: %v", cs, err), "OK").Focus()
		return
	}
	r := transform.NewReader(state.Response.Body, e.NewDecoder())
	b, err := NewBrowser(state.Screen, state.Conf.Width, state.U, r)
	if err != nil {
		NewOptions(state.Screen, fmt.Sprintf("Error displaying server response: %v", err), "OK").Focus()
		return
	}
	if err = state.History.Add(b); err != nil {
		NewOptions(state.Screen, fmt.Sprintf("Unable to persist history to disk: %v", err), "OK").Focus()
	}
	return
}

func copy(src, dst string) (int64, error) {
	sourceFileStat, err := os.Stat(src)
	if err != nil {
		return 0, err
	}
	if !sourceFileStat.Mode().IsRegular() {
		return 0, fmt.Errorf("%s is not a regular file", src)
	}
	source, err := os.Open(src)
	if err != nil {
		return 0, err
	}
	defer source.Close()
	destination, err := os.Create(dst)
	if err != nil {
		return 0, err
	}
	defer destination.Close()
	nBytes, err := io.Copy(destination, source)
	return nBytes, err
}

func getFileNameFromURL(u *url.URL, mimeType string) string {
	fileName := path.Base(u.String())
	if fileName == "." {
		fileName = fmt.Sprintf("download_%d", time.Now().Unix())
	}
	if path.Ext(fileName) == "" {
		extensions, _ := mime.ExtensionsByType(mimeType)
		if len(extensions) > 0 {
			fileName += extensions[0]
		}
	}
	return fileName
}

// flow breaks up text to its maximum width.
func flow(s string, maxWidth int) []string {
	var ss []string
	flowProcessor(s, maxWidth, func(line string) {
		ss = append(ss, line)
	})
	return ss
}

func flowProcessor(s string, maxWidth int, out func(string)) {
	var buf strings.Builder
	var col int
	var lastSpace int
	for _, r := range s {
		if r == '\r' {
			continue
		}
		if r == '\n' {
			out(buf.String())
			buf.Reset()
			col = 0
			lastSpace = 0
			continue
		}
		buf.WriteRune(r)
		if unicode.IsSpace(r) {
			lastSpace = col
		}
		if col == maxWidth {
			// If the word is greater than the width, then break the word down.
			end := lastSpace
			if end == 0 {
				end = col
			}
			out(strings.TrimSpace(buf.String()[:end]))
			prefix := strings.TrimSpace(buf.String()[end:])
			buf.Reset()
			lastSpace = 0
			buf.WriteString(prefix)
			col = len(prefix)
			continue
		}
		col++
	}
	out(buf.String())
}

func NewText(s tcell.Screen, text string) *Text {
	return &Text{
		Screen: s,
		X:      0,
		Y:      0,
		Style:  defaultStyle,
		Text:   text,
	}
}

type Text struct {
	Screen   tcell.Screen
	X        int
	Y        int
	MaxWidth int
	Style    tcell.Style
	Text     string
}

func (t *Text) WithOffset(x, y int) *Text {
	t.X = x
	t.Y = y
	return t
}

func (t *Text) WithMaxWidth(x int) *Text {
	t.MaxWidth = x
	return t
}

func (t *Text) WithStyle(st tcell.Style) *Text {
	t.Style = st
	return t
}

func (t *Text) Draw() (x, y int) {
	maxX, _ := t.Screen.Size()
	maxWidth := maxX - t.X
	if t.MaxWidth > 0 && maxWidth > t.MaxWidth {
		maxWidth = t.MaxWidth
	}
	lines := flow(t.Text, maxWidth)
	var requiredMaxWidth int
	for lineIndex := 0; lineIndex < len(lines); lineIndex++ {
		y = t.Y + lineIndex
		x = t.X
		for _, c := range lines[lineIndex] {
			var comb []rune
			w := runewidth.RuneWidth(c)
			if w == 0 {
				comb = []rune{c}
				c = ' '
				w = 1
			}
			t.Screen.SetContent(x, y, c, comb, t.Style)
			x += w
			if x > requiredMaxWidth {
				requiredMaxWidth = x
			}
		}
	}
	return requiredMaxWidth, y
}

type Choice struct {
	Index  int
	Option string
}

func ChoiceOptionIndex(options ...string) (op []string) {
	op = make([]string, len(options))
	for i := range options {
		op[i] = strconv.FormatInt(int64(i), 10)
	}
	return op
}

func choiceIndex(options []string, s string) (index int, matchesPrefix bool) {
	index = -1
	for i, c := range options {
		if c == s {
			index = i
			continue
		}
		if strings.HasPrefix(c, s) {
			matchesPrefix = true
		}
	}
	return
}

func NewChoice(options ...string) (runes chan rune, selection chan Choice, closer func()) {
	var buffer string
	runes = make(chan rune)
	selection = make(chan Choice)

	var ctx context.Context
	ctx, closer = context.WithCancel(context.Background())
	go func(ctx context.Context) {
		defer close(runes)
		defer close(selection)
		index := -1
		var matchesPrefix bool
		for {
			select {
			case <-time.After(time.Millisecond * 200):
				if index > -1 {
					selection <- Choice{Index: index, Option: options[index]}
					index = -1
				}
				buffer = ""
			case r := <-runes:
				buffer += string(r)
				index, matchesPrefix = choiceIndex(options, buffer)
				if index < 0 {
					buffer = ""
					continue
				}
				if matchesPrefix {
					continue // Wait to see if any more is typed in.
				}
				selection <- Choice{Index: index, Option: options[index]}
				index = -1
				buffer = ""
			case <-ctx.Done():
				return
			}
		}
	}(ctx)
	return
}

func NewOptions(s tcell.Screen, msg string, opts ...string) *Options {
	cancelIndex := -1
	for i, o := range opts {
		if o == "Cancel" || o == "Exit" {
			cancelIndex = i
			break
		}
	}
	return &Options{
		Screen:      s,
		Style:       defaultStyle,
		Message:     msg,
		Options:     opts,
		CancelIndex: cancelIndex,
	}
}

type Options struct {
	Screen      tcell.Screen
	X           int
	Y           int
	Style       tcell.Style
	Message     string
	Options     []string
	ActiveIndex int
	CancelIndex int
}

func (o *Options) Draw() {
	o.Screen.Clear()
	t := NewText(o.Screen, o.Message)
	_, y := t.Draw()
	for i, oo := range o.Options {
		style := defaultStyle
		var prefix = " "
		if i == o.ActiveIndex {
			style = defaultStyle.Background(tcell.ColorGray)
			prefix = ">"
		}
		NewText(o.Screen, fmt.Sprintf("%s [%d] %s", prefix, i, oo)).WithOffset(1, i+y+2).WithStyle(style).Draw()
	}
}

func (o *Options) Up() {
	if o.ActiveIndex == 0 {
		o.ActiveIndex = len(o.Options) - 1
		return
	}
	o.ActiveIndex--
}

func (o *Options) Down() {
	if o.ActiveIndex == len(o.Options)-1 {
		o.ActiveIndex = 0
		return
	}
	o.ActiveIndex++
}

func (o *Options) Focus() string {
	runes, selection, closer := NewChoice(ChoiceOptionIndex(o.Options...)...)
	defer closer()
	go func() {
		for choice := range selection {
			o.ActiveIndex = choice.Index
			o.Screen.PostEvent(nil)
		}
	}()
	o.Draw()
	o.Screen.Show()
	for {
		switch ev := o.Screen.PollEvent().(type) {
		case *tcell.EventResize:
			o.Screen.Sync()
		case *tcell.EventKey:
			switch ev.Key() {
			case tcell.KeyBacktab:
				o.Up()
			case tcell.KeyTab:
				o.Down()
			case tcell.KeyUp:
				o.Up()
			case tcell.KeyDown:
				o.Down()
			case tcell.KeyEscape:
				if o.CancelIndex > -1 {
					return o.Options[o.CancelIndex]
				}
			case tcell.KeyRune:
				runes <- ev.Rune()
			case tcell.KeyEnter:
				return o.Options[o.ActiveIndex]
			}
		}
		o.Draw()
		o.Screen.Show()
	}
}

func NewLineConverter(r io.Reader, width int) *LineConverter {
	return &LineConverter{
		Reader:   r,
		MaxWidth: width,
	}
}

type LineConverter struct {
	Reader       io.Reader
	MaxWidth     int
	preFormatted bool
}

func (lc *LineConverter) process(s string) (l Line, isVisualLine bool) {
	if strings.HasPrefix(s, "```") {
		lc.preFormatted = !lc.preFormatted
		return l, false
	}
	if lc.preFormatted {
		return PreformattedTextLine{Text: s}, true
	}
	if strings.HasPrefix(s, "=>") {
		return LinkLine{Text: s, MaxWidth: lc.MaxWidth}, true
	}
	if strings.HasPrefix(s, "#") {
		return HeadingLine{Text: s, MaxWidth: lc.MaxWidth}, true
	}
	if strings.HasPrefix(s, "* ") {
		return UnorderedListItemLine{Text: s, MaxWidth: lc.MaxWidth}, true
	}
	if strings.HasPrefix(s, ">") {
		return QuoteLine{Text: s, MaxWidth: lc.MaxWidth}, true
	}
	return TextLine{Text: s, MaxWidth: lc.MaxWidth}, true
}

func (lc *LineConverter) Lines() (lines []Line, err error) {
	reader := bufio.NewReader(lc.Reader)
	var s string
	for {
		s, err = reader.ReadString('\n')
		line, isVisual := lc.process(strings.TrimRight(s, "\n"))
		if isVisual {
			lines = append(lines, line)
		}
		if err != nil {
			break
		}
	}
	if err == io.EOF {
		err = nil
	}
	return
}

type Line interface {
	Draw(to tcell.Screen, atX, atY int, highlighted bool) (x, y int)
}

type TextLine struct {
	Text     string
	MaxWidth int
}

func (l TextLine) Draw(to tcell.Screen, atX, atY int, highlighted bool) (x, y int) {
	return NewText(to, l.Text).WithOffset(atX, atY).WithMaxWidth(l.MaxWidth).Draw()
}

type PreformattedTextLine struct {
	Text string
}

func (l PreformattedTextLine) Draw(to tcell.Screen, atX, atY int, highlighted bool) (x, y int) {
	for _, c := range l.Text {
		var comb []rune
		w := runewidth.RuneWidth(c)
		if w == 0 {
			comb = []rune{c}
			c = ' '
			w = 1
		}
		to.SetContent(atX, atY, c, comb, preformattedStyle)
		atX += w
	}
	return atX, atY
}

type LinkLine struct {
	Text     string
	MaxWidth int
}

func (l LinkLine) URL(relativeTo *url.URL) (u *url.URL, err error) {
	var urlString []rune
	for _, r := range strings.TrimSpace(strings.TrimPrefix(l.Text, "=>")) {
		if unicode.IsSpace(r) {
			break
		}
		urlString = append(urlString, r)
	}
	u, err = url.Parse(string(urlString))
	if err != nil {
		return
	}
	if relativeTo == nil {
		return
	}
	return relativeTo.ResolveReference(u), nil
}

func (l LinkLine) Draw(to tcell.Screen, atX, atY int, highlighted bool) (x, y int) {
	ls := defaultStyle.Foreground(tcell.ColorDarkCyan)
	if highlighted {
		ls = ls.Background(tcell.ColorWhite).Foreground(tcell.ColorDarkCyan)
	}
	return NewText(to, l.Text).WithOffset(atX+2, atY).WithMaxWidth(l.MaxWidth).WithStyle(ls).Draw()
}

type HeadingLine struct {
	Text     string
	MaxWidth int
}

func (l HeadingLine) Draw(to tcell.Screen, atX, atY int, highlighted bool) (x, y int) {
	return NewText(to, l.Text).WithOffset(atX, atY).WithMaxWidth(l.MaxWidth).WithStyle(defaultStyle.Foreground(tcell.ColorGreen)).Draw()
}

type UnorderedListItemLine struct {
	Text     string
	MaxWidth int
}

func (l UnorderedListItemLine) Draw(to tcell.Screen, atX, atY int, highlighted bool) (x, y int) {
	return NewText(to, l.Text).WithOffset(atX+2, atY).WithMaxWidth(l.MaxWidth).Draw()
}

type QuoteLine struct {
	Text     string
	MaxWidth int
}

func (l QuoteLine) Draw(to tcell.Screen, atX, atY int, highlighted bool) (x, y int) {
	return NewText(to, l.Text).WithOffset(atX+2, atY).WithMaxWidth(l.MaxWidth).WithStyle(defaultStyle.Foreground(tcell.ColorLightGrey)).Draw()
}

func NewBrowser(s tcell.Screen, w int, u *url.URL, r io.Reader) (b *Browser, err error) {
	b = &Browser{
		Screen:          s,
		URL:             u,
		ActiveLineIndex: -1,
	}
	maxWidth, _ := s.Size()
	if maxWidth > w {
		maxWidth = w
	}
	b.Lines, err = NewLineConverter(r, maxWidth).Lines()
	b.LineYIndices = make([]int, len(b.Lines))
	b.calculateLinkIndices()
	return
}

type Browser struct {
	Screen          tcell.Screen
	URL             *url.URL
	Lines           []Line
	ScrollX         int
	MinScrollX      int
	ScrollY         int
	MinScrollY      int
	LinkLineIndices []int
	ActiveLineIndex int
	LineYIndices    []int
}

func (b *Browser) ScrollLeft(by int) {
	if b.ScrollX < 0 {
		b.ScrollX += by
		if b.ScrollX > 0 {
			b.ScrollX = 0
		}
	}
}

func (b *Browser) ScrollRight(by int) {
	if b.ScrollX > b.MinScrollX {
		b.ScrollX -= by
		if b.ScrollX < b.MinScrollX {
			b.ScrollX = b.MinScrollX
		}
	}
}

func (b *Browser) ScrollUp(by int) {
	if b.ScrollY < 0 {
		b.ScrollY += by
		if b.ScrollY > 0 {
			b.ScrollY = 0
		}
	}
}

func (b *Browser) ScrollDown(by int) {
	if b.ScrollY > b.MinScrollY {
		b.ScrollY -= by
		if b.ScrollY < b.MinScrollY {
			b.ScrollY = b.MinScrollY
		}
	}
}

func (b *Browser) calculateLinkIndices() {
	for i := 0; i < len(b.Lines); i++ {
		if _, ok := b.Lines[i].(LinkLine); ok {
			b.LinkLineIndices = append(b.LinkLineIndices, i)
		}
	}
}

func (b *Browser) CurrentLink() (u *url.URL, err error) {
	for i := 0; i < len(b.Lines); i++ {
		if i == b.ActiveLineIndex {
			if ll, ok := b.Lines[b.ActiveLineIndex].(LinkLine); ok {
				return ll.URL(b.URL)
			}
		}
	}
	return nil, nil
}

func (b *Browser) PreviousLink() {
	if len(b.LinkLineIndices) == 0 {
		return
	}
	defer b.ScrollToLink()
	if b.ActiveLineIndex < 0 {
		b.ActiveLineIndex = b.LinkLineIndices[len(b.LinkLineIndices)-1]
		return
	}
	var curIndex, li int
	for curIndex, li = range b.LinkLineIndices {
		if li == b.ActiveLineIndex {
			break
		}
	}
	if curIndex == 0 {
		b.ActiveLineIndex = b.LinkLineIndices[len(b.LinkLineIndices)-1]
		return
	}
	b.ActiveLineIndex = b.LinkLineIndices[curIndex-1]
}

func (b *Browser) NextLink() {
	if len(b.LinkLineIndices) == 0 {
		return
	}
	defer b.ScrollToLink()
	if b.ActiveLineIndex < 0 {
		b.ActiveLineIndex = b.LinkLineIndices[0]
		return
	}
	var curIndex, li int
	for curIndex, li = range b.LinkLineIndices {
		if li == b.ActiveLineIndex {
			break
		}
	}
	if curIndex == len(b.LinkLineIndices)-1 {
		b.ActiveLineIndex = b.LinkLineIndices[0]
		return
	}
	b.ActiveLineIndex = b.LinkLineIndices[curIndex+1]
}

func (b *Browser) ScrollToLink() {
	lineYIndex := b.LineYIndices[b.ActiveLineIndex]
	_, h := b.Screen.Size()
	if lineYIndex >= h {
		b.ScrollDown(lineYIndex - h + 1)
	}
	if lineYIndex < 0 {
		b.ScrollUp(lineYIndex*-1 + h)
	}
}

func (b *Browser) Draw() {
	b.Screen.Clear()
	var maxX int
	x := b.ScrollX
	y := b.ScrollY
	for lineIndex, line := range b.Lines {
		highlighted := lineIndex == b.ActiveLineIndex
		b.LineYIndices[lineIndex] = y
		xx, yy := line.Draw(b.Screen, x, y, highlighted)
		if xx > maxX {
			maxX = xx
		}
		y = yy + 1
	}
	// Calculate the maximum scroll area.
	w, h := b.Screen.Size()
	b.MinScrollX = (maxX * -1) + b.ScrollX + w
	b.MinScrollY = (y * -1) + b.ScrollY + h + 1
}

func (b *Browser) Focus() (next Action, navigateTo *url.URL, err error) {
	b.Draw()
	b.Screen.Sync()
	for {
		switch ev := b.Screen.PollEvent().(type) {
		case *tcell.EventResize:
			b.Screen.Sync()
		case *tcell.EventKey:
			switch ev.Key() {
			case tcell.KeyEscape:
				return
			case tcell.KeyBacktab:
				b.PreviousLink()
			case tcell.KeyTAB:
				b.NextLink()
			case tcell.KeyCtrlO:
				b.PreviousLink()
			case tcell.KeyEnter:
				next = ActionNavigate
				navigateTo, err = b.CurrentLink()
				return
			case tcell.KeyHome:
				b.ScrollX = 0
			case tcell.KeyEnd:
				b.ScrollX = b.MinScrollX
			case tcell.KeyLeft:
				b.ScrollLeft(1)
			case tcell.KeyUp:
				b.ScrollUp(1)
			case tcell.KeyDown:
				b.ScrollDown(1)
			case tcell.KeyRight:
				b.ScrollRight(1)
			case tcell.KeyCtrlU:
				_, h := b.Screen.Size()
				b.ScrollUp(h / 2)
			case tcell.KeyCtrlD:
				_, h := b.Screen.Size()
				b.ScrollDown(h / 2)
			case tcell.KeyPgUp:
				b.ScrollUp(5)
			case tcell.KeyPgDn:
				b.ScrollDown(5)
			case tcell.KeyCtrlH:
				next = ActionViewHistory
				return
			case tcell.KeyCtrlL:
				next = ActionAskForURL
				return
			case tcell.KeyRune:
				switch ev.Rune() {
				case 'b':
					next = ActionToggleBookmark
					return
				case 'B':
					next = ActionViewBookmarks
					return
				case 'q':
					return
				case 'g':
					b.ScrollY = 0
				case 'G':
					b.ScrollY = b.MinScrollY
				case 'H':
					next = ActionGoBack
					return
				case 'L':
					next = ActionGoForward
					return
				case 'h':
					b.ScrollLeft(1)
				case 'j':
					b.ScrollDown(1)
				case 'k':
					b.ScrollUp(1)
				case 'l':
					b.ScrollRight(1)
				case 'n':
					b.NextLink()
				case '?':
					next = ActionViewHelp
					return
				}
			}
		}
		b.Draw()
		b.Screen.Show()
	}
}

func ParseVisit(s string) (v Visit, err error) {
	parts := strings.SplitN(s, "\t", 2)
	if len(parts) != 2 {
		return
	}
	v.Time, err = time.Parse(time.RFC3339, parts[0])
	if err != nil {
		return
	}
	v.URL = parts[1]
	return
}

func readVisits(fileName string) (visits []Visit, err error) {
	lines, err := readLines(fileName)
	if err != nil {
		return
	}
	for _, s := range lines {
		var v Visit
		v, err = ParseVisit(s)
		if err != nil {
			err = fmt.Errorf("history: couldn't parse visit: %w", err)
			return
		}
		visits = append(visits, v)
	}
	return
}

type Visit struct {
	Time time.Time
	URL  string
}

func (v Visit) TabDelimited() string {
	return fmt.Sprintf("%s\t%s\n", v.Time.Format(time.RFC3339), v.URL)
}

func (v Visit) Gemini() string {
	return fmt.Sprintf("=> %s (Visited: %s)\n", v.URL, v.Time.Format(time.RFC3339))
}

func NewBookmarks(fileName string) (b *Bookmarks, closer func() error, err error) {
	b = &Bookmarks{
		entries: map[string]Visit{},
	}
	// Read bookmarks.
	visits, err := readVisits(fileName)
	if err != nil {
		return
	}
	for _, v := range visits {
		b.entries[v.URL] = v
	}
	// Save file on close.
	closer = func() error {
		buf := new(bytes.Buffer)
		for _, v := range b.entries {
			fmt.Fprintf(buf, v.TabDelimited())
		}
		os.MkdirAll(path.Dir(fileName), os.ModePerm)
		return atomic.WriteFile(fileName, buf)
	}
	return
}

type Bookmarks struct {
	entries map[string]Visit
}

func (b *Bookmarks) Contains(u *url.URL) bool {
	s := u.String()
	_, ok := b.entries[s]
	return ok
}

func (b *Bookmarks) Remove(u *url.URL) {
	delete(b.entries, u.String())
}

func (b *Bookmarks) Add(u *url.URL) {
	if u.Scheme == "min" {
		return
	}
	s := u.String()
	b.entries[s] = Visit{
		URL:  u.String(),
		Time: time.Now(),
	}
}

func (b *Bookmarks) All() (u *url.URL, resp *gemini.Response) {
	u = &url.URL{Scheme: "min", Opaque: "bookmarks"}
	bdy := new(bytes.Buffer)
	io.WriteString(bdy, "# Bookmarks\n\n")
	var keys []string
	for s := range b.entries {
		keys = append(keys, s)
	}
	keys = sort.StringSlice(keys)
	for _, key := range keys {
		io.WriteString(bdy, b.entries[key].Gemini())
	}
	resp = &gemini.Response{
		Header: &gemini.Header{Code: gemini.CodeSuccess},
		Body:   ioutil.NopCloser(bdy),
	}
	return
}

func NewHistory(size int, historyFileName string) (h *History, closer func(), err error) {
	h = &History{
		max:      size,
		past:     []Visit{},
		browsers: []*Browser{},
	}
	// Read past history.
	h.past, err = readVisits(historyFileName)
	if err != nil {
		return
	}
	// Open file to add to history.
	h.f, err = os.OpenFile(historyFileName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	closer = func() {
		h.f.Sync()
		h.f.Close()
	}
	return
}

type History struct {
	max      int
	past     []Visit
	browsers []*Browser
	index    int
	f        *os.File
}

func (h *History) Current() (b *Browser) {
	if h.index < len(h.browsers) {
		return h.browsers[h.index]
	}
	return nil
}

func (h *History) Back() {
	if h.index > 0 {
		h.index--
	}
}

func (h *History) Forward() {
	h.index++
	if h.index >= len(h.browsers) {
		h.index = len(h.browsers) - 1
	}
}

func (h *History) Add(b *Browser) error {
	// If we've gone back, remove future URLs and replace with this.
	if h.index < len(h.browsers)-1 {
		h.browsers = h.browsers[0 : h.index+1]
	}
	// Remove an browsers that are over the max count.
	if len(h.browsers) == h.max && h.max > 0 {
		h.browsers = h.browsers[1:]
	}
	h.browsers = append(h.browsers, b)
	h.index = len(h.browsers) - 1
	// Persist it, if it's not history or bookmarks.
	if b.URL.Scheme == "min" {
		return nil
	}
	v := Visit{
		URL:  b.URL.String(),
		Time: time.Now(),
	}
	h.past = append(h.past, v)
	_, err := fmt.Fprintf(h.f, v.TabDelimited())
	return err
}

func (h *History) All() (u *url.URL, resp *gemini.Response) {
	u = &url.URL{Scheme: "min", Opaque: "history"}
	bdy := new(bytes.Buffer)
	io.WriteString(bdy, "# History\n\n")
	for _, s := range byTimeDescending(h.past) {
		io.WriteString(bdy, s.Gemini())
	}
	resp = &gemini.Response{
		Header: &gemini.Header{Code: gemini.CodeSuccess},
		Body:   ioutil.NopCloser(bdy),
	}
	return
}

func byTimeDescending(views []Visit) []Visit {
	sort.Slice(views, func(i, j int) bool {
		return views[j].Time.Before(views[i].Time)
	})
	return views
}

func NewInput(s tcell.Screen, msg, text string) *Input {
	return &Input{
		Screen:      s,
		X:           0,
		Y:           0,
		Style:       defaultStyle,
		Message:     msg,
		Text:        text,
		CursorIndex: len(text),
	}
}

type Input struct {
	Screen      tcell.Screen
	X           int
	Y           int
	Style       tcell.Style
	Message     string
	Text        string
	CursorIndex int
	ActiveIndex int
}

func (o *Input) Draw() {
	o.Screen.Clear()
	_, y := NewText(o.Screen, o.Message).WithOffset(o.X, o.Y).WithStyle(o.Style).Draw()

	if o.ActiveIndex == 0 {
		NewText(o.Screen, ">").WithOffset(o.X, o.Y+y+2).WithStyle(defaultStyle).Draw()
	}
	NewText(o.Screen, o.Text).WithOffset(o.X+2, o.Y+y+2).WithStyle(defaultStyle).Draw()
	if o.ActiveIndex == 0 {
		o.Screen.ShowCursor(o.X+2+o.CursorIndex, o.Y+y+2)
	} else {
		o.Screen.HideCursor()
	}

	activeStyle := defaultStyle.Background(tcell.ColorGray)
	okStyle := defaultStyle
	if o.ActiveIndex == 1 {
		okStyle = activeStyle
	}
	NewText(o.Screen, "[ OK ]").WithOffset(1, o.Y+y+4).WithStyle(okStyle).Draw()

	cancelStyle := defaultStyle
	if o.ActiveIndex == 2 {
		cancelStyle = activeStyle
	}
	NewText(o.Screen, "[ Cancel ]").WithOffset(1, o.Y+y+5).WithStyle(cancelStyle).Draw()
}

func (o *Input) Up() {
	if o.ActiveIndex == 0 {
		o.ActiveIndex = 2
		return
	}
	o.ActiveIndex--
}

func (o *Input) Down() {
	if o.ActiveIndex == 2 {
		o.ActiveIndex = 0
		return
	}
	o.ActiveIndex++
}

type InputResult string

func (o *Input) Focus() (text string, ok bool) {
	o.Draw()
	o.Screen.Show()
	for {
		if o.ActiveIndex == 0 {
			// Handle textbox keys.
			switch ev := o.Screen.PollEvent().(type) {
			case *tcell.EventResize:
				o.Screen.Sync()
			case *tcell.EventKey:
				switch ev.Key() {
				case tcell.KeyBackspace:
					if o.CursorIndex > 0 {
						o.CursorIndex--
						o.Text = cut(o.Text, o.CursorIndex)
					}
				case tcell.KeyBackspace2:
					if o.CursorIndex > 0 {
						o.CursorIndex--
						o.Text = cut(o.Text, o.CursorIndex)
					}
				case tcell.KeyLeft:
					if o.CursorIndex > 0 {
						o.CursorIndex--
					}
				case tcell.KeyRight:
					if o.CursorIndex < len(o.Text) {
						o.CursorIndex++
					}
				case tcell.KeyDelete:
					o.Text = cut(o.Text, o.CursorIndex)
				case tcell.KeyHome:
					o.CursorIndex = 0
				case tcell.KeyEnd:
					o.CursorIndex = len(o.Text)
				case tcell.KeyRune:
					o.Text = insert(o.Text, o.CursorIndex, ev.Rune())
					o.CursorIndex++
				case tcell.KeyBacktab:
					o.Up()
				case tcell.KeyEscape:
					o.Down()
				case tcell.KeyTab:
					o.Down()
				case tcell.KeyDown:
					o.Down()
				case tcell.KeyEnter:
					o.Down()
				}
			}
			o.Draw()
			o.Screen.Show()
			continue
		}
		switch ev := o.Screen.PollEvent().(type) {
		case *tcell.EventResize:
			o.Screen.Sync()
		case *tcell.EventKey:
			switch ev.Key() {
			case tcell.KeyBacktab:
				o.Up()
			case tcell.KeyTab:
				o.Down()
			case tcell.KeyUp:
				o.Up()
			case tcell.KeyDown:
				o.Down()
			case tcell.KeyEnter:
				switch o.ActiveIndex {
				case 0:
					o.ActiveIndex = 1
					break
				case 1:
					return o.Text, true
				case 2:
					return o.Text, false
				}
			case tcell.KeyEscape:
				return o.Text, false
			case tcell.KeyRune:
				switch ev.Rune() {
				case 'q':
					return o.Text, false
				}
			}
		}
		o.Draw()
		o.Screen.Show()
	}
}

func cut(s string, at int) string {
	prefix, suffix := split(s, at)
	if len(suffix) > 0 {
		suffix = suffix[1:]
	}
	return prefix + suffix
}

func split(s string, at int) (prefix, suffix string) {
	if at > len(s) {
		prefix = s
		return
	}
	prefix = string([]rune(s)[:at])
	suffix = string([]rune(s)[at:])
	return
}

func insert(s string, at int, r rune) string {
	prefix, suffix := split(s, at)
	return prefix + string(r) + suffix
}

const helpText = `# Help

## Navigation

n/Tab            Next link / option
Ctrl-O/Shift+Tab Previous link / option
Enter            Navigate to selected link
H                Navigate backwards in history
L                Navigate forwards in history
Esc              Exit

## Features

b                Toggle bookmark
B                View bookmarks
Ctrl-H           View history
?                View help

## Scrolling

g                Scroll to top of document
G                Scroll to end of document
←/h              Scroll left
↓/j              Scroll down
↑/k              Scroll up
→/l              Scroll right
Home             Scroll home horizontally
End              Scroll end horizontally
Ctrl-U           Scroll up half a screen
Ctrl-D           Scroll down half a screen

## Configuration

### config.ini

* Stored at $HOME/.min/config.ini
* Consists of key/value pairs (e.g. "width=80")
* Contains previously accepted server certificates
* Contains links to client certificates, stored in the same directory

## history.tsv

* Stores previously visited URLs

## boomarks.tsv

* Stores bookmarks
`

func Help() (u *url.URL, resp *gemini.Response) {
	u = &url.URL{Scheme: "min", Opaque: "help"}
	buf := bytes.NewBufferString(helpText)
	resp = &gemini.Response{
		Header: &gemini.Header{Code: gemini.CodeSuccess},
		Body:   ioutil.NopCloser(buf),
	}
	return
}
