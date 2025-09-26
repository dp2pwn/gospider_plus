package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/go-rod/rod/lib/proto"
)

type BrowserPoolConfig struct {
	PoolSize           int
	NavigationTimeout  time.Duration
	StabilizationDelay time.Duration
	Headless           *bool
	InitScripts        []string
}

func resolveBrowserBinary(ctx context.Context) (string, error) {
	if candidate := strings.TrimSpace(os.Getenv("ROD_BROWSER")); candidate != "" {
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		} else {
			Logger.Warnf("ROD_BROWSER points to %s but cannot be used: %v", candidate, err)
		}
	}

	if bin, has := launcher.LookPath(); has {
		if _, err := os.Stat(bin); err == nil {
			return bin, nil
		}
	}

	browser := launcher.NewBrowser()
	if ctx != nil {
		browser.Context = ctx
	}
	browser.Logger = log.New(io.Discard, "", 0)

	path, err := browser.Get()
	if err != nil {
		return "", err
	}

	Logger.Infof("Downloaded Chromium to %s", path)
	return path, nil
}

type BrowserPool struct {
	cfg         BrowserPoolConfig
	headless    bool
	launcher    *launcher.Launcher
	browser     *rod.Browser
	sessions    []*rod.Browser
	pagePool    chan *rod.Page
	initOnce    sync.Once
	shutdownMu  sync.Mutex
	initialized bool
	ctx         context.Context
	cancel      context.CancelFunc
}

type PageAnalysisResult struct {
	URL         string
	StateHash   string
	Signature   uint64
	Digest      string
	IsNewState  bool
	APICalls    []string
	Transitions []StateTransition
}

func NewBrowserPool(cfg BrowserPoolConfig) *BrowserPool {
	if cfg.PoolSize <= 0 {
		cfg.PoolSize = 2
	}
	if cfg.NavigationTimeout <= 0 {
		cfg.NavigationTimeout = 12 * time.Second
	}
	if cfg.StabilizationDelay <= 0 {
		cfg.StabilizationDelay = 600 * time.Millisecond
	}
	headless := true
	if cfg.Headless != nil {
		headless = *cfg.Headless
	}
	return &BrowserPool{cfg: cfg, headless: headless}
}

func (bp *BrowserPool) Initialize(ctx context.Context) error {
	var initErr error
	bp.initOnce.Do(func() {
		initErr = bp.initialize(ctx)
	})
	return initErr
}

func (bp *BrowserPool) initialize(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	bp.ctx, bp.cancel = context.WithCancel(ctx)

	launch := launcher.New().Leakless(false).NoSandbox(true)
	if bp.headless {
		launch = launch.Headless(true)
	} else {
		launch = launch.Headless(false)
	}
	launch = launch.Set("disable-gpu", "1").Set("enable-features", "NetworkService,NetworkServiceInProcess")

	binaryPath, err := resolveBrowserBinary(bp.ctx)
	if err != nil {
		return fmt.Errorf("resolve browser binary: %w", err)
	}
	if binaryPath != "" {
		Logger.Debugf("Using Chromium binary %s", binaryPath)
		launch = launch.Bin(binaryPath)
		if err := os.Setenv("ROD_BROWSER", binaryPath); err != nil {
			Logger.Debugf("failed to set ROD_BROWSER: %v", err)
		}
	}

	controlURL, err := launch.Launch()
	if err != nil {
		return fmt.Errorf("launch browser: %w", err)
	}

	browser := rod.New().ControlURL(controlURL)
	if err := browser.Connect(); err != nil {
		launch.Kill()
		return fmt.Errorf("connect browser: %w", err)
	}

	sessions := make([]*rod.Browser, 0, bp.cfg.PoolSize)
	pages := make([]*rod.Page, 0, bp.cfg.PoolSize)

	cleanup := func() {
		for _, page := range pages {
			_ = page.Close()
		}
		for _, session := range sessions {
			_ = session.Close()
		}
		_ = browser.Close()
		launch.Kill()
	}

	for i := 0; i < bp.cfg.PoolSize; i++ {
		session, err := browser.Incognito()
		if err != nil {
			cleanup()
			return fmt.Errorf("create incognito session: %w", err)
		}
		page, err := session.Page(proto.TargetCreateTarget{URL: "about:blank"})
		if err != nil {
			_ = session.Close()
			cleanup()
			return fmt.Errorf("create page: %w", err)
		}
		if err := bp.applyInitScripts(page); err != nil {
			_ = page.Close()
			_ = session.Close()
			cleanup()
			return err
		}
		sessions = append(sessions, session)
		pages = append(pages, page)
	}

	bp.launcher = launch
	bp.browser = browser
	bp.sessions = sessions
	bp.pagePool = make(chan *rod.Page, len(pages))
	for _, page := range pages {
		bp.pagePool <- page
	}
	bp.initialized = true
	return nil
}

func (bp *BrowserPool) applyInitScripts(page *rod.Page) error {
	for _, scriptPath := range bp.cfg.InitScripts {
		if scriptPath == "" {
			continue
		}
		absPath, err := filepath.Abs(scriptPath)
		if err != nil {
			return fmt.Errorf("resolve init script path: %w", err)
		}
		content, err := os.ReadFile(absPath)
		if err != nil {
			return fmt.Errorf("read init script %s: %w", scriptPath, err)
		}
		if _, err := page.EvalOnNewDocument(string(content)); err != nil {
			return fmt.Errorf("inject init script %s: %w", scriptPath, err)
		}
	}
	return nil
}

func (bp *BrowserPool) AcquirePage(ctx context.Context) (*rod.Page, error) {
	if !bp.initialized {
		return nil, errors.New("browser pool not initialized")
	}
	if ctx == nil {
		ctx = bp.ctx
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case page := <-bp.pagePool:
		return page, nil
	}
}

func (bp *BrowserPool) ReleasePage(page *rod.Page) error {
	if page == nil {
		return nil
	}
	if !bp.initialized {
		return page.Close()
	}
	_ = page.Navigate("about:blank")
	select {
	case bp.pagePool <- page:
	default:
		_ = page.Close()
	}
	return nil
}

func (bp *BrowserPool) Shutdown(ctx context.Context) error {
	bp.shutdownMu.Lock()
	defer bp.shutdownMu.Unlock()
	if !bp.initialized {
		return nil
	}
	if bp.cancel != nil {
		bp.cancel()
	}
	if bp.pagePool != nil {
		close(bp.pagePool)
		for len(bp.pagePool) > 0 {
			page := <-bp.pagePool
			if page != nil {
				_ = page.Close()
			}
		}
		bp.pagePool = nil
	}
	for _, session := range bp.sessions {
		_ = session.Close()
	}
	bp.sessions = nil
	if bp.browser != nil {
		_ = bp.browser.Close()
		bp.browser = nil
	}
	if bp.launcher != nil {
		bp.launcher.Kill()
		bp.launcher = nil
	}
	bp.initialized = false
	return nil
}

func (bp *BrowserPool) NavigateAndAnalyze(ctx context.Context, url string, graph *ApplicationStateGraph) (*PageAnalysisResult, error) {
	if !bp.initialized {
		return nil, errors.New("browser pool not initialized")
	}
	if ctx == nil {
		ctx = bp.ctx
	}
	if graph == nil {
		return nil, errors.New("state graph is required")
	}
	page, err := bp.AcquirePage(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = bp.ReleasePage(page) }()

	apiSet := make(map[string]struct{})
	apiCalls := make([]string, 0, 8)
	var apiMu sync.Mutex
	stopEvents := page.EachEvent(func(e *proto.NetworkRequestWillBeSent) {
		if e.Type == proto.NetworkResourceTypeXHR || e.Type == proto.NetworkResourceTypeFetch {
			apiMu.Lock()
			if _, exists := apiSet[e.Request.URL]; !exists {
				apiSet[e.Request.URL] = struct{}{}
				apiCalls = append(apiCalls, e.Request.URL)
			}
			apiMu.Unlock()
		}
	})
	defer stopEvents()

	navCtx := page.Context(ctx)
	if bp.cfg.NavigationTimeout > 0 {
		navCtx = navCtx.Timeout(bp.cfg.NavigationTimeout)
	}
	if err := navCtx.Navigate(url); err != nil {
		return nil, fmt.Errorf("navigate %s: %w", url, err)
	}
	if err := navCtx.WaitLoad(); err != nil && !errors.Is(err, context.DeadlineExceeded) {
		return nil, fmt.Errorf("wait load %s: %w", url, err)
	}
	if bp.cfg.StabilizationDelay > 0 {
		select {
		case <-time.After(bp.cfg.StabilizationDelay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	htmlContent, err := page.HTML()
	if err != nil {
		return nil, fmt.Errorf("get html %s: %w", url, err)
	}

	stateHash, signature, digest, err := graph.CalculateDOMFingerprint(htmlContent)
	if err != nil {
		return nil, fmt.Errorf("fingerprint %s: %w", url, err)
	}
	isNew := graph.AddState(stateHash, url, signature, digest)

	transitions := make([]StateTransition, 0)
	if isNew {
		transitions, err = bp.extractTransitions(page)
		if err != nil {
			return nil, fmt.Errorf("extract transitions %s: %w", url, err)
		}
		if len(transitions) > 0 {
			graph.RegisterTransitions(stateHash, transitions)
		}
	}

	return &PageAnalysisResult{
		URL:         url,
		StateHash:   stateHash,
		Signature:   signature,
		Digest:      digest,
		IsNewState:  isNew,
		APICalls:    apiCalls,
		Transitions: transitions,
	}, nil
}

func (bp *BrowserPool) extractTransitions(page *rod.Page) ([]StateTransition, error) {
	const script = `(() => {
        const toSelector = (el) => {
            if (!el || !el.tagName) {
                return "";
            }
            const parts = [];
            let current = el;
            let depth = 0;
            while (current && current.tagName && depth < 6) {
                let selector = current.tagName.toLowerCase();
                if (current.id) {
                    selector += "#" + current.id;
                    parts.unshift(selector);
                    break;
                }
                if (current.classList && current.classList.length) {
                    selector += "." + Array.from(current.classList).slice(0, 2).join(".");
                }
                if (current.parentElement) {
                    const siblings = Array.from(current.parentElement.children).filter(node => node.tagName === current.tagName);
                    if (siblings.length > 1) {
                        const index = siblings.indexOf(current) + 1;
                        selector += ":nth-of-type(" + index + ")";
                    }
                }
                parts.unshift(selector);
                current = current.parentElement;
                depth++;
            }
            return parts.join(" > ");
        };

        const transitions = [];
        const anchors = Array.from(document.querySelectorAll('a[href]'));
        for (const anchor of anchors) {
            if (!anchor.href) continue;
            transitions.push({
                type: 'navigate',
                selector: toSelector(anchor),
                targetUrl: anchor.href
            });
        }
        const buttons = Array.from(document.querySelectorAll('button'));
        for (const button of buttons) {
            transitions.push({
                type: 'click',
                selector: toSelector(button),
                text: (button.innerText || '').trim().slice(0, 64)
            });
        }
        const forms = Array.from(document.forms);
        for (const form of forms) {
            const action = form.action || window.location.href;
            const method = (form.method || 'GET').toUpperCase();
            transitions.push({
                type: 'form',
                selector: toSelector(form),
                targetUrl: action,
                method
            });
        }
        return JSON.stringify(transitions);
    })()`

	result, err := page.Eval(script)
	if err != nil {
		return nil, err
	}
	rawJSON := result.Value.Str()
	if rawJSON == "" {
		if result.Value.Nil() {
			return nil, fmt.Errorf("empty transition payload")
		}
		rawJSON = result.Value.String()
	}
	var raw []map[string]string
	if err := json.Unmarshal([]byte(rawJSON), &raw); err != nil {
		return nil, err
	}
	transitions := make([]StateTransition, 0, len(raw))
	for _, item := range raw {
		action := item["type"]
		if action == "" {
			continue
		}
		details := make(map[string]string)
		for k, v := range item {
			if k == "type" {
				continue
			}
			details[k] = v
		}
		transitions = append(transitions, StateTransition{
			ActionType: action,
			Details:    details,
		})
	}
	return transitions, nil
}
