// DataGhost Content Script
// Multi-layer Login & Sign-in Detection Engine

(function () {
    if (window.__dataghost_injected) return;
    window.__dataghost_injected = true;

    // Helper: Resolve relative URL to absolute
    function resolveUrl(url) {
        try {
            return new URL(url, window.location.href).href;
        } catch {
            return window.location.href;
        }
    }

    // Helper: Detect search engine results page
    function isSearchEnginePage() {
        const host = window.location.hostname.toLowerCase();
        const path = window.location.pathname.toLowerCase();
        const search = window.location.search.toLowerCase();

        if ((host.includes('google.') || host.includes('google.co.')) && (path.startsWith('/search') || search.includes('q='))) return true;
        if (host.includes('duckduckgo.com') && (search.includes('q=') || path.length > 1)) return true;
        if (host.includes('bing.com') && (path.startsWith('/search') || search.includes('q='))) return true;
        if (host.includes('search.yahoo.com') || (host.includes('yahoo.com') && path.startsWith('/search'))) return true;
        if (host.includes('ecosia.org') && search.includes('q=')) return true;
        if (host.includes('search.brave.com')) return true;

        return false;
    }

    // Multi-Layer Login & Sign-in Scanner
    function scanForLoginFeatures() {
        const signals = [];
        let hasPassword = false;
        let hasAuthInput = false;
        let hasSSO = false;
        let authType = null; // 'login' | 'signup'
        let primaryFormTarget = null;
        let isFormTargetCrossOrigin = false;

        // 1. Check for Password Inputs (The most definitive signal)
        const passwordInputs = document.querySelectorAll('input[type="password"]');
        if (passwordInputs.length > 0) {
            hasPassword = true;
            signals.push(`Password field detected (${passwordInputs.length})`);
        }

        // 2. Check for Autocomplete hints (current-password, new-password, username)
        const autocompleteInputs = document.querySelectorAll(
            'input[autocomplete*="password"], input[autocomplete="username"], input[autocomplete="email"]'
        );
        if (autocompleteInputs.length > 0) {
            hasAuthInput = true;
            signals.push('Credential autocomplete attributes present');
        }

        // 3. Check for Username / Email inputs inside an auth context
        const userInputs = document.querySelectorAll(
            'input[name*="user" i], input[name*="login" i], input[name*="email" i], ' +
            'input[id*="username" i], input[id*="login" i], input[id*="email" i]'
        );
        if (userInputs.length > 0 && (hasPassword || autocompleteInputs.length > 0)) {
            hasAuthInput = true;
        }

        // 4. Check for Federated / Social Single Sign-On (SSO) Buttons
        const ssoButtons = document.querySelectorAll(
            'button, a[role="button"], a.btn, div[role="button"]'
        );
        for (const btn of ssoButtons) {
            const text = (btn.innerText || btn.getAttribute('aria-label') || '').toLowerCase();
            if (text.includes('sign in with') || text.includes('log in with') ||
                text.includes('continue with google') || text.includes('continue with apple') ||
                text.includes('continue with facebook') || text.includes('continue with github') ||
                text.includes('continue with microsoft') || text.includes('single sign-on') || text.includes('sso')) {
                hasSSO = true;
                signals.push(`SSO button detected: "${text.trim().slice(0, 24)}"`);
                break;
            }
        }

        // 5. Inspect Forms & Target Actions
        const forms = document.querySelectorAll('form');
        for (const form of forms) {
            const hasPassInForm = form.querySelector('input[type="password"]');
            const hasUserInForm = form.querySelector('input[name*="user" i], input[name*="login" i], input[name*="email" i]');
            
            if (hasPassInForm || hasUserInForm) {
                const rawAction = form.getAttribute('action') || '';
                const resolvedAction = resolveUrl(rawAction);
                try {
                    const actionUrl = new URL(resolvedAction);
                    primaryFormTarget = actionUrl.hostname;
                    isFormTargetCrossOrigin = actionUrl.hostname !== window.location.hostname;
                } catch {}
                break;
            }
        }

        // 6. Check URL & Headings to distinguish Login vs Sign Up
        const url = window.location.href.toLowerCase();
        const path = window.location.pathname.toLowerCase();
        const title = (document.title || '').toLowerCase();

        if (url.includes('signup') || url.includes('register') || url.includes('join') || url.includes('create-account') ||
            title.includes('sign up') || title.includes('create account') || title.includes('register')) {
            authType = 'signup';
        } else if (hasPassword || hasAuthInput || hasSSO || url.includes('login') || url.includes('signin') || title.includes('sign in') || title.includes('log in')) {
            authType = 'login';
        }

        const isLoginPresent = Boolean(hasPassword || hasAuthInput || hasSSO || (forms.length > 0 && authType));

        return {
            hasLogin: isLoginPresent,
            authType: authType,
            hasPassword: hasPassword,
            hasSSO: hasSSO,
            primaryFormTarget: primaryFormTarget,
            isFormTargetCrossOrigin: isFormTargetCrossOrigin,
            signals: signals
        };
    }

    // Run passive scan and inform background
    function runScan() {
        const isSearch = isSearchEnginePage();
        const loginData = scanForLoginFeatures();

        chrome.runtime.sendMessage({
            type: 'PAGE_FORMS_ANALYSIS',
            payload: {
                pageUrl: window.location.href,
                pageHost: window.location.hostname,
                isPageHttp: window.location.protocol === 'http:',
                isSearchEngine: isSearch,
                loginData: loginData
            }
        }).catch(() => {});
    }

    const reportedPasswordFields = new WeakSet();
    document.addEventListener('input', event => {
        const field = event.target;
        if (!event.isTrusted || !(field instanceof HTMLInputElement) || field.type !== 'password') return;
        if (event.inputType && !event.inputType.startsWith('insert')) return;
        if (reportedPasswordFields.has(field)) return;
        reportedPasswordFields.add(field);

        chrome.runtime.sendMessage({ type: 'PASSWORD_FIELD_USED' })
            .then(response => {
                if (!response?.ok) reportedPasswordFields.delete(field);
            })
            .catch(() => reportedPasswordFields.delete(field));
    }, true);

    // Initial scan
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', runScan);
    } else {
        runScan();
    }

    // Debounced mutation observer for dynamic apps
    let scanTimeout;
    const observer = new MutationObserver(() => {
        clearTimeout(scanTimeout);
        scanTimeout = setTimeout(runScan, 700);
    });

    try {
        observer.observe(document.body || document.documentElement, {
            childList: true,
            subtree: true
        });
    } catch {}
})();
