// PhishGuard content script extracts page-level phishing signals and forwards to background.
// Runs at document_idle. Lightweight to avoid impacting page perf.

(function () {
  function isExternalAction(action) {
    return action.startsWith("http") && !action.includes(location.hostname);
  }

  function extract() {
    const forms = Array.from(document.querySelectorAll("form"));
    const passwordFields = document.querySelectorAll('input[type="password"]').length;
    const externalForms = forms.filter((f) => isExternalAction(f.getAttribute("action") || "")).length;

    // The real credential-harvesting tell is a password field INSIDE a form that submits
    // cross-domain; not "a password field exists somewhere" plus "some unrelated form submits
    // externally" (an ordinary page with a login widget AND, say, a Mailchimp/Formspree/Google
    // Forms newsletter signup elsewhere would otherwise look identical to that pattern, and
    // that combination is extremely common on completely legitimate sites).
    const crossDomainPasswordForm = forms.some((f) => {
      const hasPassword = f.querySelector('input[type="password"]') !== null;
      return hasPassword && isExternalAction(f.getAttribute("action") || "");
    });

    const iframes = document.querySelectorAll("iframe").length;
    const externalScripts = Array.from(document.scripts).filter(
      (s) => s.src && !s.src.includes(location.hostname)
    ).length;
    const titleText = document.title || "";
    const visibleText = (document.body?.innerText || "").slice(0, 500);

    return {
      url: location.href,
      hostname: location.hostname,
      title: titleText,
      hasPasswordField: passwordFields > 0,
      passwordFieldCount: passwordFields,
      formCount: forms.length,
      externalFormSubmissions: externalForms,
      crossDomainPasswordForm,
      iframeCount: iframes,
      externalScriptCount: externalScripts,
      visibleTextSample: visibleText,
    };
  }

  try {
    const features = extract();
    chrome.runtime.sendMessage({ type: "PAGE_FEATURES", features });
  } catch (e) {
    /* extension context invalidated; ignore */
  }
})();
