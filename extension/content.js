// PhishGuard content script — extracts page-level phishing signals and forwards to background.
// Runs at document_idle. Lightweight to avoid impacting page perf.

(function () {
  function extract() {
    const forms = Array.from(document.querySelectorAll("form"));
    const passwordFields = document.querySelectorAll('input[type="password"]').length;
    const externalForms = forms.filter((f) => {
      const action = f.getAttribute("action") || "";
      return action.startsWith("http") && !action.includes(location.hostname);
    }).length;
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
      iframeCount: iframes,
      externalScriptCount: externalScripts,
      visibleTextSample: visibleText,
    };
  }

  try {
    const features = extract();
    chrome.runtime.sendMessage({ type: "PAGE_FEATURES", features });
  } catch (e) {
    /* extension context invalidated — ignore */
  }
})();
