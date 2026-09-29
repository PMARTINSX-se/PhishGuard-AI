// Exposes a small, safe bridge into the main process for the webapp/ renderer; contextIsolation
// stays on (no direct Node/Electron access from page JS), only this one explicit function crosses.
const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("phishguard", {
  isElectron: true,
  // suggestedName: string used as the default filename in the native Save dialog.
  // Resolves to { ok: true, filePath } on success, { ok: false, canceled: true } if the user
  // cancelled the dialog, or { ok: false, error } on failure.
  exportInvestigationPDF: (suggestedName) => ipcRenderer.invoke("export-investigation-pdf", suggestedName),
});
