import { contextBridge, ipcRenderer } from "electron";

contextBridge.exposeInMainWorld("api", {
  getAppState: () => ipcRenderer.invoke("app:get-state"),
  finishIntro: () => ipcRenderer.invoke("app:finish-intro"),
  openProjectDialog: () => ipcRenderer.invoke("project:open"),
  openProjectPath: (projectPath) =>
    ipcRenderer.invoke("project:open", projectPath),
  listRecentProjects: () => ipcRenderer.invoke("project:list-recent"),
  runScan: (projectId) => ipcRenderer.invoke("scan:start", projectId),
  setCheckActive: (projectId, checkId, active) => ipcRenderer.invoke("project:set-check-active", projectId, checkId, active),
  getPackages: (projectId, force = false) => ipcRenderer.invoke("project:get-packages", projectId, force),
  getOverview: (projectId) => ipcRenderer.invoke("project:get-overview", projectId),
  getTimeMachine: (projectId) => ipcRenderer.invoke("project:get-time-machine", projectId),
  getEvolutionForecast: (projectId) => ipcRenderer.invoke("project:get-evolution-forecast", projectId),
  getAwards: (projectId) => ipcRenderer.invoke("project:get-awards", projectId),
  managePackage: (projectId, packageId, action) => ipcRenderer.invoke("project:manage-package", projectId, packageId, action),
  deleteEmptyArtifact: (projectId, issueId) => ipcRenderer.invoke("issue:delete-empty-artifact", projectId, issueId),
  fixViaCodex: (projectId, issueId) => ipcRenderer.invoke("issue:fix-via-codex", projectId, issueId),
  fixCheckViaCodex: (projectId, checkId, issueIds) => ipcRenderer.invoke("issue:fix-check-via-codex", projectId, checkId, issueIds),
  getIssueCommit: (projectId, issueId) => ipcRenderer.invoke("issue:get-commit", projectId, issueId),
  getFixPrompt: (issueId) =>
    ipcRenderer.invoke("issue:get-fix-prompt", issueId),
  highlightIssue: (issueId) => ipcRenderer.invoke("issue:highlight", issueId),
  openExternal: (target) => ipcRenderer.invoke("project:open-external", target),
  onScanProgress: (callback) =>
    ipcRenderer.on("scan:progress", (_event, data) => callback(data)),
  onScanResults: (callback) =>
    ipcRenderer.on("scan:results", (_event, data) => callback(data)),
  onCodexProgress: (callback) =>
    ipcRenderer.on("codex:progress", (_event, data) => callback(data)),
});
