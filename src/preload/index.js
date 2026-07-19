import { contextBridge, ipcRenderer } from 'electron';

contextBridge.exposeInMainWorld('api', {
  getAppState: () => ipcRenderer.invoke('app:get-state'),
  finishIntro: () => ipcRenderer.invoke('app:finish-intro'),
  openProjectDialog: () => ipcRenderer.invoke('project:open'),
  openProjectPath: (projectPath) => ipcRenderer.invoke('project:open', projectPath),
  listRecentProjects: () => ipcRenderer.invoke('project:list-recent'),
  runScan: (projectId) => ipcRenderer.invoke('scan:start', projectId),
  getFixPrompt: (issueId) => ipcRenderer.invoke('issue:get-fix-prompt', issueId),
  highlightIssue: (issueId) => ipcRenderer.invoke('issue:highlight', issueId),
  openExternal: (target) => ipcRenderer.invoke('project:open-external', target),
  onScanProgress: (callback) => ipcRenderer.on('scan:progress', (_event, data) => callback(data)),
  onScanResults: (callback) => ipcRenderer.on('scan:results', (_event, data) => callback(data))
});
