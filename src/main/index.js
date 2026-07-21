import { app, BrowserWindow, dialog, ipcMain, Menu, screen } from 'electron';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import Store from 'electron-store';
import { ProjectService } from './project-service.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const store = new Store({ name: 'settings', defaults: { introSeen: false, recentProjects: [], windowState: null } });
let windowRef;
let projects;

const defaultWindowState = { width: 1380, height: 900 };

function isFiniteNumber(value) {
  return typeof value === 'number' && Number.isFinite(value);
}

function isVisibleOnConnectedDisplay(bounds) {
  return screen.getAllDisplays().some(({ workArea }) => (
    bounds.x < workArea.x + workArea.width
    && bounds.x + bounds.width > workArea.x
    && bounds.y < workArea.y + workArea.height
    && bounds.y + bounds.height > workArea.y
  ));
}

function getSavedWindowState() {
  const saved = store.get('windowState');
  if (!saved || !isFiniteNumber(saved.width) || !isFiniteNumber(saved.height)) return defaultWindowState;

  const state = {
    width: Math.max(1050, Math.round(saved.width)),
    height: Math.max(700, Math.round(saved.height))
  };
  if (isFiniteNumber(saved.x) && isFiniteNumber(saved.y)) {
    const bounds = { ...state, x: Math.round(saved.x), y: Math.round(saved.y) };
    if (isVisibleOnConnectedDisplay(bounds)) Object.assign(state, { x: bounds.x, y: bounds.y });
  }
  return state;
}

function saveWindowState(window) {
  const bounds = window.isMaximized() ? window.getNormalBounds() : window.getBounds();
  store.set('windowState', { ...bounds, isMaximized: window.isMaximized() });
}

function createWindow() {
  const savedState = getSavedWindowState();
  const wasMaximized = store.get('windowState')?.isMaximized;
  const window = new BrowserWindow({
    ...savedState,
    show: false,
    minWidth: 1050,
    minHeight: 700,
    frame: true,
    icon: path.join(here, '../../Logo/logo.ico'),
    titleBarStyle: process.platform === 'darwin' ? 'hiddenInset' : undefined,
    backgroundColor: '#f5f5f7',
    webPreferences: {
      preload: path.join(here, '../preload/index.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false
    }
  });
  windowRef = window;
  window.once('close', () => saveWindowState(window));
  if (wasMaximized) window.maximize();
  window.once('ready-to-show', () => window.show());
  window.loadFile(path.join(here, '../renderer/index.html'));
}

app.whenReady().then(() => {
  Menu.setApplicationMenu(null);
  projects = new ProjectService({ store, send: (channel, payload) => windowRef?.webContents.send(channel, payload) });
  createWindow();
  app.on('activate', () => { if (BrowserWindow.getAllWindows().length === 0) createWindow(); });
});

app.on('window-all-closed', () => { if (process.platform !== 'darwin') app.quit(); });

ipcMain.handle('app:get-state', () => ({ introSeen: store.get('introSeen') }));
ipcMain.handle('app:finish-intro', () => store.set('introSeen', true));
ipcMain.handle('project:list-recent', () => store.get('recentProjects', []));
ipcMain.handle('project:open', async (_event, suppliedPath) => {
  let projectPath = suppliedPath;
  if (!projectPath) {
    const result = await dialog.showOpenDialog(windowRef, { properties: ['openDirectory'] });
    if (result.canceled) return null;
    [projectPath] = result.filePaths;
  }
  return projects.open(projectPath);
});
ipcMain.handle('scan:start', (_event, projectId) => projects.startScan(projectId));
ipcMain.handle('project:set-check-active', (_event, projectId, checkId, active) => projects.setCheckActive(projectId, checkId, active));
ipcMain.handle('project:get-packages', (_event, projectId, force) => projects.getPackages(projectId, force));
ipcMain.handle('project:get-overview', (_event, projectId) => projects.getOverview(projectId));
ipcMain.handle('project:get-time-machine', (_event, projectId) => projects.getTimeMachine(projectId));
ipcMain.handle('project:get-evolution-forecast', (_event, projectId) => projects.getEvolutionForecast(projectId));
ipcMain.handle('project:get-awards', (_event, projectId) => projects.getAwards(projectId));
ipcMain.handle('project:manage-package', (_event, projectId, packageId, action) => projects.managePackage(projectId, packageId, action));
ipcMain.handle('issue:delete-empty-artifact', (_event, projectId, issueId) => projects.deleteEmptyArtifact(projectId, issueId));
ipcMain.handle('issue:fix-via-codex', (_event, projectId, issueId, useFlightPlan) => projects.fixViaCodex(projectId, issueId, useFlightPlan));
ipcMain.handle('issue:fix-check-via-codex', (_event, projectId, checkId, issueIds) => projects.fixCheckViaCodex(projectId, checkId, issueIds));
ipcMain.handle('project:chat-with-codex', (_event, projectId, request) => projects.chatWithCodex(projectId, request));
ipcMain.handle('issue:get-commit', (_event, projectId, issueId) => projects.getIssueCommit(projectId, issueId));
ipcMain.handle('issue:get-repair-flight-plan', (_event, projectId, issueId) => projects.getRepairFlightPlan(projectId, issueId));
ipcMain.handle('issue:get-fix-prompt', (_event, issueId) => projects.getFixPrompt(issueId));
ipcMain.handle('issue:highlight', (_event, issueId) => projects.highlight(issueId));
ipcMain.handle('window:minimize', () => windowRef?.minimize());
ipcMain.handle('window:toggle-maximize', () => { if (!windowRef) return false; windowRef.isMaximized() ? windowRef.unmaximize() : windowRef.maximize(); return windowRef.isMaximized(); });
ipcMain.handle('window:close', () => windowRef?.close());
ipcMain.handle('window:is-maximized', () => windowRef?.isMaximized() ?? false);
ipcMain.handle('project:open-external', async (_event, target) => {
  const { shell } = await import('electron');
  return shell.openPath(target);
});
