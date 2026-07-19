import { app, BrowserWindow, dialog, ipcMain, Menu } from 'electron';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import Store from 'electron-store';
import { ProjectService } from './project-service.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const store = new Store({ name: 'settings', defaults: { introSeen: false, recentProjects: [] } });
let windowRef;
let projects;

function createWindow() {
  windowRef = new BrowserWindow({
    width: 1380,
    height: 900,
    minWidth: 1050,
    minHeight: 700,
    frame: true,
    titleBarStyle: process.platform === 'darwin' ? 'hiddenInset' : undefined,
    backgroundColor: '#f5f5f7',
    webPreferences: {
      preload: path.join(here, '../preload/index.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false
    }
  });
  windowRef.loadFile(path.join(here, '../renderer/index.html'));
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
ipcMain.handle('project:get-packages', (_event, projectId, force) => projects.getPackages(projectId, force));
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
