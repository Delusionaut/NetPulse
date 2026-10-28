const { app, BrowserWindow, dialog } = require("electron");
const { spawn } = require("child_process");
const http = require("http");
const path = require("path");

const PORT = process.env.NETPULSE_PORT || "8765";
let engine = null;
let splash = null;
let mainWindow = null;

function engineDir() {
  if (app.isPackaged) {
    return path.join(process.resourcesPath, "engine");
  }
  return path.resolve(__dirname, "..", "..");
}

function staticDir() {
  if (app.isPackaged) {
    return path.join(process.resourcesPath, "app", "dist");
  }
  const built = path.resolve(__dirname, "..", "dist");
  return require("fs").existsSync(path.join(built, "index.html")) ? built : "";
}

function iconPath() {
  if (app.isPackaged) return path.join(process.resourcesPath, "assets", "NetPulse.ico");
  return path.resolve(__dirname, "..", "..", "assets", "NetPulse.ico");
}

function pythonCommand() {
  if (process.env.NETPULSE_PYTHON) return process.env.NETPULSE_PYTHON;
  return process.platform === "win32" ? "python" : "python3";
}

function startEngine() {
  const cwd = engineDir();
  const ui = staticDir();
  const env = {
    ...process.env,
    NETPULSE_PORT: PORT,
    NETPULSE_STATIC: ui || "none",
  };
  engine = spawn(pythonCommand(), ["app.py"], {
    cwd,
    env,
    windowsHide: true,
    stdio: ["ignore", "pipe", "pipe"],
  });
  engine.on("error", (err) => {
    dialog.showErrorBox("NetPulse", `Could not start Python (${pythonCommand()}): ${err.message}`);
  });
}

function healthcheck() {
  return new Promise((resolve) => {
    const req = http.get(`http://127.0.0.1:${PORT}/api/health`, (res) => {
      res.resume();
      resolve(res.statusCode === 200);
    });
    req.on("error", () => resolve(false));
    req.setTimeout(800, () => {
      req.destroy();
      resolve(false);
    });
  });
}

async function waitForApi() {
  const deadline = Date.now() + 20000;
  while (Date.now() < deadline) {
    if (await healthcheck()) return true;
    await new Promise((r) => setTimeout(r, 300));
  }
  return false;
}

function createSplash() {
  splash = new BrowserWindow({
    width: 460,
    height: 320,
    frame: false,
    resizable: false,
    center: true,
    transparent: false,
    backgroundColor: "#020617",
    show: true,
    icon: iconPath(),
    webPreferences: { contextIsolation: true, nodeIntegration: false },
  });
  splash.loadFile(path.join(__dirname, "splash.html"));
}

function createMain() {
  mainWindow = new BrowserWindow({
    width: 1380,
    height: 900,
    minWidth: 960,
    minHeight: 640,
    show: false,
    backgroundColor: "#020617",
    autoHideMenuBar: true,
    title: "NetPulse",
    icon: iconPath(),
    webPreferences: { contextIsolation: true, nodeIntegration: false },
  });
  mainWindow.loadURL(`http://127.0.0.1:${PORT}/`);
  mainWindow.once("ready-to-show", () => {
    if (splash && !splash.isDestroyed()) splash.close();
    mainWindow.show();
  });
  mainWindow.on("closed", () => {
    mainWindow = null;
  });
}

app.whenReady().then(async () => {
  createSplash();
  startEngine();
  const ok = await waitForApi();
  if (!ok) {
    dialog.showErrorBox(
      "NetPulse",
      "The local API did not start. Install Python 3.10+ and the packages in requirements.txt, then launch NetPulse again.",
    );
    app.quit();
    return;
  }
  createMain();
});

app.on("window-all-closed", () => {
  app.quit();
});

app.on("before-quit", () => {
  if (engine && !engine.killed) {
    engine.kill();
  }
});
