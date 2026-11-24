import {
  DefaultCrossWindowChannel,
  LAST_KNOWN_EMBEDDER_ORIGIN_STORAGE_KEY,
  __require,
  escapeCssQuotedValue,
  storageAvailable
} from "./chunk-PUEHXZBG.js";

// src/utils/insertScript.ts
var insertScript = async (src, nonce = "") => {
  const script = document.createElement("script");
  script.src = src;
  script.nonce = nonce;
  return new Promise((resolve, reject) => {
    script.onerror = reject;
    script.onload = () => resolve(script);
    document.head.appendChild(script);
  });
};

// src/utils/insertMeta.ts
var insertMeta = (id, jsonSetting) => {
  const meta = document.createElement("meta");
  meta.id = id;
  meta.setAttribute("data-settings", JSON.stringify(jsonSetting));
  document.head.appendChild(meta);
  return meta;
};

// src/utils/getRepoRoot.ts
var getRepoRoot = (projectPath) => {
  const slashIdx = projectPath.lastIndexOf("/");
  if (slashIdx < 0) {
    return projectPath;
  }
  return projectPath.slice(slashIdx + 1);
};

// src/utils/kebabCase.ts
var pascalOrCamelCaseBoundary = /\B([A-Z])/g;
var kebabCase = (str) => str.replace(pascalOrCamelCaseBoundary, "-$1").toLowerCase();

// src/utils/loadGitLabFonts.ts
var getFontPreloadElements = (fontFace) => fontFace.src.map((src) => {
  const linkElement = document.createElement("link");
  linkElement.setAttribute("rel", "preload");
  linkElement.setAttribute("as", "font");
  linkElement.setAttribute("type", `font/${src.format}`);
  linkElement.setAttribute("crossorigin", "");
  linkElement.setAttribute("href", src.url);
  return linkElement;
});
var getFontFaceDefinition = (fontFace) => {
  const keys = Object.keys(fontFace);
  const fontFaceBody = keys.filter((key) => fontFace[key] && key !== "src").map((key) => {
    switch (key) {
      case "display":
      case "family":
      case "featureSettings":
      case "stretch":
      case "style":
      case "weight": {
        const value = key === "family" ? `'${escapeCssQuotedValue(fontFace[key])}'` : fontFace[key];
        return `font-${kebabCase(key)}: ${value};`;
      }
      default:
        return `${kebabCase(key)}: ${fontFace[key]};`;
    }
  });
  const srcDeclarations = fontFace.src.map((src, idx) => {
    const url = escapeCssQuotedValue(src.url);
    const format = escapeCssQuotedValue(src.format);
    const prefix = idx > 0 ? "  " : "";
    return `${prefix}url('${url}') format('${format}')`;
  }).join(",\n");
  fontFaceBody.push(`src: ${srcDeclarations};`);
  return `@font-face {
${fontFaceBody.join("\n")}
}`;
};
var generateFontFaceStyleElement = (fontFaces) => {
  const styleElement = document.createElement("style");
  styleElement.innerHTML = fontFaces.map(getFontFaceDefinition).join("\n");
  return styleElement;
};
var loadGitLabFonts = (fontFaces) => {
  if (!fontFaces || fontFaces.length === 0) return;
  fontFaces.flatMap(getFontPreloadElements).forEach((element) => {
    document.head.appendChild(element);
  });
  document.head.appendChild(generateFontFaceStyleElement(fontFaces));
};

// ../logger/src/constants.ts
var LOG_LEVEL_NAMES = {
  [1 /* Trace */]: "trace",
  [2 /* Debug */]: "debug",
  [3 /* Info */]: "info",
  [4 /* Warn */]: "warn",
  [5 /* Error */]: "error"
};

// ../logger/src/Logger.ts
var Logger = class {
  #minLevel;
  #writer;
  constructor(options) {
    this.#minLevel = options.minLevel === void 0 ? 2 /* Debug */ : options.minLevel;
    this.#writer = options.writer;
  }
  trace(...message) {
    this.#writeLog(1 /* Trace */, message);
  }
  debug(...message) {
    this.#writeLog(2 /* Debug */, message);
  }
  info(...message) {
    this.#writeLog(3 /* Info */, message);
  }
  warn(...message) {
    this.#writeLog(4 /* Warn */, message);
  }
  error(...message) {
    this.#writeLog(5 /* Error */, message);
  }
  #writeLog(level, message) {
    if (level < this.#minLevel) {
      return;
    }
    this.#writer.log(level, ...message);
  }
};

// ../logger/src/ConsoleLogWriter.ts
var ConsoleLogWriter = class {
  // eslint-disable-next-line class-methods-use-this
  log(level, ...message) {
    switch (level) {
      case 1 /* Trace */:
        console.trace(...message);
        break;
      case 2 /* Debug */:
        console.debug(...message);
        break;
      case 3 /* Info */:
        console.info(...message);
        break;
      case 4 /* Warn */:
        console.warn(...message);
        break;
      case 5 /* Error */:
        console.error(...message);
        break;
      default:
        console.log(...message);
        break;
    }
  }
};

// ../logger/src/factory.ts
var createConsoleLogger = (options = {}) => new Logger({
  ...options,
  writer: new ConsoleLogWriter()
});
var defaultLogger = createConsoleLogger();

// src/utils/purgeClientStorage.ts
async function deleteAllIndexedDBDatabases() {
  if (typeof indexedDB === "undefined" || !indexedDB) {
    return;
  }
  try {
    const databases = await indexedDB.databases();
    const namedDatabases = databases.filter((dbInfo) => dbInfo.name);
    if (namedDatabases.length === 0) {
      defaultLogger.info("No IndexedDB databases found to delete");
      return;
    }
    const deletionPromises = namedDatabases.map((dbInfo) => {
      const { name = "" } = dbInfo;
      return new Promise((resolve, reject) => {
        const deleteRequest = indexedDB.deleteDatabase(name);
        deleteRequest.onsuccess = () => {
          defaultLogger.info(`Successfully deleted database: ${name}`);
          resolve();
        };
        deleteRequest.onerror = () => {
          const requestError = deleteRequest.error?.message ?? "unknown error";
          const error = new Error(
            `Failed to delete database (${name}) due to error: "${requestError}"`
          );
          defaultLogger.error(error.message);
          reject(error);
        };
        deleteRequest.onblocked = () => {
          const error = new Error(
            `Failed to delete database (${name}) because it is in use. Please close all tabs running the Web IDE.`
          );
          defaultLogger.error(error.message);
          reject(error);
        };
      });
    });
    await Promise.all(deletionPromises);
    defaultLogger.info("All IndexedDB databases have been deleted successfully");
  } catch (error) {
    defaultLogger.error("Error during IndexedDB cleanup");
    throw error;
  }
}
async function purgeClientStorage() {
  if (storageAvailable("localStorage")) {
    localStorage.clear();
    defaultLogger.info("All localStorage data has been cleared");
  }
  if (storageAvailable("sessionStorage")) {
    sessionStorage.clear();
    defaultLogger.info("All sessionStorage data has been cleared");
  }
  await deleteAllIndexedDBDatabases();
}

// src/handleEmbedderChange.ts
var handleEmbedderChange = async (message) => {
  if (storageAvailable("localStorage")) {
    const lastKnownOrigin = localStorage.getItem(LAST_KNOWN_EMBEDDER_ORIGIN_STORAGE_KEY);
    const currentOrigin = message.origin || "";
    if (lastKnownOrigin && lastKnownOrigin !== currentOrigin) {
      defaultLogger.info(
        "Detected embedder origin change, purging web browser storage and registering new origin"
      );
      await purgeClientStorage();
    }
    localStorage.setItem(LAST_KNOWN_EMBEDDER_ORIGIN_STORAGE_KEY, currentOrigin);
  } else {
    const error = Error(
      "LocalStorage is not available and is required to proceed with the Web IDE Workbench initialization"
    );
    defaultLogger.error(error.message);
    throw error;
  }
  return message;
};

// src/amd/configRequire.ts
var configRequire = (config) => __require.config(config);

// src/main.ts
var SCRIPT_VSCODE_AMD_LOADER = "vscode/out/vs/loader.js";
var SCRIPT_VSCODE_WORKBENCH_NLS = "vscode/out/nls.messages.js";
var SCRIPT_VSCODE_WORKBENCH = "vscode/out/vs/workbench/workbench.web.main.js";
var getExtensionConfig = async (config, extensionPath) => {
  const extensionPackageJSONUrl = `${config.workbenchBaseUrl}/vscode/extensions/${extensionPath}/package.json`;
  const rawJson = await fetch(extensionPackageJSONUrl).then((x) => x.text());
  const packageJSON = JSON.parse(rawJson);
  return {
    extensionPath,
    packageJSON
  };
};
var getBuiltInExtensions = async (config) => Promise.all([
  getExtensionConfig(config, "gitlab-web-ide"),
  getExtensionConfig(config, "gitlab-language-support-vue"),
  getExtensionConfig(config, "gitlab-vscode-extension"),
  getExtensionConfig(config, "gitlab-vscode-theme")
]);
var setupNavigatorKeyboard = () => {
  if (navigator.keyboard) {
    Object.assign(navigator.keyboard, {
      getLayoutMap: () => Promise.resolve(/* @__PURE__ */ new Map())
    });
  }
};
var setupAMDRequire = async (config) => {
  await insertScript(`${config.workbenchBaseUrl}/${SCRIPT_VSCODE_AMD_LOADER}`, config.nonce);
  const vscodeUrl = `${config.workbenchBaseUrl}/vscode`;
  configRequire({
    baseUrl: `${vscodeUrl}/out`,
    recordStats: true,
    trustedTypesPolicy: window.trustedTypes?.createPolicy("amdLoader", {
      createScriptURL(value) {
        if (value.startsWith(vscodeUrl)) {
          return value;
        }
        throw new Error(`Invalid script url: ${value}`);
      }
    })
  });
};
var main = async () => {
  const windowChannel = new DefaultCrossWindowChannel({
    localWindow: window,
    remoteWindow: window.parent,
    remoteWindowOrigin: "*"
  });
  try {
    windowChannel.postMessage({ key: "web-ide-config-request" });
    const initWorkbenchMessage = await handleEmbedderChange(
      await windowChannel.waitForMessage("web-ide-config-response")
    );
    const config = JSON.parse(initWorkbenchMessage.params.config);
    await fetch(`${config.gitlabUrl}/api/graphql`, {
      mode: "cors",
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({})
    });
    windowChannel.postMessage({ key: "web-ide-cors-success-response" });
    loadGitLabFonts(config.editorFont?.fontFaces);
    const extensionList = await getBuiltInExtensions(config);
    insertMeta("gitlab-builtin-vscode-extensions", extensionList);
    setupNavigatorKeyboard();
    await setupAMDRequire(config);
    await Promise.all([
      insertScript(`${config.workbenchBaseUrl}/${SCRIPT_VSCODE_WORKBENCH_NLS}`, config.nonce),
      insertScript(`${config.workbenchBaseUrl}/${SCRIPT_VSCODE_WORKBENCH}`, config.nonce)
    ]);
    const { start } = await import("./start-JDBUQXFO.js");
    if (config) {
      await start({
        ...config,
        repoRoot: getRepoRoot(config.projectPath)
      });
    } else {
      throw new Error(`Unexpected config (${config}) when trying to start VSCode.`);
    }
    windowChannel.postMessage({ key: "ready" });
  } catch (e) {
    windowChannel.postMessage({
      key: "error",
      params: { errorType: "start-workbench-failed" /* START_WORKBENCH_FAILED */, details: e.message }
    });
  }
};
export {
  main
};
//# sourceMappingURL=main.js.map
