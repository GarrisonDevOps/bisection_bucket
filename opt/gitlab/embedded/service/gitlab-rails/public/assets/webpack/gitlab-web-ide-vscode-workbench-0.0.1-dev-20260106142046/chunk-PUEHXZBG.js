var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __require = /* @__PURE__ */ ((x) => typeof require !== "undefined" ? require : typeof Proxy !== "undefined" ? new Proxy(x, {
  get: (a, b) => (typeof require !== "undefined" ? require : a)[b]
}) : x)(function(x) {
  if (typeof require !== "undefined") return require.apply(this, arguments);
  throw Error('Dynamic require of "' + x + '" is not supported');
});
var __commonJS = (cb, mod) => function __require2() {
  return mod || (0, cb[__getOwnPropNames(cb)[0]])((mod = { exports: {} }).exports, mod), mod.exports;
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
  // If the importer is in node compatibility mode or this is not an ESM
  // file that has been converted to a CommonJS file using a Babel-
  // compatible transform (i.e. "__esModule" has not been set), then set
  // "default" to the CommonJS "module.exports" for node compatibility.
  isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
  mod
));

// ../cross-origin-channel/src/constants.ts
var WAIT_FOR_MESSAGE_TIMEOUT = 3e4;

// ../cross-origin-channel/src/DefaultPortChannel.ts
var DefaultPortChannel = class {
  messagePort;
  name;
  constructor({ name, messagePort }) {
    this.messagePort = messagePort;
    this.name = name;
  }
  dispose() {
    this.messagePort.close();
  }
  start() {
    this.messagePort.start();
  }
  addMessagesListener(callback) {
    const port = this.messagePort;
    const listener = (event) => {
      const message = event.data;
      callback(message);
    };
    port.addEventListener("message", listener);
    return {
      dispose() {
        port.removeEventListener("message", listener);
      }
    };
  }
  addMessageListener(messageKey, callback) {
    return this.addMessagesListener((message) => {
      if (message.key === messageKey) {
        callback(message);
      }
    });
  }
  postMessage(message) {
    this.messagePort.postMessage(message);
  }
  waitForMessage(messageKey, timeout = WAIT_FOR_MESSAGE_TIMEOUT) {
    return new Promise((resolve, reject) => {
      const disposable = this.addMessageListener(messageKey, (message) => {
        resolve(message);
        disposable.dispose();
      });
      setTimeout(() => {
        disposable.dispose();
        reject(new Error(`Channel timed out while waiting for message ${messageKey}`));
      }, timeout);
    });
  }
};

// ../cross-origin-channel/src/DefaultCrossWindowChannel.ts
var DefaultCrossWindowChannel = class {
  #localWindow;
  #remoteWindow;
  #remoteWindowOrigin;
  #messageChannels;
  #disposables;
  constructor({ localWindow, remoteWindow, remoteWindowOrigin }) {
    this.#localWindow = localWindow;
    this.#remoteWindow = remoteWindow;
    this.#remoteWindowOrigin = remoteWindowOrigin;
    this.#messageChannels = /* @__PURE__ */ new Map();
    this.#disposables = [];
    this.#disposables.push(
      this.addMessageListener("port-channel-request", (event) => {
        const { name } = event.params;
        const channel = this.#messageChannels.get(name);
        if (channel) {
          this.postMessage({ key: "port-channel-response", params: { name, port: channel.port2 } });
        } else {
          this.postMessage({
            key: "port-channel-response-error",
            params: { name, error: `Could not find a port with name ${name}` }
          });
        }
      })
    );
  }
  dispose() {
    this.#disposables.forEach((disposable) => {
      disposable.dispose();
    });
  }
  postMessage(message) {
    if (message.key === "port-channel-response") {
      this.#remoteWindow.postMessage(
        { key: message.key, params: { name: message.params.name } },
        this.#remoteWindowOrigin,
        [message.params.port]
      );
    } else {
      this.#remoteWindow.postMessage(message, this.#remoteWindowOrigin);
    }
  }
  addMessagesListener(callback) {
    const localWindow = this.#localWindow;
    const remoteWindowOrigin = this.#remoteWindowOrigin;
    const listener = (event) => {
      const message = { ...event.data, origin: event.origin };
      if (event.source !== this.#remoteWindow && event.origin !== remoteWindowOrigin) {
        return;
      }
      if (message.key === "port-channel-response") {
        callback({
          key: "port-channel-response",
          origin: message.origin,
          params: { name: message.params.name, port: event.ports[0] }
        });
      } else {
        callback(message);
      }
    };
    localWindow.addEventListener("message", listener);
    return {
      dispose() {
        localWindow.removeEventListener("message", listener);
      }
    };
  }
  addMessageListener(targetMessageKey, callback) {
    return this.addMessagesListener((message) => {
      if (message.key === targetMessageKey) {
        callback(message);
      }
    });
  }
  waitForMessage(targetMessageKey, timeout = WAIT_FOR_MESSAGE_TIMEOUT) {
    return new Promise((resolve, reject) => {
      const disposable = this.addMessageListener(targetMessageKey, (message) => {
        resolve(message);
        disposable.dispose();
      });
      setTimeout(() => {
        disposable.dispose();
        reject(new Error(`Channel timed out while waiting for message ${targetMessageKey}`));
      }, timeout);
    });
  }
  async requestRemotePortChannel(name) {
    this.postMessage({ key: "port-channel-request", params: { name } });
    const message = await this.waitForMessage("port-channel-response");
    return new DefaultPortChannel({ name, messagePort: message.params.port });
  }
  createLocalPortChannel(name) {
    let channel = this.#messageChannels.get(name);
    if (!channel) {
      channel = new MessageChannel();
      this.#messageChannels.set(name, channel);
    }
    return new DefaultPortChannel({ name, messagePort: channel.port1 });
  }
};

// ../utils-escape/src/escapeCssQuotedValue.ts
var escapeCssQuotedValue = (val) => val.replace('"', "%22").replace("'", "%27");

// src/constant.ts
var DEFAULT_SESSION_ID = "current-user";
var DEFAULT_DOCUMENTATION_URL = "https://docs.gitlab.com/ee/user/web_ide";
var LAST_KNOWN_EMBEDDER_ORIGIN_STORAGE_KEY = "last-known-web-ide-embedder-origin";

// src/utils/storageAvailable.ts
function storageAvailable(type) {
  let storage;
  try {
    storage = window[type];
    const x = "__storage_test__";
    storage.setItem(x, x);
    storage.removeItem(x);
    return true;
  } catch (e) {
    return e instanceof DOMException && // everything except Firefox
    (e.code === 22 || // Firefox
    e.code === 1014 || // test name field too, because code might not be present
    // everything except Firefox
    e.name === "QuotaExceededError" || // Firefox
    e.name === "NS_ERROR_DOM_QUOTA_REACHED") && // acknowledge QuotaExceededError only if there's something already stored
    storage && storage.length !== 0;
  }
}

export {
  __require,
  __commonJS,
  __toESM,
  DefaultCrossWindowChannel,
  escapeCssQuotedValue,
  storageAvailable,
  DEFAULT_SESSION_ID,
  DEFAULT_DOCUMENTATION_URL,
  LAST_KNOWN_EMBEDDER_ORIGIN_STORAGE_KEY
};
/**
 * Ported from mustache: https://github.com/janl/mustache.js/blob/v4.2.0/mustache.js#L60-L75
 * @license https://github.com/janl/mustache.js/blob/v4.2.0/LICENSE
 */
//# sourceMappingURL=chunk-PUEHXZBG.js.map
