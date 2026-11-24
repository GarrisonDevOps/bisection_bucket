const path = require('path');
const fs = require('fs');

const ROOT_PATH = path.resolve(__dirname, '..');
const WEBPACK_OUTPUT_PATH = path.join(ROOT_PATH, 'public/assets/webpack');
const WEBPACK_PUBLIC_PATH = '/assets/webpack/';
const SOURCEGRAPH_VERSION = require('@sourcegraph/code-host-integration/package.json').version;

const SOURCEGRAPH_PATH = path.join('sourcegraph', SOURCEGRAPH_VERSION, '/');
const SOURCEGRAPH_OUTPUT_PATH = path.join(WEBPACK_OUTPUT_PATH, SOURCEGRAPH_PATH);
const SOURCEGRAPH_PUBLIC_PATH = path.join(WEBPACK_PUBLIC_PATH, SOURCEGRAPH_PATH);

const GITLAB_WEB_IDE_VERSION = require('@gitlab/web-ide/package.json').version;
// The MFE's chunk names carry no content hash, so the version in the path is what keeps a
// cached chunk from one release being served to another.
const MFE_DUO_CHAT_VERSION = require('@gitlab-mfe/duo-chat/package.json').version;

const { pdfJsCopyFilesPatterns } = require('./pdfjs.constants');

const GITLAB_WEB_IDE_PATH = path.join(
  `gitlab-web-ide-vscode-workbench-${GITLAB_WEB_IDE_VERSION}`,
  '/',
);
const GITLAB_WEB_IDE_OUTPUT_PATH = path.join(WEBPACK_OUTPUT_PATH, GITLAB_WEB_IDE_PATH);
const GITLAB_WEB_IDE_PUBLIC_PATH = path.join(WEBPACK_PUBLIC_PATH, GITLAB_WEB_IDE_PATH);

const MFE_DUO_CHAT_PATH = path.join('mfes', `duo-chat-${MFE_DUO_CHAT_VERSION}`, '/');
const MFE_DUO_CHAT_OUTPUT_PATH = path.join(WEBPACK_OUTPUT_PATH, MFE_DUO_CHAT_PATH);
const MFE_DUO_CHAT_PUBLIC_PATH = path.join(WEBPACK_PUBLIC_PATH, MFE_DUO_CHAT_PATH);

const IS_EE = require('./helpers/is_ee_env');
const IS_JH = require('./helpers/is_jh_env');

const SOURCEGRAPH_PACKAGE = '@sourcegraph/code-host-integration';
const GITLAB_WEB_IDE_PACKAGE = '@gitlab/web-ide';
const MFE_DUO_CHAT_PACKAGE = '@gitlab-mfe/duo-chat';

// Determine Sidekiq assets path from environment variables.
// These are set by `rake gitlab:assets:compile` (see lib/tasks/gitlab/assets.rake).
function getSidekiqAssetsSourcePath() {
  const assetsPath = process.env.SIDEKIQ_ASSETS_SRC_PATH;

  if (!assetsPath) {
    return null;
  }

  if (!fs.existsSync(assetsPath)) {
    throw new Error(`Sidekiq assets path does not exist: ${assetsPath}`);
  }

  console.log(`Sidekiq assets path: ${assetsPath}`);

  return assetsPath;
}

function getSidekiqAssetsDestinationPath() {
  const sidekiqPath = process.env.SIDEKIQ_ASSETS_DEST_PATH;

  if (!sidekiqPath) {
    return null;
  }

  console.log(`Sidekiq destination subpath: ${sidekiqPath}`);
  const destPath = path.join(ROOT_PATH, sidekiqPath);
  console.log(`Sidekiq assets destination path: ${destPath}`);

  return destPath;
}

const SIDEKIQ_ASSETS_SOURCE = getSidekiqAssetsSourcePath();
const SIDEKIQ_ASSETS_DEST = getSidekiqAssetsDestinationPath();

// Sourcegraph and the Web IDE ship prebuilt bundles, so the minimizers skip them. Their CSS has
// rules Lightning CSS can't parse, which would fail the build.
const copyFilesPatterns = [
  ...pdfJsCopyFilesPatterns,
  {
    from: path.join(ROOT_PATH, 'node_modules', SOURCEGRAPH_PACKAGE, '/'),
    to: SOURCEGRAPH_OUTPUT_PATH,
    globOptions: {
      ignore: ['package.json'],
    },
    info: { minimized: true },
  },
  {
    from: path.join(ROOT_PATH, 'node_modules', GITLAB_WEB_IDE_PACKAGE, 'dist', 'public'),
    to: GITLAB_WEB_IDE_OUTPUT_PATH,
    toType: 'dir',
    info: { minimized: true },
  },
  {
    from: path.join(ROOT_PATH, 'node_modules', MFE_DUO_CHAT_PACKAGE, 'dist'),
    to: MFE_DUO_CHAT_OUTPUT_PATH,
    toType: 'dir',
    info: { minimized: true },
  },
  // Add Sidekiq assets if both source and destination are available
  ...(SIDEKIQ_ASSETS_SOURCE && SIDEKIQ_ASSETS_DEST
    ? [
        {
          from: SIDEKIQ_ASSETS_SOURCE,
          to: SIDEKIQ_ASSETS_DEST,
          toType: 'dir',
        },
      ]
    : []),
];

const IS_PRODUCTION = process.env.NODE_ENV === 'production';
const IS_DEV_SERVER = process.env.WEBPACK_SERVE === 'true';
const { DEV_SERVER_HOST, DEV_SERVER_PUBLIC_ADDR } = process.env;
const DEV_SERVER_PORT = parseInt(process.env.DEV_SERVER_PORT, 10);
const DEV_SERVER_ALLOWED_HOSTS =
  process.env.DEV_SERVER_ALLOWED_HOSTS && process.env.DEV_SERVER_ALLOWED_HOSTS.split(',');
const DEV_SERVER_LIVERELOAD = IS_DEV_SERVER && process.env.DEV_SERVER_LIVERELOAD !== 'false';

module.exports = {
  IS_EE,
  IS_JH,
  ROOT_PATH,
  WEBPACK_OUTPUT_PATH,
  WEBPACK_PUBLIC_PATH,
  SOURCEGRAPH_PUBLIC_PATH,
  GITLAB_WEB_IDE_PUBLIC_PATH,
  MFE_DUO_CHAT_PUBLIC_PATH,
  copyFilesPatterns,
  IS_PRODUCTION,
  IS_DEV_SERVER,
  DEV_SERVER_HOST,
  DEV_SERVER_PUBLIC_ADDR,
  DEV_SERVER_PORT,
  DEV_SERVER_ALLOWED_HOSTS,
  DEV_SERVER_LIVERELOAD,
};
