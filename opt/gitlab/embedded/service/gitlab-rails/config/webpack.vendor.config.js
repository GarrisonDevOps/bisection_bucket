const path = require('path');
const webpack = require('webpack');
const vendorDllHash = require('./helpers/vendor_dll_hash');

const ROOT_PATH = path.resolve(__dirname, '..');

const dllHash = vendorDllHash();
const dllCachePath = path.join(ROOT_PATH, `tmp/cache/webpack-dlls/${dllHash}`);
const dllPublicPath = `/assets/webpack/dll.${dllHash}/`;

module.exports = {
  mode: 'development',
  resolve: {
    extensions: ['.js'],
    alias: {
      jquery$: 'jquery/dist/jquery.slim.js',
    },
  },

  // ensure output is not generated when errors are encountered
  bail: true,

  context: ROOT_PATH,

  entry: {
    vendor: [
      '@apollo/client/core',
      '@gitlab/at.js',
      'core-js',
      'dompurify',
      'echarts',
      'jed',
      'jquery/dist/jquery.slim.js',
      'katex',
      'mousetrap',
      'pikaday',
      'popper.js',
      'sortablejs/modular/sortable.esm.js',
      'source-map',
      'three',
      'vue',
      'vuex',
    ],
  },

  output: {
    path: dllCachePath,
    publicPath: dllPublicPath,
    filename: '[name].dll.bundle.js',
    chunkFilename: '[name].dll.chunk.js',
    library: '[name]_[hash]',
  },

  plugins: [
    new webpack.DllPlugin({
      path: path.join(dllCachePath, '[name].dll.manifest.json'),
      name: '[name]_[hash]',
    }),
  ],

  node: {
    fs: 'empty', // sqljs requires fs
    setImmediate: false,
  },

  devtool: 'cheap-module-source-map',
};
