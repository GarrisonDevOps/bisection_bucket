const path = require('path');
const IS_EE = require('../../config/helpers/is_ee_env');

const config = {
  stories: [
    '../../app/assets/javascripts/**/*.stories.js',
    IS_EE && '../../ee/app/assets/javascripts/**/*.stories.js',
  ].filter(Boolean),
  addons: [
    '@storybook/addon-docs',
    '@storybook/addon-essentials',
    '@storybook/addon-a11y',
    '@storybook/addon-viewport',
    'storybook-dark-mode',
  ],
  framework: {
    name: '@storybook/vue3-webpack5',
    options: {
      builder: {
        disableTelemetry: Boolean(process.env.CI),
      },
    },
  },
  docs: {
    autodocs: true,
  },
  staticDirs: [
    {
      from: path.resolve(__dirname, '../../app/assets/images'),
      to: '/assets/images',
    },
    {
      from: path.resolve(__dirname, '../../node_modules/@gitlab/svgs/dist/file_icons'),
      to: '/assets/file_icons',
    },
  ],
};

module.exports = config;
