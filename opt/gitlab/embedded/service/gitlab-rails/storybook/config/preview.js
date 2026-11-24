// Some modules read window.gon on initialization thus we need to define this object before anything else
import './gon';
// Not a public export. Check this path when you upgrade Storybook.
import { applyDecorators as storybookApplyDecorators } from '@storybook/vue3/dist/entry-preview.mjs';
import Vue, { h } from 'vue';
import VueApollo from 'vue-apollo';
import Vuex from 'vuex'; // eslint-disable-line no-restricted-imports
import translateMixin from '~/vue_shared/translate';
import logoWithBlackText from '../static/_logo_with_black_text.svg';
import logoWithWhiteText from '../static/_logo_with_white_text.svg';

// Filter out invalid language tags from navigator.languages to prevent Intl API errors
// This is particularly important in CI environments where invalid tags like 'en-US@posix' may be present
if (typeof navigator !== 'undefined' && navigator.languages) {
  const validLanguages = navigator.languages.filter((lang) => {
    try {
      Intl.getCanonicalLocales(lang);
      return true;
    } catch {
      // Invalid language tag, filter it out
      return false;
    }
  });

  // Only override if we filtered out any invalid languages
  if (validLanguages.length !== navigator.languages.length) {
    Object.defineProperty(navigator, 'languages', {
      value: validLanguages.length > 0 ? validLanguages : ['en-US'],
      writable: false,
      enumerable: true,
      configurable: true,
    });
  }
}

const stylesheetsRequireCtx = require.context(
  '../../app/assets/stylesheets',
  true,
  /(application|highlight\/themes\/white)\.scss$/,
);

translateMixin(Vue);
Vue.use(VueApollo);
Vue.use(Vuex);

stylesheetsRequireCtx('./application.scss');
import('../../app/assets/builds/tailwind.css');
stylesheetsRequireCtx('./highlight/themes/white.scss');

// The Vue 3 renderer passes no args to a story, and each `<story />` in a decorator drops
// every attribute but class and style. So bind the args before any decorator runs.
const withArgsAsProps = (storyFn) => (context) => {
  const story = storyFn(context);
  // A copy, because `h` writes normalized `class` and `style` back into a plain props object.
  return { render: () => h(story, { ...context.args }) };
};

export const applyDecorators = (storyFn, storyDecorators) =>
  storybookApplyDecorators(withArgsAsProps(storyFn), storyDecorators);

// Recreate the named containers from app/views/layouts/_page.html.haml so container
// query utilities such as `@md/panel:gl-grid-cols-2` also apply in stories.
export const decorators = [
  () => ({
    template: `
      <div class="gl-@container/content-panels">
        <div class="gl-@container/panel"><story /></div>
      </div>
    `,
  }),
];

export const theme = {
  brandTitle: 'GitLab (Product)',
  brandUrl: 'https://gitlab.com/gitlab-org/gitlab',
};

export const parameters = {
  darkMode: {
    current: 'light',
    stylePreview: true,
    classTarget: 'html',
    darkClass: 'gl-dark',
    dark: {
      ...theme,
      brandImage: logoWithWhiteText,
    },
    light: {
      ...theme,
      brandImage: logoWithBlackText,
    },
  },
  a11y: {},
  viewport: {
    viewports: {
      breakpointSmall: {
        name: 'Breakpoint small (width: 320px)',
        styles: {
          height: '568px',
          width: '320px',
        },
      },
      breakpointMedium: {
        name: 'Breakpoint medium (width: 768px)',
        styles: {
          height: '1024px',
          width: '768px',
        },
      },
      breakpointLarge: {
        name: 'Breakpoint large (width: 1024px)',
        styles: {
          height: '768px',
          width: '1024px',
        },
      },
      breakpointExtraLarge: {
        name: 'Breakpoint extra large (width: 1280px)',
        styles: {
          height: '800px',
          width: '1280px',
        },
      },
    },
  },
};
