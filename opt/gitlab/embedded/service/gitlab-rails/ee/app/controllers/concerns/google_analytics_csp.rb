# frozen_string_literal: true

module GoogleAnalyticsCSP
  extend ActiveSupport::Concern

  included do
    content_security_policy do |policy|
      next unless helpers.google_tag_manager_enabled?
      next unless policy.directives.present?

      # Tag Manager with a Content Security Policy for Google Analytics 4
      # https://developers.google.com/tag-platform/security/guides/csp#google_analytics_4_google_analytics

      default_script_src = policy.directives['script-src'] || policy.directives['default-src']
      script_src_values = Array.wrap(default_script_src) | ['*.googletagmanager.com']
      policy.script_src(*script_src_values)

      ga4_domains = [
        '*.googletagmanager.com', # Google tag manager
        'https://analytics.gitlab.com' # Analytics server
      ]

      default_img_src = policy.directives['img-src'] || policy.directives['default-src']
      img_src_values = Array.wrap(default_img_src) | ga4_domains
      policy.img_src(*img_src_values)

      default_connect_src = policy.directives['connect-src'] || policy.directives['default-src']
      connect_src_values = Array.wrap(default_connect_src) | ga4_domains
      policy.connect_src(*connect_src_values)

      default_frame_src = policy.directives['frame-src'] || policy.directives['default-src']
      frame_src_values = Array.wrap(default_frame_src) | ga4_domains
      policy.frame_src(*frame_src_values)
    end
  end
end
