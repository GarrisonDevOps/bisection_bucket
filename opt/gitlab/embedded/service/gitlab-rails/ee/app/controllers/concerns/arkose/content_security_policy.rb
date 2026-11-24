# frozen_string_literal: true

module Arkose
  module ContentSecurityPolicy
    extend ActiveSupport::Concern

    included do
      content_security_policy do |policy|
        next unless policy.directives.present?

        default_script_src = policy.directives['script-src'] || policy.directives['default-src']
        script_src_values = Array.wrap(default_script_src) | ["https://*.arkoselabs.com"]
        policy.script_src(*script_src_values)

        default_frame_src = policy.directives['frame-src'] || policy.directives['default-src']
        frame_src_values = Array.wrap(default_frame_src) | ['https://*.arkoselabs.com']
        policy.frame_src(*frame_src_values)

        default_connect_src = policy.directives['connect-src'] || policy.directives['default-src']
        connect_src_values = Array.wrap(default_connect_src) | ['https://*.arkoselabs.com']
        policy.connect_src(*connect_src_values)
      end
    end
  end
end
