# frozen_string_literal: true

module EE
  module Gitlab
    module RackAttack
      module Request
        extend ::Gitlab::Utils::Override

        override :should_be_skipped?
        def should_be_skipped?
          super || verified_geo_request? || virtual_registries_api_endpoints? || geo_proxy_workhorse_request?
        end

        override :throttle_unauthenticated_git_http?
        def throttle_unauthenticated_git_http?
          return false if verified_geo_request?

          super
        end

        def alerts_notify?
          web_request? && logical_path.include?('alerts/notify')
        end
      end
    end
  end
end
