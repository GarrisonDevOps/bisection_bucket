# frozen_string_literal: true

module EE
  module API
    module Integrations
      module Slack
        module Request
          extend ActiveSupport::Concern

          class_methods do
            extend ::Gitlab::Utils::Override

            override :verify!
            def verify!(request)
              return false if ::Integrations::GitlabSlackApplication.blocked_by_settings?(log: true)

              super
            end
          end
        end
      end
    end
  end
end
