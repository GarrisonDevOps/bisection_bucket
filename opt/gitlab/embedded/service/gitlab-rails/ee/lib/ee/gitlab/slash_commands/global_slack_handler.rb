# frozen_string_literal: true

module EE
  module Gitlab
    module SlashCommands
      module GlobalSlackHandler
        extend ActiveSupport::Concern
        extend ::Gitlab::Utils::Override

        override :trigger
        def trigger
          return false if ::Integrations::GitlabSlackApplication.blocked_by_settings?(log: true)

          super
        end
      end
    end
  end
end
