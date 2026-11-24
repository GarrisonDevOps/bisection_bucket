# frozen_string_literal: true

module EE
  module Gitlab
    module Auth
      module EditorExtensions
        module LanguageServerClientVerifier
          extend ::Gitlab::Utils::Override

          private

          override :dedicated?
          def dedicated?
            ::Gitlab::Dedicated.feature_available?(:enforce_language_server_version_on_dedicated) || super
          end
        end
      end
    end
  end
end
