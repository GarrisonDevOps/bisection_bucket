# frozen_string_literal: true

module EE
  module Authn
    module AgnosticTokenIdentifier
      extend ActiveSupport::Concern

      EE_TOKEN_TYPES = [::Authn::Tokens::ScimAccessToken].freeze

      class_methods do
        extend ::Gitlab::Utils::Override

        override :token_types
        def token_types
          super + EE_TOKEN_TYPES
        end
      end
    end
  end
end
