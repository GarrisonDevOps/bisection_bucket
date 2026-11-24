# frozen_string_literal: true

module Gitlab
  module Auth
    module GroupSaml
      class Config < Gitlab::Auth::Saml::Config
        def self.options
          {}
        end

        def self.enabled?
          Gitlab::Auth::OAuth::Provider.enabled?(:group_saml)
        end

        def self.sign_in_enabled?
          Gitlab::Auth::OAuth::Provider.sign_in_enabled?(:group_saml)
        end
      end
    end
  end
end
