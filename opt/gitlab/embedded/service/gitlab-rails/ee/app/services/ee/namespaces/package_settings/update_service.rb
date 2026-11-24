# frozen_string_literal: true

module EE
  module Namespaces
    module PackageSettings
      module UpdateService
        extend ActiveSupport::Concern
        extend ::Gitlab::Utils::Override

        EE_ALLOWED_ATTRIBUTES = %i[audit_events_enabled].freeze

        private

        override :allowed_attributes
        def allowed_attributes
          super + EE_ALLOWED_ATTRIBUTES
        end
      end
    end
  end
end
