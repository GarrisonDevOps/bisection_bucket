# frozen_string_literal: true

module EE
  module Observability
    module GroupO11ySetting
      extend ActiveSupport::Concern

      class_methods do
        extend ::Gitlab::Utils::Override

        override :hosted_service?
        def hosted_service?
          ::Gitlab::Saas.feature_available?(:observability_hosted_service)
        end
      end
    end
  end
end
