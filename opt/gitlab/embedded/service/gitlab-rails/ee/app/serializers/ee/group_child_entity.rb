# frozen_string_literal: true

module EE
  module GroupChildEntity
    extend ActiveSupport::Concern

    prepended do
      expose :compliance_management_frameworks, if: ->(_instance, _options) { compliance_framework_available? }
    end

    private

    def compliance_framework_available?
      return unless project?

      object.licensed_feature_available?(:compliance_framework)
    end
  end
end
