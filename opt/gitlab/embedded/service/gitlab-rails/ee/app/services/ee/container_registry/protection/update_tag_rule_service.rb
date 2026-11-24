# frozen_string_literal: true

module EE
  module ContainerRegistry
    module Protection
      module UpdateTagRuleService
        extend ::Gitlab::Utils::Override

        override :execute
        def execute
          return service_response_error(message: _('Operation not allowed')) if container_protection_tag_rule.immutable?

          super
        end
      end
    end
  end
end
