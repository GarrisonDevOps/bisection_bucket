# frozen_string_literal: true

module EE
  module ContainerRegistry
    module Protection
      module CreateTagRuleService
        extend ::Gitlab::Utils::Override

        override :validate
        def validate(protection_rule)
          return unless protection_rule.immutable?

          unless project.licensed_feature_available?(:container_registry_immutable_tag_rules)
            return _('Immutable tag rules require an Ultimate license')
          end

          return if can?(current_user, :create_container_registry_protection_immutable_tag_rule, project)

          _('Unauthorized to create an immutable protection rule for container image tags')
        end
      end
    end
  end
end
