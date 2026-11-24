# frozen_string_literal: true

module EE
  module ContainerRegistry
    module Tag
      extend ::Gitlab::Utils::Override
      include ::Gitlab::Utils::StrongMemoize

      override :protection_rule
      def protection_rule
        # Return the matching immutable protection rule if it exists as it has the highest restrictiveness.
        immutable_protection_rule || super
      end
      strong_memoize_attr :protection_rule

      override :protected_for_delete?
      def protected_for_delete?(user)
        return true if user && protection_rule&.immutable?

        super
      end

      private

      def immutable_protection_rule
        return unless project.licensed_feature_available?(:container_registry_immutable_tag_rules)

        project.container_registry_protection_tag_rules.detect do |rule|
          rule.immutable? && rule.matches_tag_name?(name)
        end
      end
    end
  end
end
