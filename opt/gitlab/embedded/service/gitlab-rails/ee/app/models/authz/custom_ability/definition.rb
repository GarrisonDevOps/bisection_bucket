# frozen_string_literal: true

module Authz
  class CustomAbility
    # Represents a definition from gitlab/ee/config/custom_abilities/*.yml
    class Definition
      def initialize(ability_name)
        @ability_name = ability_name
      end

      def name
        return unless attributes[:name]

        attributes[:name].to_sym
      end

      def exists?
        attributes.present?
      end

      def group_ability_enabled?
        attributes.fetch(:group_ability, false)
      end

      def project_ability_enabled?
        attributes.fetch(:project_ability, false)
      end

      def admin_ability_enabled?
        return false if group_ability_enabled? || project_ability_enabled?

        exists?
      end

      def project_permissions
        attributes.fetch(:project_permissions, []).map(&:to_sym)
      end

      def group_permissions
        attributes.fetch(:group_permissions, []).map(&:to_sym)
      end

      private

      attr_reader :ability_name

      def attributes
        @attributes ||= Gitlab::CustomRoles::Definition.all[ability_name&.to_sym] || {}
      end
    end
  end
end
