# frozen_string_literal: true

module VirtualRegistries
  module Packages
    module Maven
      def self.table_name_prefix
        'virtual_registries_packages_maven_'
      end

      def self.feature_prerequisites_met?(group)
        group.dependency_proxy_feature_available? &&
          ::Feature.enabled?(:maven_virtual_registry, group) &&
          group.licensed_feature_available?(:packages_virtual_registry)
      end

      def self.feature_enabled?(group)
        feature_prerequisites_met?(group) && ::VirtualRegistries::Setting.enabled_for_group?(group)
      end

      def self.virtual_registry_available?(group, current_user, permission = :read_virtual_registry)
        feature_enabled?(group) && ::VirtualRegistries.user_has_access?(group, current_user, permission)
      end
    end
  end
end
