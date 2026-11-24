# frozen_string_literal: true

module Ai
  module DuoSettings
    # Wraps a group together with a pre-loaded map of NamespaceSetting rows for
    # the group and all of its ancestors, and derives the display values the
    # admin Duo availability list needs:
    #
    #   - duo_availability   : effective value (own override, else inherited)
    #   - inherited_value    : nearest ancestor override, else the instance default
    #   - admin_locked       : true only on the introducer of a lock
    #   - locked_by_ancestor : nearest strict ancestor that introduced a lock
    #
    # The settings_by_namespace_id map is built once by the resolver from a
    # single batched query, so no per-row ancestor queries are issued.
    class DuoAvailabilityNamespacePresenter
      LOCKING_VALUES = %w[always_on never_on].freeze

      # settings_by_namespace_id: { namespace_id => NamespaceSetting }
      def initialize(group, settings_by_namespace_id:, instance_default:)
        @group = group
        @settings_by_namespace_id = settings_by_namespace_id
        @instance_default = instance_default.to_s
      end

      attr_reader :group

      delegate :id, :name, :full_path, :to_global_id, to: :group

      def duo_availability
        own_override || inherited_value
      end

      def inherited_value
        # Walk strict ancestors nearest-first; first one with an explicit override wins.
        strict_ancestor_ids.each do |ancestor_id|
          value = override_value_for(ancestor_id)
          return value if value
        end

        instance_default
      end

      def admin_locked
        setting = own_setting
        return false unless setting

        setting.admin_locked_duo_features_enabled && LOCKING_VALUES.include?(own_override.to_s)
      end

      # Returns the nearest strict ancestor group that introduced an admin lock,
      # or nil. The group locking itself is conveyed via admin_locked, not here.
      def locked_by_ancestor
        strict_ancestor_ids.each do |ancestor_id|
          setting = settings_by_namespace_id[ancestor_id]
          next unless setting&.admin_locked_duo_features_enabled
          next unless LOCKING_VALUES.include?(availability_of(setting).to_s)

          return setting.namespace
        end

        nil
      end

      private

      attr_reader :settings_by_namespace_id, :instance_default

      def own_setting
        settings_by_namespace_id[group.id]
      end

      # The group's own explicit override value, or nil when it inherits.
      def own_override
        override_value_for(group.id)
      end

      # An explicit override exists when the namespace's own row has a non-nil
      # duo_features_enabled column; otherwise the value is inherited.
      def override_value_for(namespace_id)
        setting = settings_by_namespace_id[namespace_id]
        return unless setting
        return if setting.read_attribute(:duo_features_enabled).nil?

        availability_of(setting)
      end

      def availability_of(setting)
        setting.duo_availability.to_s
      end

      # Ancestor namespace ids, nearest-first, excluding the group itself.
      # Derived from traversal_ids to avoid a recursive query.
      def strict_ancestor_ids
        @strict_ancestor_ids ||= (group.traversal_ids - [group.id]).reverse
      end
    end
  end
end
