# frozen_string_literal: true

module WorkItems
  module Statuses
    # Single source of truth for the per-type feature flags that gate status
    # support while a type is still being rolled out.
    #
    # Some work item types (currently Epic and Ticket) only support status behind a feature
    # flag. This module centralizes the base_type => flag mapping so every layer
    # that must honor it (widget exposure, lifecycle resolution, the type
    # projection, and the validation layer) asks the same question and stays
    # consistent across flag on/off.
    #
    # Status is scoped to the root ancestor, so the flags are always evaluated on
    # the root namespace.
    module FeatureFlags
      # Base types whose status support is still behind a feature flag. Types not
      # listed here (issue, task) are never flag-gated and are always enabled.
      # The per-type flag is evaluated in `status_enabled_for_base_type?` with a
      # literal flag name (required by the Gitlab/FeatureFlagKeyDynamic cop so
      # flag usage stays statically greppable).
      STATUS_FLAG_GATED_BASE_TYPES = %w[epic ticket].freeze

      def self.status_flag_gated_base_types
        STATUS_FLAG_GATED_BASE_TYPES
      end

      # Whether the status feature is enabled for the given base type in the
      # given root namespace. Non-flag-gated types are always enabled. When the
      # root namespace cannot be resolved we cannot evaluate the root-scoped
      # flag, so we treat a flag-gated type as disabled (the safe, dormant
      # default) and a non-gated type as enabled.
      def self.status_enabled_for_base_type?(base_type, root_namespace)
        case base_type.to_s
        when 'epic'
          return false unless root_namespace

          ::Feature.enabled?(:work_item_status_for_epics, root_namespace)
        when 'ticket'
          return false unless root_namespace

          ::Feature.enabled?(:work_item_ticket_migration, root_namespace)
        else
          true
        end
      end

      # Single answer to "may a status row be written for this type here?".
      # Licensed namespaces follow the per-type rollout flag; unlicensed ones
      # need the rows flag, and flag-gated types stay off until licensed.
      def self.write_status_row?(base_type, root_namespace)
        return false unless root_namespace

        if root_namespace.licensed_feature_available?(:work_item_status)
          status_enabled_for_base_type?(base_type, root_namespace)
        else
          write_rows_without_license?(base_type, root_namespace)
        end
      end

      # Flag-gated types keep the license gate because their validation layer
      # still depends on widget visibility. Only the row write is unlicensed;
      # the widget stays hidden.
      def self.write_rows_without_license?(base_type, root_namespace)
        return false unless root_namespace
        return false if status_flag_gated_base_types.include?(base_type.to_s)

        ::Feature.enabled?(:work_item_status_rows_without_license, root_namespace, type: :gitlab_com_derisk)
      end
    end
  end
end
