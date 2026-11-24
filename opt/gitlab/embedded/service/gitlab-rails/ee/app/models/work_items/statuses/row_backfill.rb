# frozen_string_literal: true

module WorkItems
  module Statuses
    # Which status filter branches can be skipped because the backfills guarantee the rows.
    module RowBackfill
      # Epics join after https://gitlab.com/gitlab-org/gitlab/-/work_items/632560 is finalized.
      BACKFILLED_BASE_TYPES = %w[issue task].freeze

      def self.legacy_rows_rewritten?(root_namespace)
        enabled_for?(root_namespace)
      end

      def self.rows_complete_for?(root_namespace, base_type)
        backfilled_type?(base_type) && enabled_for?(root_namespace)
      end

      def self.backfilled_type?(base_type)
        BACKFILLED_BASE_TYPES.include?(base_type.to_s)
      end

      def self.enabled_for?(namespace)
        root_namespace = namespace&.root_ancestor
        return false unless root_namespace

        ::Feature.enabled?(:work_item_status_single_column_filter, root_namespace, type: :gitlab_com_derisk)
      end
    end
  end
end
