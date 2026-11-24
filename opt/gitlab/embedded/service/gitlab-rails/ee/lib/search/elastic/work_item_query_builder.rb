# frozen_string_literal: true

module Search
  module Elastic
    class WorkItemQueryBuilder < QueryBuilder
      extend ::Gitlab::Utils::Override
      include Gitlab::Utils::StrongMemoize

      DOC_TYPE = 'work_item'
      # iid field can be added here as lenient option will pardon format errors, like integer out of range.
      FIELDS = %w[iid^50 title^2 description].freeze
      IID_REGEX = /#(\d+)\z/

      QUERY_COMPONENTS = {
        ::Search::Elastic::Filters => %i[
          by_combined_search_level_and_membership
          by_combined_confidentiality
          by_state
          by_not_hidden
          by_label_ids
          by_archived
          by_work_item_type_ids
          by_author
          by_assignees
          by_milestone
          by_milestone_state
          by_label_names
          by_weight
          by_health_status
          by_closed_at
          by_created_at
          by_updated_at
          by_due_date
          by_iids
        ],
        ::Search::Elastic::Aggregations => %i[by_label_ids by_state by_work_item_type_ids],
        ::Search::Elastic::Formats => [
          { method: :source_fields, skip_if_size_zero: true },
          { method: :page, skip_if_size_zero: true },
          { method: :size, skip_if_size_zero: true }
        ],
        ::Search::Elastic::Sorts::WorkItem => [
          { method: :sort_by, skip_if_size_zero: true }
        ]
      }.freeze

      private

      override :extra_options
      def extra_options
        {
          doc_type: DOC_TYPE,
          project_visibility_level_field: :project_visibility_level,
          min_access_level_confidential_public_internal: ::Gitlab::Access::GUEST,
          min_access_level_confidential: ::Gitlab::Access::PLANNER
        }
      end

      override :prepare_options
      def prepare_options
        options[:fields] = fields
        options[:related_ids] = related_ids

        if options[:aggregation]
          # For aggregation queries, include all authorization scopes so the type
          # aggregation reflects counts across all work item types (including group-level epics)
          options[:use_group_authorization] = true
          options[:use_project_authorization] = true
          options[:features] = 'issues'
        else
          options[:use_group_authorization] = use_group_authorization?
          options[:use_project_authorization] = use_project_authorization?
          options[:features] = 'issues' if use_project_authorization?
        end
      end

      override :build_initial_query_hash
      def build_initial_query_hash
        if query =~ IID_REGEX
          ::Search::Elastic::Queries.by_iid(iid: Regexp.last_match(1), doc_type: DOC_TYPE)
        else
          ::Search::Elastic::Queries.by_full_text(query: query, options: options)
        end
      end

      def fields
        return options[:fields] if options[:fields].presence

        FIELDS
      end

      def related_ids
        return [] unless options[:related_ids].present?

        # related_ids are used to search for related notes on noteable records
        # this is not enabled on GitLab.com for global searches
        return [] if options[:search_level].to_sym == :global && ::Gitlab::Saas.feature_available?(:advanced_search)

        options[:related_ids]
      end

      def use_project_authorization?
        return true unless options[:work_item_type_ids].present?

        project_work_item_type_ids = options[:work_item_type_ids] - group_work_item_type_ids
        project_work_item_type_ids.present?
      end

      def use_group_authorization?
        # If explicit type inclusion filter is present
        if options[:work_item_type_ids].present?
          return options[:work_item_type_ids].any? { |id| group_work_item_type_ids.include?(id) }
        end

        # If explicit type exclusion filter is present
        if options[:not_work_item_type_ids].present?
          # Use group auth only if epic is NOT excluded
          return !options[:not_work_item_type_ids].any? { |id| group_work_item_type_ids.include?(id) }
        end

        # No filter specified - include all types (including group-level)
        true
      end

      def group_work_item_type_ids
        [::WorkItems::TypesFramework::Provider.new.find_by_base_type(:epic).id].freeze
      end
      strong_memoize_attr :group_work_item_type_ids
    end
  end
end
