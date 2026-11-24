# frozen_string_literal: true

module Search
  module Elastic
    class MergeRequestQueryBuilder < QueryBuilder
      extend ::Gitlab::Utils::Override

      DOC_TYPE = 'merge_request'
      # iid field can be added here as lenient option will pardon format errors, like integer out of range.
      FIELDS = %w[iid^3 title^2 description].freeze

      # ProjectPolicy grants read_merge_request to a Planner member wherever merge requests are ENABLED,
      # but PRIVATE_FEATURES_MIN_ACCESS_LEVEL[:merge_requests] is REPORTER, which the membership filters
      # would otherwise apply to the ENABLED and PRIVATE levels alike.
      RELAXED_FEATURE_ACCESS = {
        merge_requests: {
          min_access_level: Gitlab::Access::PLANNER,
          feature_access_levels: [::ProjectFeature::ENABLED]
        }
      }.freeze

      QUERY_COMPONENTS = {
        ::Search::Elastic::Filters => %i[
          by_search_level_and_membership
          by_state
          by_archived
          by_author
          by_assignees
          by_label_ids
          by_source_branch
          by_target_branch
          by_created_at
          by_updated_at
          by_not_hidden
        ],
        ::Search::Elastic::Aggregations => %i[by_label_ids],
        ::Search::Elastic::Formats => [
          { method: :source_fields, skip_if_size_zero: true },
          { method: :size, skip_if_size_zero: true }
        ],
        ::Search::Elastic::Sorts::Base => [
          { method: :sort_by, skip_if_size_zero: true }
        ]
      }.freeze

      private

      override :extra_options
      def extra_options
        {
          doc_type: DOC_TYPE,
          features: 'merge_requests',
          project_id_field: :target_project_id,
          relaxed_feature_access: RELAXED_FEATURE_ACCESS,
          assignee_id_field: :assignee_ids
        }
      end

      override :prepare_options
      def prepare_options
        options[:fields] = options[:fields].presence || FIELDS
        options[:related_ids] = related_ids
      end

      override :build_initial_query_hash
      def build_initial_query_hash
        if query =~ /!(\d+)\z/
          ::Search::Elastic::Queries.by_iid(iid: Regexp.last_match(1), doc_type: DOC_TYPE)
        else
          ::Search::Elastic::Queries.by_full_text(query: query, options: options)
        end
      end

      def related_ids
        return [] unless options[:related_ids].present?

        # related_ids are used to search for related notes on noteable records
        # this is not enabled on GitLab.com for global searches
        return [] if options[:search_level].to_sym == :global && ::Gitlab::Saas.feature_available?(:advanced_search)

        options[:related_ids]
      end
    end
  end
end
