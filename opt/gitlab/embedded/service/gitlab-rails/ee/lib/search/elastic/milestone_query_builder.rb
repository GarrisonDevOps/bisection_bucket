# frozen_string_literal: true

module Search
  module Elastic
    class MilestoneQueryBuilder < QueryBuilder
      extend ::Gitlab::Utils::Override

      DOC_TYPE = 'milestone'
      FIELDS = %w[title^2 description].freeze

      QUERY_COMPONENTS = {
        ::Search::Elastic::Filters => [
          :by_type,
          :by_combined_search_level_and_membership,
          :by_archived
        ],
        ::Search::Elastic::Formats => %i[source_fields size]
      }.freeze

      private

      override :extra_options
      def extra_options
        {
          doc_type: DOC_TYPE,
          features: [:issues, :merge_requests],
          relaxed_feature_access: {
            merge_requests: {
              min_access_level: Gitlab::Access::GUEST,
              feature_access_levels: [::ProjectFeature::ENABLED]
            }
          },
          # Group milestones store the group's visibility in the field project milestones use.
          namespace_visibility_field: :visibility_level,
          project_document_field: :project_id,
          # Group milestones are inherited, so group-level search also returns ancestor group milestones.
          include_ancestor_groups: true
        }
      end

      override :prepare_options
      def prepare_options
        options[:fields] = options[:fields].presence || FIELDS
        options[:use_project_authorization] = true
        options[:use_group_authorization] =
          ::Feature.enabled?(:advanced_search_group_milestones, options[:current_user])
      end

      override :build_initial_query_hash
      def build_initial_query_hash
        ::Search::Elastic::Queries.by_full_text(query: query, options: options)
      end
    end
  end
end
