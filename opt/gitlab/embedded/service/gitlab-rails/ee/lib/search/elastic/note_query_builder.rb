# frozen_string_literal: true

module Search
  module Elastic
    class NoteQueryBuilder < QueryBuilder
      extend ::Gitlab::Utils::Override

      DOC_TYPE = 'note'
      FIELDS = %w[note].freeze

      # Formats run first so that by_noteable_type can override _source and size for related_ids_only lookups.
      QUERY_COMPONENTS = {
        ::Search::Elastic::Formats => %i[source_fields size],
        ::Search::Elastic::Filters => [
          :by_search_level_and_membership,
          :by_note_confidentiality,
          { method: :by_not_hidden, migration: ::Elastic::Latest::NoteInstanceProxy::HIDDEN_BACKFILL_MIGRATION },
          :by_archived,
          :by_noteable_type
        ]
      }.freeze

      private

      override :extra_options
      def extra_options
        {
          doc_type: DOC_TYPE,
          min_access_level_confidential: ::Gitlab::Access::PLANNER,
          min_access_level_confidential_public_internal: ::Gitlab::Access::PLANNER
        }
      end

      override :prepare_options
      def prepare_options
        options[:fields] = options[:fields].presence || FIELDS
        options[:features] = noteable_features
        options[:relaxed_feature_access] = ::Search::Elastic::MergeRequestQueryBuilder::RELAXED_FEATURE_ACCESS
      end

      override :build_initial_query_hash
      def build_initial_query_hash
        ::Search::Elastic::Queries.by_full_text(query: query, options: options)
      end

      def noteable_features
        features = ::Elastic::Latest::NoteClassProxy::NOTEABLE_TYPE_TO_FEATURE
        return features.values unless options[:noteable_type]

        Array.wrap(features[options[:noteable_type].to_sym])
      end
    end
  end
end
