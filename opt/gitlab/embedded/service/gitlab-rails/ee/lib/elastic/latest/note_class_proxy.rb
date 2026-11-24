# frozen_string_literal: true

module Elastic
  module Latest
    class NoteClassProxy < ApplicationClassProxy
      extend ::Gitlab::Utils::Override

      NOTEABLE_TYPE_TO_FEATURE = {
        Issue: :issues,
        MergeRequest: :merge_requests,
        Snippet: :snippets,
        Commit: :repository
      }.freeze

      def es_type
        'note'
      end

      def elastic_search(query, options: {})
        if ::Feature.enabled?(:search_notes_use_query_builder, options[:current_user], type: :gitlab_com_derisk)
          return search(::Search::Elastic::NoteQueryBuilder.build(query: query, options: options), options)
        end

        options[:in] = ['note']
        options[:no_join_project] = true
        options[:project_id_field] = :project_id
        @noteable_type_to_feature = filtered_noteable_types(options)

        query_hash = basic_query_hash(%w[note], query, options)

        context.name(:note) do
          query_hash = get_authorization_filter(query_hash, options)
          query_hash = confidentiality_filter(query_hash, options)
          query_hash = hidden_filter(query_hash, options)
          query_hash = context.name(:archived) { archived_filter(query_hash) } if archived_filter_applicable?(options)
          query_hash = ::Search::Elastic::Filters.by_noteable_type(query_hash:, options:)
        end

        search(query_hash, options)
      end

      # rubocop: disable CodeReuse/ActiveRecord
      def preload_indexing_data(relation)
        preloaded_data = relation
          .includes(:author,
            noteable: [:assignees, :namespace, :group, { project: :namespace, target_project: :namespace }],
            project: [
              :project_feature, :route,
              { namespace: %i[namespace_settings namespace_settings_with_ancestors_inherited_settings] }
            ]
          )

        project_notes, namespace_notes = preloaded_data.partition(&:for_project_noteable?)

        projects = project_notes.filter_map { |n| n.noteable&.try(:project) || n.noteable&.try(:target_project) }.uniq
        namespaces = namespace_notes.filter_map { |n| n.noteable&.try(:namespace) }.uniq

        ::Namespaces::Preloaders::ProjectRootAncestorPreloader.new(projects).execute
        ::Namespaces::Preloaders::NamespaceRootAncestorPreloader.new(namespaces).execute

        preloaded_data
      end
      # rubocop: enable CodeReuse/ActiveRecord

      private

      attr_reader :noteable_type_to_feature

      def get_authorization_filter(query_hash, options)
        ::Search::Elastic::Filters.by_search_level_and_membership(
          query_hash: query_hash, options: options.merge(
            features: noteable_type_to_feature.values,
            relaxed_feature_access: ::Search::Elastic::MergeRequestQueryBuilder::RELAXED_FEATURE_ACCESS
          )
        )
      end

      def confidentiality_filter(query_hash, options)
        current_user = options[:current_user]

        return query_hash if current_user&.can_read_all_resources?

        filter_options = options.merge(min_access_level_confidential: ::Gitlab::Access::PLANNER,
          min_access_level_confidential_public_internal: ::Gitlab::Access::PLANNER)
        ::Search::Elastic::Filters.by_note_confidentiality(query_hash: query_hash, options: filter_options)
      end

      # Gated on the BACKFILL, not the mapping migration: `term: { hidden: false }`
      # does not match a document missing the field, so filtering before the
      # backfill completes would drop every un-backfilled note from results.
      def hidden_filter(query_hash, options)
        unless ::Elastic::DataMigrationService.migration_has_finished?(
          ::Elastic::Latest::NoteInstanceProxy::HIDDEN_BACKFILL_MIGRATION
        )
          return query_hash
        end

        ::Search::Elastic::Filters.by_not_hidden(query_hash: query_hash, options: options)
      end

      def archived_filter_applicable?(options)
        !(options[:include_archived] || options[:search_level] == 'project')
      end

      def filtered_noteable_types(options = {})
        return NOTEABLE_TYPE_TO_FEATURE unless options[:noteable_type]

        noteable_type_symbol = options[:noteable_type].to_sym
        return {} unless NOTEABLE_TYPE_TO_FEATURE.key?(noteable_type_symbol)

        NOTEABLE_TYPE_TO_FEATURE.slice(noteable_type_symbol)
      end
    end
  end
end
