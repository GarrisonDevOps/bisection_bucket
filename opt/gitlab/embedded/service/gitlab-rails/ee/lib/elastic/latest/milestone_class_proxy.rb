# frozen_string_literal: true

module Elastic
  module Latest
    class MilestoneClassProxy < ApplicationClassProxy
      extend ::Gitlab::Utils::Override

      def elastic_search(query, options: {})
        query_hash = ::Search::Elastic::MilestoneQueryBuilder.build(query: query, options: options)

        search(query_hash, options)
      end

      def preload_indexing_data(relation)
        relation.preload_for_indexing
      end

      override :routing_options
      def routing_options(options)
        es_options = super
        return es_options if es_options[:routing].blank? || options[:project_ids].blank?
        return es_options unless ::Feature.enabled?(:advanced_search_group_milestones, options[:current_user])

        root_namespace_ids = Namespace.id_in(Project.id_in(options[:project_ids]).select(:namespace_id))
          .map { |namespace| namespace.traversal_ids.first }.uniq

        { **es_options, routing: [es_options[:routing], *root_namespace_ids.map { |id| "n_#{id}" }].join(',') }
      end
    end
  end
end
