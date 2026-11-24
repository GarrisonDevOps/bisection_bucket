# frozen_string_literal: true

module Resolvers
  module ComplianceManagement
    class FrameworkResolver < BaseResolver
      include Gitlab::Graphql::Authorize::AuthorizeResource

      authorize :read_compliance_framework

      type ::Types::ComplianceManagement::ComplianceFrameworkType.connection_type, null: true

      argument :id, ::Types::GlobalIDType[::ComplianceManagement::Framework],
        description: 'Global ID of a specific compliance framework to return.',
        required: false

      argument :search, GraphQL::Types::String,
        required: false,
        default_value: nil,
        description: 'Search framework with most similar names.'

      argument :sort, Types::ComplianceManagement::ComplianceFrameworkSortEnum,
        required: false,
        default_value: nil,
        description: 'Sort compliance frameworks by the criteria.'

      argument :ids, [::Types::GlobalIDType[::ComplianceManagement::Framework]],
        description: 'List of Global IDs of compliance frameworks to return.',
        required: false

      def resolve(id: nil, ids: nil, search: nil, sort: nil)
        ids = [id] if ids.nil? || id.present?
        model_ids = ids.filter_map { |single_id| single_id&.model_id&.to_i }

        cache_key = create_cache_key(fetch_namespace_ids)

        BatchLoader::GraphQL
          .for(cache_key)
          .batch(key: [:multi_namespace_frameworks, model_ids, search, sort], default_value: []) do |cache_keys, loader|
            cache_keys.each do |key|
              namespace_ids = parse_cache_key(key)
              result = frameworks(namespace_ids, search, sort)

              result = result.select { |fw| model_ids.include?(fw.id) } if model_ids.any?(&:present?)

              result.each do |fw|
                loader.call(key) { |array| array << fw }
              end
            end
          end
      end

      private

      def create_cache_key(namespace_ids)
        namespace_ids.sort.join(',')
      end

      def fetch_namespace_ids
        ids = [object.root_ancestor.id]
        csp_namespace = ::Security::PolicySetting.in_organization(object.root_ancestor.organization)&.csp_namespace
        ids << csp_namespace.id if csp_namespace

        ids
      end

      def parse_cache_key(cache_key)
        cache_key.split(',').map(&:to_i)
      end

      def frameworks(ns_ids, search, sort)
        ::ComplianceManagement::Framework
          .with_namespaces(ns_ids)
          .search(search)
          .sort_by_attribute(sort)
      end
    end
  end
end
