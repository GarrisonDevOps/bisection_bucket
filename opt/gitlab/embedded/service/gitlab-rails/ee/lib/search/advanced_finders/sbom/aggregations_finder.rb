# frozen_string_literal: true

# Search::AdvancedFinders::Sbom::AggregationsFinder
#
# Elasticsearch-backed counterpart of ::Sbom::AggregationsFinder. Returns one ::Sbom::Occurrence
# per (sort value, component, component version) tuple in a group, carrying the same aggregate
# occurrence, project and vulnerability counts that finder selects.
#
# Two searches are issued. A sub-aggregation can never see documents outside its parent bucket,
# and a bucket key includes the sort field, so counting inside those buckets would only count
# the part of a dependency sharing a sort value:
#
#   1. a composite aggregation producing the rows, plus the id used to load each one;
#   2. a `filters` aggregation producing the counts for the pairs on those rows.
#
# Arguments:
#   namespace: the Group whose dependencies are aggregated. Group level only.
#   params: optional! a hash with one or more of:
#     per_page: number of rows to return, clamped to MAX_PAGE_SIZE.
#     sort_by: severity, packager, name or license (the underlying column names also work)
#     sort: asc or desc
#     after_key: composite aggregation key to page from, as supplied by a paginating caller
#     component_ids, component_names, component_versions, not: { component_versions: [] }
#     licenses, package_managers, malware, project_ids
#     security_project_tracked_context_id, tracked_refs_scope
module Search
  module AdvancedFinders
    module Sbom
      class AggregationsFinder
        include ::Gitlab::Utils::StrongMemoize

        class AggregatedOccurrence < SimpleDelegator
          attr_reader :occurrence_count, :project_count, :vulnerability_count

          def initialize(occurrence, occurrence_count:, project_count:, vulnerability_count:)
            super(occurrence)

            @occurrence_count = occurrence_count
            @project_count = project_count
            @vulnerability_count = vulnerability_count
          end

          # Matches the `licenses_select` in ::Sbom::AggregationsFinder
          def licenses
            [__getobj__.licenses.first].compact
          end
        end

        DEFAULT_PAGE_SIZE = 20
        MAX_PAGE_SIZE = 100

        # `project_ids` needs no hierarchy check as ::Sbom::DependenciesFinder does: by_traversal_ids
        # already confines the search to this group, so an id from outside it matches nothing.
        FORWARDED_PARAMS = %i[
          component_ids
          component_names
          component_versions
          licenses
          malware
          package_managers
          project_ids
        ].freeze

        def initialize(namespace, params: {})
          @namespace = namespace
          @params = params
        end

        def execute
          ::Search::Elastic::CompositePagination::Page.new(
            records: records_for(page_buckets),
            first_key: page_buckets.first&.dig(:key),
            last_key: page_buckets.last&.dig(:key),
            has_next_page: buckets.size > page_size
          )
        end
        strong_memoize_attr :execute

        private

        attr_reader :namespace, :params

        # -- searching ----------------------------------------------------------------------

        def buckets
          search(dependencies_options)&.dig(:dependencies, :buckets) || []
        end
        strong_memoize_attr :buckets

        def page_buckets
          buckets.first(page_size)
        end
        strong_memoize_attr :page_buckets

        def records_for(selected_buckets)
          return [] if selected_buckets.empty?

          build_records(selected_buckets, search_counts(selected_buckets))
        end

        def search_counts(buckets)
          pairs = buckets.map { |bucket| component_and_version(bucket) }.uniq
          options = counts_options(pairs)

          search(options)&.dig(:version_counts, :buckets) || {}
        end

        def search(options)
          query = ::Search::Elastic::SbomOccurrenceRefQueryBuilder.build(query: nil, options: options)

          ::Gitlab::Search::Client.execute_search(query: query, options: search_options) do |response|
            ::Search::Elastic::ResponseMapper.new(response).aggregations
          end
        end

        def search_options
          {
            index_name: ::Search::Elastic::References::Sbom::OccurrenceRef.index,
            root_ancestor_ids: [namespace.root_ancestor.id]
          }
        end

        # -- parsing ------------------------------------------------------------------------

        def build_records(buckets, counts_by_key)
          occurrences = load_occurrences(buckets)

          buckets.filter_map do |bucket|
            occurrence = occurrences[occurrence_id(bucket)]
            next unless occurrence

            bucket_key = filter_key(*component_and_version(bucket))
            counts = counts_by_key[bucket_key]
            build_record(occurrence, counts)
          end
        end

        def load_occurrences(buckets)
          ids = buckets.map { |bucket| occurrence_id(bucket) }

          ::Sbom::Occurrence.id_in(ids).with_component.with_version.index_by(&:id)
        end

        def build_record(occurrence, counts)
          counts ||= {}

          AggregatedOccurrence.new(
            occurrence,
            occurrence_count: counts.dig(:occurrence_count, :value).to_i,
            project_count: counts.dig(:project_count, :value).to_i,
            vulnerability_count: counts.dig(:vulnerability_count, :value).to_i
          )
        end

        def occurrence_id(bucket)
          bucket.dig(:occurrence_id, :value).to_i
        end

        def component_and_version(bucket)
          [bucket.dig(:key, :component_id), bucket.dig(:key, :component_version_id)]
        end

        def filter_key(component_id, component_version_id)
          "#{component_id}-#{component_version_id}"
        end

        # -- query options ------------------------------------------------------------------

        def dependencies_options
          query_options.merge(
            aggregate_by_component_and_version: true,
            bucket_size: page_size + 1,
            sort_by: params[:sort_by],
            sort: params[:sort],
            after_key: params[:after_key]
          )
        end

        def counts_options(pairs)
          query_options.merge(component_and_version_filters: pairs.index_by { |pair| filter_key(*pair) })
        end

        # Shared by both searches, so the counts see the same documents as the rows.
        def query_options
          {
            search_level: 'group',
            traversal_ids: [namespace.elastic_namespace_ancestry],
            security_project_tracked_context_id: params[:security_project_tracked_context_id],
            tracked_refs_scope: params[:tracked_refs_scope]&.to_sym
          }.merge(filter_options).compact
        end
        strong_memoize_attr :query_options

        def filter_options
          options = params.slice(*FORWARDED_PARAMS).to_h.symbolize_keys
          options[:not_component_versions] = params.dig(:not, :component_versions)

          options.delete(:package_managers) unless package_manager_filter_enabled?

          options
        end

        def package_manager_filter_enabled?
          Feature.enabled?(:dependencies_page_filter_by_package_manager, namespace)
        end

        def page_size
          (params[:per_page].presence || DEFAULT_PAGE_SIZE).to_i.clamp(1, MAX_PAGE_SIZE)
        end
      end
    end
  end
end
