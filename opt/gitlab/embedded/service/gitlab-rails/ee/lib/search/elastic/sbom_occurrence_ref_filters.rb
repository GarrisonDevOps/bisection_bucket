# frozen_string_literal: true

module Search
  module Elastic
    module SbomOccurrenceRefFilters
      class << self
        include ::Elastic::Latest::QueryContext::Aware
        include Search::Elastic::Concerns::FilterUtils

        def by_project_ids(query_hash:, options:)
          project_ids = options[:project_ids]
          return query_hash if project_ids.blank?

          context.name(:filters) do
            add_filter(query_hash, :query, :bool, :filter) do
              {
                terms: {
                  _name: context.name(:project_ids),
                  project_id: Array.wrap(project_ids)
                }
              }
            end
          end
        end

        def by_component_ids(query_hash:, options:)
          component_ids = options[:component_ids]
          return query_hash if component_ids.blank?

          context.name(:filters) do
            add_filter(query_hash, :query, :bool, :filter) do
              {
                terms: {
                  _name: context.name(:component_ids),
                  component_id: Array.wrap(component_ids)
                }
              }
            end
          end
        end

        def by_component_names(query_hash:, options:)
          component_names = options[:component_names]
          return query_hash if component_names.blank?

          context.name(:filters) do
            add_filter(query_hash, :query, :bool, :filter) do
              {
                terms: {
                  _name: context.name(:component_names),
                  component_name: Array.wrap(component_names)
                }
              }
            end
          end
        end

        def by_package_managers(query_hash:, options:)
          package_managers = options[:package_managers]
          return query_hash if package_managers.blank?

          context.name(:filters) do
            add_filter(query_hash, :query, :bool, :filter) do
              {
                terms: {
                  _name: context.name(:package_managers),
                  package_manager: Array.wrap(package_managers)
                }
              }
            end
          end
        end

        # Mirrors the Postgres LEFT OUTER JOIN in `filter_by_source_types`: a nil member matches
        # occurrences with no source, which is a missing field here rather than a value. Values are
        # already enum integers, as with `VulnerabilityFilters#by_report_type`.
        def by_source_types(query_hash:, options:)
          source_types = options[:source_types]
          return query_hash if source_types.blank?

          values = Array.wrap(source_types)
          present = values.compact
          include_missing = values.size != present.size

          context.name(:filters) do
            add_filter(query_hash, :query, :bool, :filter) do
              should = []
              should << { terms: { source_type: present } } if present.any?
              should << { bool: { must_not: { exists: { field: :source_type } } } } if include_missing

              {
                bool: {
                  _name: context.name(:source_types),
                  should: should,
                  minimum_should_match: 1
                }
              }
            end
          end
        end

        def by_component_versions(query_hash:, options:)
          component_versions = options[:component_versions]
          not_component_versions = options[:not_component_versions]
          return query_hash if component_versions.blank? && not_component_versions.blank?

          context.name(:filters) do
            if component_versions.present?
              add_filter(query_hash, :query, :bool, :filter) do
                {
                  terms: {
                    _name: context.name(:component_versions),
                    component_version: Array.wrap(component_versions)
                  }
                }
              end
            end

            if not_component_versions.present?
              add_filter(query_hash, :query, :bool, :must_not) do
                {
                  terms: {
                    _name: context.name(:not_component_versions),
                    component_version: Array.wrap(not_component_versions)
                  }
                }
              end
            end

            query_hash
          end
        end

        def by_licenses(query_hash:, options:)
          licenses = options[:licenses]
          return query_hash if licenses.blank?

          values = Array.wrap(licenses)

          context.name(:filters) do
            add_filter(query_hash, :query, :bool, :filter) do
              license_filter(values, options[:include_secondary_license])
            end
          end
        end

        def by_malware(query_hash:, options:)
          malware = options[:malware]
          return query_hash unless malware.in?([true, false])

          context.name(:filters) do
            add_filter(query_hash, :query, :bool, :filter) do
              { term: { malware: { _name: context.name(:malware), value: malware } } }
            end
          end
        end

        def by_security_project_tracked_context_id(query_hash:, options:)
          security_project_tracked_context_id = options[:security_project_tracked_context_id]
          return query_hash if security_project_tracked_context_id.blank?

          context.name(:filters) do
            add_filter(query_hash, :query, :bool, :filter) do
              {
                terms: {
                  _name: context.name(:security_project_tracked_context_id),
                  security_project_tracked_context_id: Array.wrap(security_project_tracked_context_id)
                }
              }
            end
          end
        end

        # Documents are one per (occurrence, tracked ref), so without this filter every aggregated count
        # is multiplied by the number of tracked refs the occurrence appears on.
        def by_tracked_refs_scope(query_hash:, options:)
          # We must not apply the default branch filter when filtering by a specific
          # tracked ref as it won't behave as intended when trying to show a non-default ref.
          return query_hash if options[:security_project_tracked_context_id].present?

          case options[:tracked_refs_scope]
          when :all_refs
            query_hash
          else
            # The dependency list shows dependencies on the default branch by default
            by_is_default(query_hash: query_hash, value: true)
          end
        end

        def by_is_default(query_hash:, value:)
          context.name(:filters) do
            add_filter(query_hash, :query, :bool, :filter) do
              { term: { is_default: { _name: context.name(:is_default), value: value } } }
            end
          end
        end

        private

        def license_filter(values, include_secondary)
          unless include_secondary
            return { terms: { _name: context.name(:licenses), primary_license_spdx_identifier: values } }
          end

          {
            bool: {
              _name: context.name(:licenses),
              should: [
                { terms: { primary_license_spdx_identifier: values } },
                { terms: { secondary_license_spdx_identifier: values } }
              ],
              minimum_should_match: 1
            }
          }
        end
      end
    end
  end
end
