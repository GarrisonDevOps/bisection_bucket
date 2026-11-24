# frozen_string_literal: true

module Search
  module Elastic
    module Types
      module Sbom
        class OccurrenceRef
          class << self
            def index_name
              Search::Elastic::References::Sbom::OccurrenceRef.index
            end

            def target
              ::Sbom::OccurrenceRef
            end

            def mappings
              {
                dynamic: 'strict',
                properties: base_mappings
              }
            end

            def settings
              base_settings
            end

            private

            def base_mappings
              {
                type: { type: 'keyword' },
                schema_version: { type: 'short' },
                project_id: { type: 'long' },
                traversal_ids: { type: 'keyword' },
                sbom_occurrence_id: { type: 'long' },
                security_project_tracked_context_id: { type: 'long' },
                pipeline_id: { type: 'long' },
                commit_sha: { type: 'keyword' },
                is_default: { type: 'boolean' },
                component_name: { type: 'keyword' },
                component_version: { type: 'keyword' },
                component_id: { type: 'long' },
                component_version_id: { type: 'long' },
                source_id: { type: 'long' },
                source_type: { type: 'short' }, # enum
                package_manager: { type: 'keyword' },
                input_file_path: { type: 'keyword' },
                # Denormalised primary (licenses[0]) and secondary (licenses[1]) licenses.
                # `by_licenses` filters depth 0-1 (positions 0 OR 1); the
                # COALESCE(spdx_identifier, name) sort needs the name fallback at both
                # positions.
                primary_license_spdx_identifier: { type: 'keyword' },
                primary_license_name: { type: 'keyword' },
                secondary_license_spdx_identifier: { type: 'keyword' },
                secondary_license_name: { type: 'keyword' },
                highest_severity: { type: 'short' }, # enum
                vulnerability_count: { type: 'integer' },
                reachability: { type: 'short' }, # enum
                archived: { type: 'boolean' },
                uuid: { type: 'keyword' },
                purl_type: { type: 'short' }, # enum
                component_type: { type: 'short' }, # enum
                source_package_name: { type: 'keyword' },
                created_at: { type: 'date' },
                updated_at: { type: 'date' },
                malware: { type: 'boolean' },
                policy_violations: { type: 'short' } # enum
              }
            end

            def base_settings
              ::Elastic::Latest::Config.settings.to_hash.deep_merge(
                index: ::Elastic::Latest::Config.separate_index_specific_settings(index_name)
              )
            end
          end
        end
      end
    end
  end
end
