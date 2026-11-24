# frozen_string_literal: true

module API
  module Entities
    class GeoSite < Grape::Entity
      include ::API::Helpers::RelatedResourcesHelpers

      expose :id, documentation: { type: 'Integer', format: 'int64' }
      expose :name, documentation: { type: 'String' }
      expose :url, documentation: { type: 'String' }
      expose :internal_url, documentation: { type: 'String' }
      expose :primary?, as: :primary, documentation: { type: 'Boolean' }
      expose :enabled, documentation: { type: 'Boolean' }
      expose :current, documentation: { type: 'Boolean' } do |geo_site|
        ::GeoNode.current?(geo_site)
      end
      expose :files_max_capacity, documentation: { type: 'Integer' }
      expose :repos_max_capacity, documentation: { type: 'Integer' }
      expose :verification_max_capacity, documentation: { type: 'Integer' }
      expose :container_repositories_max_capacity, documentation: { type: 'Integer' }
      expose :selective_sync_type, documentation: { type: 'String' }
      expose :selective_sync_shards, documentation: { type: 'Array' }
      expose :namespace_ids, as: :selective_sync_namespace_ids, documentation: { type: 'Array' }
      expose :organization_ids, as: :selective_sync_organization_ids,
        documentation: { type: 'Array' },
        if: ->(_, _) { ::Gitlab::Geo.geo_selective_sync_by_organizations_enabled? }
      expose :minimum_reverification_interval, documentation: { type: 'Integer' }
      expose :blob_download_timeout, documentation: { type: 'Integer' }
      expose :checksum_mismatch_report_threshold, documentation: { type: 'Integer' }
      expose :checksum_mismatch_self_heal_cooldown_minutes, documentation: { type: 'Integer' }
      expose :sync_object_storage, documentation: { type: 'Boolean' },
        if: ->(geo_site, _) { geo_site.secondary_or_org_migration_target? }

      expose :web_edit_url, documentation: { type: 'String' } do |geo_site|
        ::Gitlab::Routing.url_helpers.edit_admin_geo_node_url(geo_site)
      end

      expose :web_geo_replication_details_url, documentation: { type: 'String' },
        if: ->(geo_site) { geo_site.secondary_or_org_migration_target? },
        proc: ->(geo_site) { geo_site.geo_replication_details_url }

      # Links should always be the last element on the list
      expose :_links, documentation: { type: 'Hash' } do
        expose :self, documentation: { type: 'String' } do |geo_site|
          expose_url api_v4_geo_sites_path(id: geo_site.id)
        end

        expose :status, documentation: { type: 'String' } do |geo_site|
          expose_url api_v4_geo_sites_status_path(id: geo_site.id)
        end

        expose :repair, documentation: { type: 'String' } do |geo_site|
          expose_url api_v4_geo_sites_repair_path(id: geo_site.id)
        end
      end
    end
  end
end
