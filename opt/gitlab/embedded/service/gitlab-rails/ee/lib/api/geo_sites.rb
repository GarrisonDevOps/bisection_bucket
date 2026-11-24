# frozen_string_literal: true

module API
  class GeoSites < ::API::Base
    include PaginationParams
    include APIGuard

    feature_category :geo_replication
    urgency :low

    before do
      authenticate_admin_or_geo_site!
    end

    helpers do
      def authenticate_admin_or_geo_site!
        if gitlab_geo_node_token?
          bad_request! unless update_geo_sites_endpoint?
          check_gitlab_geo_request_ip!
          allow_paused_nodes!
          authenticate_by_gitlab_geo_node_token!
        else
          authenticated_as_admin!
        end
      end

      def update_geo_sites_endpoint?
        request.put? && request.path.match?(%r{/geo_sites/\d+})
      end
    end

    resource :geo_sites do
      # Example request:
      #   POST /geo_sites
      desc 'Create a Geo site' do
        detail 'Creates a Geo site.'
        summary 'Creates a new Geo site'
        success code: 200, model: ::API::Entities::GeoSite
        failure [
          { code: 400, message: 'Validation error' },
          { code: 401, message: '401 Unauthorized' },
          { code: 403, message: '403 Forbidden' }
        ]
        tags %w[geo]
      end
      params do
        optional :primary, type: Boolean, default: false, desc: 'If `true`, the site is the primary Geo site.'
        optional :enabled, type: Boolean, default: true, desc: 'If `true`, the Geo site is enabled.'
        requires :name, type: String,
          desc: 'Unique identifier for the Geo site. Must match `geo_node_name` if it is set in `gitlab.rb`, ' \
                'otherwise it must match `external_url`.'
        requires :url, type: String, desc: 'User-facing URL of the Geo site.'
        optional :internal_url, type: String,
          desc: 'URL defined on the primary site that secondary sites use to contact it. Returns `url` if not set.'
        optional :files_max_capacity, type: Integer, default: 10, values: 0..,
          desc: 'Maximum concurrency of LFS and attachment backfill for the secondary site.'
        optional :repos_max_capacity, type: Integer, default: 10, values: 0..,
          desc: 'Maximum concurrency of repository backfill for the secondary site.'
        optional :verification_max_capacity, type: Integer, default: 10, values: 0..,
          desc: 'Maximum concurrency of verification for the site.'
        optional :container_repositories_max_capacity, type: Integer, default: 2, values: 0..,
          desc: 'Maximum concurrency of container repository sync for the site.'
        optional :sync_object_storage, type: Boolean, default: false,
          desc: 'If `true`, the secondary Geo site replicates blobs in object storage.'
        optional :selective_sync_type, type: String,
          desc: 'Limit syncing to only specific groups, or shards. Valid values: `"namespaces"`, `"shards"`, or `null`'
        optional :selective_sync_shards, type: Array[String],
          coerce_with: ::API::Validations::Types::CommaSeparatedToArray.coerce,
          desc: 'Repository storages to sync projects from if `selective_sync_type` is `shards`.'
        optional :selective_sync_namespace_ids, as: :namespace_ids, type: Array[Integer],
          coerce_with: Validations::Types::CommaSeparatedToIntegerArray.coerce,
          desc: 'IDs of groups to sync if `selective_sync_type` is `namespaces`.'
        optional :selective_sync_organization_ids,
          as: :organization_ids,
          type: Array[Integer],
          coerce_with: Validations::Types::CommaSeparatedToIntegerArray.coerce,
          desc: 'IDs of organizations to sync if `selective_sync_type` is `organizations`.'
        optional :minimum_reverification_interval, type: Integer,
          desc: 'Interval, in days, after which verification expires and is repeated. Has no effect when ' \
                'set on a secondary site.'
        optional :checksum_mismatch_report_threshold, type: Integer,
          desc: 'Number of consecutive checksum mismatches on a secondary site before it reports the resource to the ' \
                'primary for self-heal re-verification. Read from the secondary site, and has no effect when set on ' \
                'the primary.'
        optional :checksum_mismatch_self_heal_cooldown_minutes, type: Integer,
          desc: 'Minimum time, in minutes, between self-heal re-verification triggers for the same resource. The ' \
                'primary and each secondary site use their own value. Secondary sites use it to throttle ' \
                're-reporting the same resource, and the primary uses it to throttle re-verifying an ' \
                'already-verified resource.'
        optional :blob_download_timeout, type: Integer, default: 28800, values: 1..86400,
          desc: 'Maximum time (in seconds) for blob downloads during Geo sync. ' \
            '[Introduced](https://gitlab.com/gitlab-org/gitlab/-/work_items/569919) in GitLab 18.10.'
      end
      route_setting :tier, :premium
      route_setting :authorization, permissions: :create_geo_site, boundary_type: :instance, assignable_when: [:admin]
      post do
        create_params = declared_params(include_missing: false)

        new_geo_site = ::Geo::NodeCreateService.new(create_params).execute

        if new_geo_site.persisted?
          present new_geo_site, with: ::API::Entities::GeoSite
        else
          render_validation_error!(new_geo_site)
        end
      end

      # Example request:
      #   GET /geo_sites
      desc 'List all Geo sites' do
        detail 'Lists all Geo sites for the instance.'
        summary 'Retrieve configuration about all Geo sites'
        success code: 200, model: ::API::Entities::GeoSite
        failure [
          { code: 400, message: '400 Bad request' },
          { code: 401, message: '401 Unauthorized' },
          { code: 403, message: '403 Forbidden' }
        ]
        is_array true
        tags %w[geo]
      end
      params do
        use :pagination
      end
      route_setting :tier, :premium
      route_setting :authorization, permissions: :read_geo_site, boundary_type: :instance, assignable_when: [:admin]
      get do
        sites = GeoNode.all

        present paginate(sites), with: ::API::Entities::GeoSite
      end

      # Example request:
      #   GET /geo_sites/status
      desc 'List all Geo site statuses' do
        detail 'Lists all Geo site statuses. When the legacy `geo_upload_replication` and ' \
          '`geo_upload_force_primary_checksumming` feature flags are disabled, the `uploads_*` fields are the sum ' \
          'of the values for each upload type.'
        summary 'Get all Geo site statuses'
        success code: 200, model: ::API::Entities::GeoSiteStatus
        failure [
          { code: 400, message: '400 Bad request' },
          { code: 401, message: '401 Unauthorized' },
          { code: 403, message: '403 Forbidden' }
        ]
        is_array true
        tags %w[geo]
      end
      params do
        use :pagination
      end
      route_setting :tier, :premium
      route_setting :authorization, permissions: :read_geo_site, boundary_type: :instance, assignable_when: [:admin]
      get '/status' do
        status = GeoNodeStatus.all

        present paginate(status), with: ::API::Entities::GeoSiteStatus
      end

      route_param :id, type: Integer, desc: 'The ID of the site' do
        helpers do
          include ::Gitlab::Utils::StrongMemoize

          def geo_site
            GeoNode.find(params[:id])
          end
          strong_memoize_attr :geo_site

          def geo_site_status
            status = GeoNodeStatus.fast_current_node_status if GeoNode.current?(geo_site)
            status || geo_site.status
          end
          strong_memoize_attr :geo_site_status
        end

        # Example request:
        #   GET /geo_sites/:id
        desc 'Retrieve a Geo site' do
          detail 'Retrieves a specified Geo site.'
          summary 'Retrieve configuration about a specific Geo site'
          success code: 200, model: ::API::Entities::GeoSite
          failure [
            { code: 400, message: '400 Bad request' },
            { code: 401, message: '401 Unauthorized' },
            { code: 403, message: '403 Forbidden' },
            { code: 404, message: '404 GeoSite Not Found' }
          ]
          tags %w[geo]
        end
        route_setting :tier, :premium
        route_setting :authorization, permissions: :read_geo_site, boundary_type: :instance, assignable_when: [:admin]
        get do
          not_found!('GeoSite') unless geo_site

          present geo_site, with: ::API::Entities::GeoSite
        end

        # Example request:
        #   GET /geo_sites/:id/status
        desc 'Retrieve a Geo site status' do
          detail 'Retrieves the status for a specified Geo site. When the legacy `geo_upload_replication` and ' \
            '`geo_upload_force_primary_checksumming` feature flags are disabled, the `uploads_*` fields are the sum ' \
            'of the values for each upload type. The `health_status` field is either `Healthy` or `Unhealthy`. The ' \
            '`health` field can be empty, `Healthy`, or contain the actual error message.'
          summary 'Get Geo metrics for a single site'
          success code: 200, model: ::API::Entities::GeoSiteStatus
          failure [
            { code: 400, message: '400 Bad request' },
            { code: 401, message: '401 Unauthorized' },
            { code: 403, message: '403 Forbidden' },
            { code: 404, message: '404 GeoSite Not Found' }
          ]
          tags %w[geo]
        end
        params do
          optional :refresh, type: Boolean,
            desc: 'If `true`, fetches the latest status from the Geo site directly, ignoring the cache.'
        end
        route_setting :tier, :premium
        route_setting :authorization, permissions: :read_geo_site, boundary_type: :instance, assignable_when: [:admin]
        get 'status' do
          not_found!('GeoSite') unless geo_site

          not_found!('Status for Geo site not found') unless geo_site_status

          present geo_site_status, with: ::API::Entities::GeoSiteStatus
        end

        # Example request:
        #   POST /geo_sites/:id/repair
        desc 'Repair a Geo site' do
          detail 'Repairs the OAuth authentication of a Geo site if there is an OAuth synchronization problem ' \
            'between the primary or secondary Geo sites. In that case, the message `There are no OAuth application ' \
            'defined for this Geo node.` might be displayed.'
          summary 'Repair authentication of the Geo site'
          success code: 200, model: ::API::Entities::GeoSiteStatus
          failure [
            { code: 400, message: '400 Bad request' },
            { code: 401, message: '401 Unauthorized' },
            { code: 403, message: '403 Forbidden' },
            { code: 404, message: '404 GeoSite Not Found' }
          ]
          tags %w[geo]
        end
        route_setting :tier, :premium
        route_setting :authorization, permissions: :repair_geo_site, boundary_type: :instance, assignable_when: [:admin]
        post 'repair' do
          not_found!('GeoSite') unless geo_site

          if !geo_site.missing_oauth_application? || geo_site.repair
            status 200
            present geo_site_status, with: ::API::Entities::GeoSiteStatus
          else
            render_validation_error!(geo_site)
          end
        end

        # Example request:
        #   PUT /geo_sites/:id
        desc 'Update a Geo site' do
          detail 'Updates a specified Geo site.'
          summary 'Edit a Geo site'
          success code: 200, model: ::API::Entities::GeoSite
          failure [
            { code: 400, message: '400 Bad request' },
            { code: 401, message: '401 Unauthorized' },
            { code: 403, message: '403 Forbidden' },
            { code: 404, message: '404 GeoSite Not Found' }
          ]
          tags %w[geo]
        end
        params do
          optional :enabled, type: Boolean, desc: 'If `true`, the Geo site is enabled.'
          optional :name, type: String,
            desc: 'Unique identifier for the Geo site. Must match `geo_node_name` if it is set in `gitlab.rb`, ' \
                  'otherwise it must match `external_url`.'
          optional :url, type: String, desc: 'User-facing URL of the Geo site.'
          optional :internal_url, type: String,
            desc: 'URL defined on the primary site that secondary sites use to contact it. Returns `url` if not set.'
          optional :files_max_capacity, type: Integer, values: 0..,
            desc: 'Maximum concurrency of LFS and attachment backfill for the secondary site.'
          optional :repos_max_capacity, type: Integer, values: 0..,
            desc: 'Maximum concurrency of repository backfill for the secondary site.'
          optional :verification_max_capacity, type: Integer, values: 0..,
            desc: 'Maximum concurrency of verification for the site.'
          optional :container_repositories_max_capacity, type: Integer, values: 0..,
            desc: 'Maximum concurrency of container repository sync for the site.'
          optional :sync_object_storage, type: Boolean,
            desc: 'If `true`, the secondary Geo site replicates blobs in object storage.'
          optional :selective_sync_type, type: String,
            desc: 'Limit syncing to only specific groups, or shards. Valid values: `"namespaces"`, `"shards"`, ' \
                  'or `null`'
          optional :selective_sync_shards, type: Array[String],
            coerce_with: ::API::Validations::Types::CommaSeparatedToArray.coerce,
            desc: 'Repository storages to sync projects from if `selective_sync_type` is `shards`.'
          optional :selective_sync_namespace_ids, as: :namespace_ids, type: Array[Integer],
            coerce_with: Validations::Types::CommaSeparatedToIntegerArray.coerce,
            desc: 'IDs of groups to sync if `selective_sync_type` is `namespaces`.'
          optional :selective_sync_organization_ids,
            as: :organization_ids,
            type: Array[Integer],
            coerce_with: Validations::Types::CommaSeparatedToIntegerArray.coerce,
            desc: 'IDs of organizations to sync if `selective_sync_type` is `organizations`.'
          optional :minimum_reverification_interval, type: Integer,
            desc: 'Interval, in days, after which verification expires and is repeated. Has no effect ' \
                  'when set on a secondary site.'
          optional :checksum_mismatch_report_threshold, type: Integer,
            desc: 'Number of consecutive checksum mismatches on a secondary site before it reports the resource to ' \
                  'the primary for self-heal re-verification. Read from the secondary site, and has no effect when ' \
                  'set on the primary.'
          optional :checksum_mismatch_self_heal_cooldown_minutes, type: Integer,
            desc: 'Minimum time, in minutes, between self-heal re-verification triggers for the same resource. The ' \
                  'primary and each secondary site use their own value. Secondary sites use it to throttle ' \
                  're-reporting the same resource, and the primary uses it to throttle re-verifying an ' \
                  'already-verified resource.'
          optional :blob_download_timeout, type: Integer, values: 1..86400,
            desc: 'Maximum time (in seconds) for blob downloads during Geo sync. ' \
              '[Introduced](https://gitlab.com/gitlab-org/gitlab/-/work_items/569919) in GitLab 18.10.'
        end
        route_setting :tier, :premium
        route_setting :authorization, permissions: :update_geo_site, boundary_type: :instance, assignable_when: [:admin]
        put do
          not_found!('GeoSite') unless geo_site

          update_params = declared_params(include_missing: false)

          updated_geo_site = ::Geo::NodeUpdateService.new(geo_site, update_params).execute

          if updated_geo_site
            present geo_site, with: ::API::Entities::GeoSite
          else
            render_validation_error!(geo_site)
          end
        end

        # Example request:
        #   DELETE /geo_sites/:id
        desc 'Delete a Geo site' do
          detail 'Deletes a specified Geo site.'
          summary 'Delete a Geo site'
          success code: 204, message: '204 No Content'
          failure [
            { code: 400, message: '400 Bad request' },
            { code: 401, message: '401 Unauthorized' },
            { code: 403, message: '403 Forbidden' },
            { code: 404, message: '404 GeoSite Not Found' }
          ]
          tags %w[geo]
        end
        route_setting :tier, :premium
        route_setting :authorization, permissions: :delete_geo_site, boundary_type: :instance, assignable_when: [:admin]
        delete do
          not_found!('GeoSite') unless geo_site

          geo_site.destroy!

          no_content!
        end
      end
    end
  end
end
