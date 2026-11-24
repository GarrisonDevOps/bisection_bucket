# frozen_string_literal: true

module API
  class GeoNodes < ::API::Base
    include PaginationParams
    include APIGuard

    feature_category :geo_replication
    urgency :low

    before do
      authenticate_admin_or_geo_node!
    end

    helpers do
      def authenticate_admin_or_geo_node!
        if gitlab_geo_node_token?
          bad_request! unless update_geo_nodes_endpoint?
          check_gitlab_geo_request_ip!
          allow_paused_nodes!
          authenticate_by_gitlab_geo_node_token!
        else
          authenticated_as_admin!
        end
      end

      def update_geo_nodes_endpoint?
        request.put? && request.path.match?(%r{/geo_nodes/\d+})
      end
    end

    resource :geo_nodes do
      # Example request:
      #   POST /geo_nodes
      desc 'Create a Geo node' do
        detail 'Creates a Geo node.'
        summary 'Creates a new Geo node'
        success code: 200, model: ::API::Entities::GeoNode
        failure [
          { code: 400, message: 'Validation error' },
          { code: 401, message: '401 Unauthorized' },
          { code: 403, message: '403 Forbidden' }
        ]
        tags %w[geo]
      end
      params do
        optional :primary, type: Boolean, default: false, desc: 'Specifying whether this node will be primary.'
        optional :enabled, type: Boolean, default: true,
          desc: 'Specifying whether this node will be enabled.'
        requires :name, type: String,
          desc: 'Unique identifier for the Geo node. Must match `geo_node_name` if it is set in `gitlab.rb`, ' \
            'otherwise it must match `external_url`.'
        requires :url, type: String, desc: 'User-facing URL of the Geo node.'
        optional :internal_url, type: String,
          desc: 'URL defined on the primary node that secondary nodes use to contact it. Returns `url` if not set.'
        optional :files_max_capacity, type: Integer, default: 10, values: 0..,
          desc: 'Control the maximum concurrency of LFS/attachment backfill for this secondary node.'
        optional :repos_max_capacity, type: Integer, default: 10, values: 0..,
          desc: 'Control the maximum concurrency of repository backfill for this secondary node.'
        optional :verification_max_capacity, type: Integer, default: 10, values: 0..,
          desc: 'Control the maximum concurrency of repository verification for this node.'
        optional :container_repositories_max_capacity, type: Integer, default: 2, values: 0..,
          desc: 'Control the maximum concurrency of container repository sync for this node.'
        optional :sync_object_storage, type: Boolean, default: false,
          desc: 'Flag indicating if the secondary Geo node will replicate blobs in Object Storage.'
        optional :selective_sync_type, type: String,
          desc: 'Limit syncing to only specific groups or shards. Possible values are `namespaces`, `shards`, and ' \
            '`null`.'
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
          desc: 'Interval, in days, after which repository verification expires and is repeated. Has no effect when ' \
            'set on a secondary node.'
        optional :checksum_mismatch_report_threshold, type: Integer,
          desc: 'Number of consecutive checksum mismatches on a secondary node before it reports the resource to the ' \
            'primary for self-heal re-verification. Read from the secondary node, and has no effect when set on ' \
            'the primary.'
        optional :checksum_mismatch_self_heal_cooldown_minutes, type: Integer,
          desc: 'Minimum time, in minutes, between self-heal re-verification triggers for the same resource. The ' \
            'primary and each secondary node use their own value. Secondary nodes use it to throttle ' \
            're-reporting the same resource, and the primary uses it to throttle re-verifying an ' \
            'already-verified resource.'
      end
      route_setting :tier, :premium
      route_setting :authorization, permissions: :create_geo_node, boundary_type: :instance, assignable_when: [:admin]
      post do
        create_params = declared_params(include_missing: false)

        create_params.delete(:organization_ids) unless ::Gitlab::Geo.geo_selective_sync_by_organizations_enabled?

        new_geo_node = ::Geo::NodeCreateService.new(create_params).execute

        if new_geo_node.persisted?
          present new_geo_node, with: ::API::Entities::GeoNode
        else
          render_validation_error!(new_geo_node)
        end
      end

      # Example request:
      #   GET /geo_nodes
      desc 'List all Geo nodes' do
        detail 'Lists all Geo nodes for the instance.'
        summary 'Retrieve configuration about all Geo nodes'
        success code: 200, model: ::API::Entities::GeoNode
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
      route_setting :authorization, permissions: :read_geo_node, boundary_type: :instance, assignable_when: [:admin]
      get do
        nodes = GeoNode.all

        present paginate(nodes), with: ::API::Entities::GeoNode
      end

      # Example request:
      #   GET /geo_nodes/status
      desc 'List all Geo node statuses' do
        detail 'Lists all Geo node statuses.'
        summary 'Get all Geo node statuses'
        success code: 200, model: ::API::Entities::GeoNodeStatus
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
      route_setting :authorization, permissions: :read_geo_node, boundary_type: :instance, assignable_when: [:admin]
      get '/status' do
        status = GeoNodeStatus.all

        present paginate(status), with: ::API::Entities::GeoNodeStatus
      end

      route_param :id, type: Integer, desc: 'The ID of the node' do
        helpers do
          include ::Gitlab::Utils::StrongMemoize

          def geo_node
            GeoNode.find(params[:id])
          end
          strong_memoize_attr :geo_node

          def geo_node_status
            status = GeoNodeStatus.fast_current_node_status if GeoNode.current?(geo_node)
            status || geo_node.status
          end
          strong_memoize_attr :geo_node_status
        end

        # Example request:
        #   GET /geo_nodes/:id
        desc 'Retrieve a single Geo node' do
          detail 'Retrieves a single Geo Node.'
          summary 'Retrieve configuration about a specific Geo node'
          success code: 200, model: ::API::Entities::GeoNode
          failure [
            { code: 400, message: '400 Bad request' },
            { code: 401, message: '401 Unauthorized' },
            { code: 403, message: '403 Forbidden' },
            { code: 404, message: '404 GeoNode Not Found' }
          ]
          tags %w[geo]
        end
        route_setting :tier, :premium
        route_setting :authorization, permissions: :read_geo_node, boundary_type: :instance, assignable_when: [:admin]
        get do
          not_found!('GeoNode') unless geo_node

          present geo_node, with: ::API::Entities::GeoNode
        end

        # Example request:
        #   GET /geo_nodes/:id/status
        desc 'Retrieve metrics for a Geo node' do
          detail 'Retrieves metrics for a specified Geo node.'
          summary 'Get Geo metrics for a single node'
          success code: 200, model: ::API::Entities::GeoNodeStatus
          failure [
            { code: 400, message: '400 Bad request' },
            { code: 401, message: '401 Unauthorized' },
            { code: 403, message: '403 Forbidden' },
            { code: 404, message: '404 GeoNode Not Found' }
          ]
          tags %w[geo]
        end
        params do
          optional :refresh, type: Boolean,
            desc: 'If `true`, fetches the latest status from the Geo node directly, ignoring the cache.'
        end
        route_setting :tier, :premium
        route_setting :authorization, permissions: :read_geo_node, boundary_type: :instance, assignable_when: [:admin]
        get 'status' do
          not_found!('GeoNode') unless geo_node

          not_found!('Status for Geo node not found') unless geo_node_status

          present geo_node_status, with: ::API::Entities::GeoNodeStatus
        end

        # Example request:
        #   POST /geo_nodes/:id/repair
        desc 'Repair authentication of the Geo node' do
          detail 'Repairs the OAuth authentication of a primary Geo node.'
          success code: 200, model: ::API::Entities::GeoNodeStatus
          failure [
            { code: 400, message: '400 Bad request' },
            { code: 401, message: '401 Unauthorized' },
            { code: 403, message: '403 Forbidden' },
            { code: 404, message: '404 GeoNode Not Found' }
          ]
          tags %w[geo]
        end
        route_setting :tier, :premium
        route_setting :authorization, permissions: :repair_geo_node, boundary_type: :instance, assignable_when: [:admin]
        post 'repair' do
          not_found!('GeoNode') unless geo_node

          if !geo_node.missing_oauth_application? || geo_node.repair
            status 200
            present geo_node_status, with: ::API::Entities::GeoNodeStatus
          else
            render_validation_error!(geo_node)
          end
        end

        # Example request:
        #   PUT /geo_nodes/:id
        desc 'Update a Geo node' do
          detail 'Updates a specified Geo node.'
          summary 'Edit a Geo node'
          success code: 200, model: ::API::Entities::GeoNode
          failure [
            { code: 400, message: '400 Bad request' },
            { code: 401, message: '401 Unauthorized' },
            { code: 403, message: '403 Forbidden' },
            { code: 404, message: '404 GeoNode Not Found' }
          ]
          tags %w[geo]
        end
        params do
          optional :enabled, type: Boolean, desc: 'If `true`, the Geo node is enabled.'
          optional :name, type: String,
            desc: 'Unique identifier for the Geo node. Must match `geo_node_name` if it is set in `gitlab.rb`, ' \
              'otherwise it must match `external_url`.'
          optional :url, type: String, desc: 'User-facing URL of the Geo node.'
          optional :internal_url, type: String,
            desc: 'URL defined on the primary node that secondary nodes use to contact it. Returns `url` if not set.'
          optional :files_max_capacity, type: Integer, values: 0..,
            desc: 'Maximum concurrency of LFS and attachment backfill for the secondary node.'
          optional :repos_max_capacity, type: Integer, values: 0..,
            desc: 'Maximum concurrency of repository backfill for the secondary node.'
          optional :verification_max_capacity, type: Integer, values: 0..,
            desc: 'Maximum concurrency of repository verification for the node.'
          optional :container_repositories_max_capacity, type: Integer, values: 0..,
            desc: 'Maximum concurrency of container repository sync for the node.'
          optional :sync_object_storage, type: Boolean,
            desc: 'If `true`, the secondary Geo node replicates blobs in object storage.'
          optional :selective_sync_type, type: String,
            desc: 'Limit syncing to only specific groups or shards. Possible values are `namespaces`, `shards`, and ' \
              '`null`.'
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
            desc: 'Interval, in days, after which repository verification expires and is repeated. Has no effect ' \
              'when set on a secondary node.'
          optional :checksum_mismatch_report_threshold, type: Integer,
            desc: 'Number of consecutive checksum mismatches on a secondary node before it reports the resource to ' \
              'the primary for self-heal re-verification. Read from the secondary node, and has no effect when ' \
              'set on the primary.'
          optional :checksum_mismatch_self_heal_cooldown_minutes, type: Integer,
            desc: 'Minimum time, in minutes, between self-heal re-verification triggers for the same resource. The ' \
              'primary and each secondary node use their own value. Secondary nodes use it to throttle ' \
              're-reporting the same resource, and the primary uses it to throttle re-verifying an ' \
              'already-verified resource.'
        end
        route_setting :tier, :premium
        route_setting :authorization, permissions: :update_geo_node, boundary_type: :instance, assignable_when: [:admin]
        put do
          not_found!('GeoNode') unless geo_node

          update_params = declared_params(include_missing: false)

          update_params.delete(:organization_ids) unless ::Gitlab::Geo.geo_selective_sync_by_organizations_enabled?

          updated_geo_node = ::Geo::NodeUpdateService.new(geo_node, update_params).execute

          if updated_geo_node
            present geo_node, with: ::API::Entities::GeoNode
          else
            render_validation_error!(geo_node)
          end
        end

        # Example request:
        #   DELETE /geo_nodes/:id
        desc 'Delete a Geo node' do
          detail 'Deletes a specified Geo node.'
          summary 'Delete a Geo node'
          success code: 204, message: '204 No Content'
          failure [
            { code: 400, message: '400 Bad request' },
            { code: 401, message: '401 Unauthorized' },
            { code: 403, message: '403 Forbidden' },
            { code: 404, message: '404 GeoNode Not Found' }
          ]
          tags %w[geo]
        end
        route_setting :tier, :premium
        route_setting :authorization, permissions: :delete_geo_node, boundary_type: :instance, assignable_when: [:admin]
        delete do
          not_found!('GeoNode') unless geo_node

          geo_node.destroy!

          no_content!
        end
      end
    end
  end
end
