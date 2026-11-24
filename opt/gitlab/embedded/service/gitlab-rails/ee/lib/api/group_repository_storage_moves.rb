# frozen_string_literal: true

module API
  class GroupRepositoryStorageMoves < ::API::Base
    include PaginationParams

    before { authenticated_as_admin! }

    feature_category :gitaly

    resource :group_repository_storage_moves do
      desc 'List all group repository storage moves' do
        detail 'Lists all group repository storage moves for an instance.'
        tags ['storage_moves']
        is_array true
        success code: 200, model: Entities::Groups::RepositoryStorageMove
      end
      params do
        use :pagination
      end
      route_setting :tier, :premium
      route_setting :authorization, permissions: :read_repository_storage_move, boundary_type: :instance,
        assignable_when: [:admin]
      get do
        storage_moves = ::Groups::RepositoryStorageMove.with_groups.order_created_at_desc

        present paginate(storage_moves), with: Entities::Groups::RepositoryStorageMove, current_user: current_user
      end

      desc 'Retrieve a group repository storage move' do
        detail 'Retrieves a specified group repository storage move. This feature was introduced in GitLab 13.9.'
        tags ['storage_moves']
        success code: 200, model: Entities::Groups::RepositoryStorageMove
      end
      params do
        requires :repository_storage_move_id, type: Integer, desc: 'ID of the group repository storage move.'
      end
      route_setting :tier, :premium
      route_setting :authorization, permissions: :read_repository_storage_move, boundary_type: :instance,
        assignable_when: [:admin]
      get ':repository_storage_move_id' do
        storage_move = ::Groups::RepositoryStorageMove.find(params[:repository_storage_move_id])

        present storage_move, with: Entities::Groups::RepositoryStorageMove, current_user: current_user
      end

      desc 'Create group repository storage moves for a storage shard' do
        detail 'Creates repository storage moves for all groups on a specified storage shard.'
        tags ['storage_moves']
        success code: 202, message: '202 Accepted'
      end
      # rubocop:disable API/ParameterValuesProc -- storage shards are instance-specific
      params do
        requires :source_storage_name, type: String, desc: 'Name of the source storage shard.', values: -> { Gitlab.config.repositories.storages.keys }, documentation: { example: 'default' }
        optional :destination_storage_name, type: String, desc: 'Name of the destination storage shard. If omitted, the storage is selected [automatically based on storage weights](https://docs.gitlab.com/administration/repository_storage_paths/#configure-where-new-repositories-are-stored).', values: -> { Gitlab.config.repositories.storages.keys }, documentation: { example: 'fast-storage' }
      end
      # rubocop:enable API/ParameterValuesProc
      route_setting :tier, :premium
      route_setting :authorization, permissions: :create_repository_storage_move, boundary_type: :instance,
        assignable_when: [:admin]
      post do
        ::Groups::ScheduleBulkRepositoryShardMovesService.enqueue(
          declared_params[:source_storage_name],
          declared_params[:destination_storage_name]
        )

        accepted!
      end
    end

    params do
      requires :id, type: String, desc: 'ID or URL-encoded path of the group.'
    end
    resource :groups, requirements: ::API::NAMESPACE_OR_PROJECT_REQUIREMENTS do
      desc 'List all repository storage moves for a group' do
        detail 'Lists all repository storage moves for a specified group.'
        tags ['storage_moves']
        is_array true
        success code: 200, model: Entities::Groups::RepositoryStorageMove
      end
      params do
        use :pagination
      end
      route_setting :tier, :premium
      route_setting :authorization, permissions: :read_repository_storage_move, boundary_type: :group,
        assignable_when: [:admin]
      get ':id/repository_storage_moves' do
        storage_moves = user_group.repository_storage_moves.with_groups.order_created_at_desc

        present paginate(storage_moves), with: Entities::Groups::RepositoryStorageMove, current_user: current_user
      end

      desc 'Retrieve a repository storage move for a group' do
        detail 'Retrieves a specified repository storage move for a group. This feature was introduced in GitLab 13.9.'
        tags ['storage_moves']
        success code: 200, model: Entities::Groups::RepositoryStorageMove
      end
      params do
        requires :repository_storage_move_id, type: Integer, desc: 'ID of the group repository storage move.'
      end
      route_setting :tier, :premium
      route_setting :authorization, permissions: :read_repository_storage_move, boundary_type: :group,
        assignable_when: [:admin]
      get ':id/repository_storage_moves/:repository_storage_move_id' do
        storage_move = user_group.repository_storage_moves.find(params[:repository_storage_move_id])

        present storage_move, with: Entities::Groups::RepositoryStorageMove, current_user: current_user
      end

      desc 'Create a group repository storage move' do
        detail 'Creates a group repository storage move for a specified group. This operation moves only group ' \
          'wiki repositories and does not move repositories for projects in a group.'
        tags ['storage_moves']
        success code: 201, model: Entities::Groups::RepositoryStorageMove
      end
      params do
        optional :destination_storage_name, type: String, desc: 'Name of the destination storage shard. If omitted, the storage is selected [automatically based on storage weights](https://docs.gitlab.com/administration/repository_storage_paths/#configure-where-new-repositories-are-stored).'
      end
      route_setting :tier, :premium
      route_setting :authorization, permissions: :create_repository_storage_move, boundary_type: :group,
        assignable_when: [:admin]
      post ':id/repository_storage_moves' do
        storage_move = user_group.repository_storage_moves.build(
          declared_params.compact.merge(source_storage_name: user_group.wiki.repository_storage)
        )

        if storage_move.schedule
          present storage_move, with: Entities::Groups::RepositoryStorageMove, current_user: current_user
        else
          render_validation_error!(storage_move)
        end
      end
    end
  end
end
