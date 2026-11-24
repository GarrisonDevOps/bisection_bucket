# frozen_string_literal: true

module Mutations
  module Projects
    class SetLocked < BaseMutation
      graphql_name 'ProjectSetLocked'

      include FindsProject

      authorize :create_path_lock
      authorize_granular_token permissions: :create_path_lock,
        boundary_argument: :project_path, boundary_type: :project

      argument :project_path, GraphQL::Types::ID,
        required: true,
        description: 'Full path of the project to mutate.'

      argument :file_path, GraphQL::Types::String,
        required: true,
        description: 'Full path to the file.'

      argument :lock, GraphQL::Types::Boolean,
        required: true,
        description: 'Whether or not to lock the file path.'

      field :project, Types::ProjectType,
        null: true,
        description: 'Project after mutation.'

      attr_reader :project

      def resolve(project_path:, file_path:, lock:)
        project = authorized_find!(project_path)

        unless project.licensed_feature_available?(:file_locks)
          raise_resource_not_available_error! 'FileLocks feature disabled'
        end

        path_lock = project.path_locks.for_path(file_path)

        if lock && !path_lock
          PathLocks::LockService.new(project, current_user).execute(file_path)
        elsif !lock && path_lock
          PathLocks::UnlockService.new(project, current_user).execute(path_lock)
        end

        { project: project, errors: [] }
      rescue PathLocks::UnlockService::AccessDenied, PathLocks::LockService::AccessDenied => error
        { project: nil, errors: [error.message] }
      end
    end
  end
end
