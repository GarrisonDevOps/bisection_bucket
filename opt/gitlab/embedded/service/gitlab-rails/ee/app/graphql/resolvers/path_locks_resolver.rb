# frozen_string_literal: true

module Resolvers
  class PathLocksResolver < BaseResolver
    include Gitlab::Graphql::Authorize::AuthorizeResource
    include LooksAhead

    authorize :read_path_locks

    type Types::PathLockType, null: true

    argument :path, GraphQL::Types::String,
      required: false,
      validates: { length: { maximum: 4096 } },
      description: 'Return only locks on the path, its parent directories, or paths under it.'

    alias_method :project, :object

    def resolve_with_lookahead(**args)
      authorize!(project)

      return [] unless path_lock_feature_enabled?

      find_path_locks(args)
    end

    private

    def preloads
      { user: [:user] }
    end

    def find_path_locks(args)
      path_locks = project.path_locks
      path_locks = path_locks.related_to_path(args[:path]) if args[:path].present?

      apply_lookahead(path_locks)
    end

    def path_lock_feature_enabled?
      project.licensed_feature_available?(:file_locks)
    end
  end
end
