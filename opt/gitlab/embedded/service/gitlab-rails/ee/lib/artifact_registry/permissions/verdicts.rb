# frozen_string_literal: true

module ArtifactRegistry
  module Permissions
    class Verdicts
      NAMESPACE_ACTIONS = %w[
        read_repository
        create_repository
        update_repository
        delete_repository
        create_repository_upstream
        update_repository_upstream
        delete_repository_upstream
      ].freeze

      REPOSITORY_ACTIONS = %w[
        read_repository
        update_repository
        delete_repository
        create_repository_upstream
        update_repository_upstream
        delete_repository_upstream
        read_artifact
        create_artifact
        delete_artifact
        read_role_assignment
        create_role_assignment
        update_role_assignment
        delete_role_assignment
      ].freeze

      ACTIONS_BY_SCOPE = { namespace: NAMESPACE_ACTIONS, repository: REPOSITORY_ACTIONS }.freeze

      attr_reader :scope, :read, :slug

      def self.absent(scope:, read:, slug:)
        new(nil, scope: scope, read: read, slug: slug)
      end

      def initialize(attributes, scope:, read:, slug:)
        @actions = ACTIONS_BY_SCOPE.fetch(scope)
        @scope = scope
        @read = read
        @slug = slug
        @absent = attributes.nil?
        @verdicts = (attributes || {}).slice(*@actions).freeze
      end

      def absent?
        @absent
      end

      def allowed?(action)
        @verdicts[action.to_s] == true
      end

      def complete?
        missing_actions.empty?
      end

      def missing_actions
        @actions - @verdicts.keys
      end
    end
  end
end
