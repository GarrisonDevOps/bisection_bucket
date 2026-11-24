# frozen_string_literal: true

module Ai
  module DuoWorkflows
    class SessionArtifactsFinder
      # rubocop:disable CodeReuse/Finder -- Dispatches to PG- or ClickHouse-backed finder
      def initialize(current_user:, namespace:, params: {})
        @current_user = current_user
        @namespace = namespace
        @params = params
      end

      def execute
        return ::Ai::DuoWorkflows::SessionArtifact.none unless allowed?

        if ::Gitlab::ClickHouse.globally_enabled_for_analytics?
          ::Ai::DuoWorkflows::SessionArtifacts::ClickHouseFinder.new(
            namespace: namespace,
            params: params
          ).execute
        else
          ::Ai::DuoWorkflows::SessionArtifacts::PostgresqlFinder.new(
            namespace: namespace,
            params: params
          ).execute
        end
      end
      # rubocop:enable CodeReuse/Finder

      private

      attr_reader :current_user, :namespace, :params

      def allowed?
        Ability.allowed?(current_user, :read_agent_artifacts, namespace)
      end
    end
  end
end
