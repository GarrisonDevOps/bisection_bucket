# frozen_string_literal: true

module Ai
  module DuoWorkflow
    # Read-only view of how ready a group is to run Duo Agent Platform flows, backing
    # the readiness rows in the group GitLab Duo settings.
    class GroupReadiness
      include Concerns::RunnerCheck
      include Concerns::McpServers

      def initialize(group, user)
        @group = group
        @user = user
      end

      # Agents live on top-level groups and projects only, so a subgroup lists the top-level group's
      # inheritance agents (the ones that run in its projects) once that feature is on for the hierarchy.
      # ItemConsumersFinder#include_inherited? gates the project side only; remove both with the flag.
      def lists_mcp_servers?
        group.root? || Feature.enabled?(:ai_catalog_group_inherited_consumers, group.root_ancestor)
      end

      def mcp_server_names
        return unless lists_mcp_servers?

        super
      end

      private

      attr_reader :group, :user

      alias_method :container, :group

      # With runner restrictions on, only instance runners and the root group's own
      # runners can pass RunnerValidator, so scanning the rest of the hierarchy would
      # only fill the candidate window with rejects.
      def runner_scope
        return ::Ci::Runner.usable_from_scope(group) unless Feature.enabled?(:duo_runner_restrictions, group)

        ::Ci::Runner.from_union(
          [group.shared_runners, ::Ci::Runner.belonging_to_group(group.root_ancestor.id)],
          remove_duplicates: false
        )
      end

      def mcp_consumer_params
        { group_id: group.root_ancestor.id }
      end

      # The top-level group's direct agents run there only, so they are noise on a subgroup.
      def mcp_agent_consumers
        return super if group.root?

        super.inheritance
      end

      def mcp_block_namespace
        group
      end
    end
  end
end
