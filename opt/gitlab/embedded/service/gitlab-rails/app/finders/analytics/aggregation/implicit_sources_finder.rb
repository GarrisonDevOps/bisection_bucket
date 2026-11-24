# frozen_string_literal: true

# Finds the top-level groups of an organization that an aggregation engine
# aggregates when no sources are requested.
#
# Arguments:
#   current_user - which user is requesting groups
#   params:
#     organization: Organizations::Organization (required)
#     with_duo_agent_platform_enabled: boolean (EE) - skips top-level groups that turned Duo Agent Platform off
module Analytics
  module Aggregation
    class ImplicitSourcesFinder
      def initialize(current_user, params = {})
        @current_user = current_user
        @params = params
      end

      def execute
        return ::Group.none unless current_user

        groups = ::Group.from_union([direct_groups, shared_groups])
          .in_organization(params.fetch(:organization))
          .top_level
          .not_deletion_in_progress

        filter_groups(groups).order_id_desc
      end

      private

      attr_reader :current_user, :params

      def direct_groups
        current_user.groups
      end

      def shared_groups
        links = ::GroupGroupLink.for_shared_with_groups(direct_groups.select(:id))

        ::Group.id_in(links.select(:shared_group_id))
      end

      def filter_groups(groups)
        groups
      end
    end
  end
end

Analytics::Aggregation::ImplicitSourcesFinder.prepend_mod
