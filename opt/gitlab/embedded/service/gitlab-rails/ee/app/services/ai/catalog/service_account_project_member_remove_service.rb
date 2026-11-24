# frozen_string_literal: true

module Ai
  module Catalog
    # Removes service account project memberships, keeping those an item consumer still needs.
    class ServiceAccountProjectMemberRemoveService
      MemberDeletionError = Class.new(StandardError)

      # @param memberships [ActiveRecord::Relation<ProjectMember>] service account project memberships
      # @param current_user [User] passed to Members::DestroyService
      # @param destroy_options [Hash] extra Members::DestroyService options
      def initialize(memberships, current_user:, **destroy_options)
        @memberships = memberships
        @current_user = current_user
        @destroy_options = destroy_options
      end

      def execute
        memberships.find_each do |member|
          next if ItemConsumer.service_account_needed_for_project?(member.user_id, member.source_id)

          ::Members::DestroyService.new(member, current_user: current_user, **destroy_options).execute

          next if member.destroyed?

          error = "Could not delete member: #{member.errors.full_messages.to_sentence}"

          ::Gitlab::ErrorTracking.track_and_raise_for_dev_exception(
            MemberDeletionError.new(error), { project_id: member.source_id, service_account_id: member.user_id }
          )
        end

        ServiceResponse.success
      end

      private

      attr_reader :memberships, :current_user, :destroy_options
    end
  end
end
