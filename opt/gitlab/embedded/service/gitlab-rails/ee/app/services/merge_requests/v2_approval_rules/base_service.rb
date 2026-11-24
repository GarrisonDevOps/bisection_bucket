# frozen_string_literal: true

module MergeRequests
  module V2ApprovalRules
    class BaseService < ::BaseContainerService
      include Gitlab::Utils::StrongMemoize

      attr_reader :merge_request

      def initialize(merge_request, current_user, params = {})
        @merge_request = merge_request

        super(
          container: merge_request&.target_project,
          current_user: current_user,
          params: params
        )
      end

      def execute
        return error('Merge request is required') if merge_request.nil?
        return ServiceResponse.error(message: %w[Prohibited], reason: :access_denied) unless can_update_approvers?

        action
      end

      private

      def action
        raise Gitlab::AbstractMethodError
      end

      def error(message, **options)
        ServiceResponse.error(message: message, **options)
      end

      def success(payload = {})
        ServiceResponse.success(payload: payload)
      end

      def can_update_approvers?
        can?(current_user, :update_approvers, merge_request)
      end
    end
  end
end
