# frozen_string_literal: true

module EE
  module Deployments # rubocop:disable Gitlab/BoundedContexts -- existing Deployments workers are not bounded
    module HooksWorker
      extend ::Gitlab::Utils::Override

      private

      override :hook_kwargs
      def hook_kwargs(params)
        kwargs = {}

        approval = ::Deployments::Approval.find_by_id(params[:approval_id]) if params[:approval_id]
        kwargs[:approval] = approval if approval

        approver = ::User.find_by_id(params[:approver_id]) if params[:approver_id]
        kwargs[:approver] = approver if approver

        kwargs
      end
    end
  end
end
