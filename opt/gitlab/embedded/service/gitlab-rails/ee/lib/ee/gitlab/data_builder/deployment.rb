# frozen_string_literal: true

module EE
  module Gitlab
    module DataBuilder
      module Deployment
        extend ::Gitlab::Utils::Override

        override :build
        def build(deployment, status, status_changed_at, approval: nil, approver: nil, **kwargs)
          payload = super(deployment, status, status_changed_at, **kwargs)

          payload[:approver] = approver.hook_attrs if approver
          payload[:approval] = approval.hook_attrs if approval

          payload
        end
      end
    end
  end
end
