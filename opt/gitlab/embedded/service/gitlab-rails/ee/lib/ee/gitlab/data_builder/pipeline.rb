# frozen_string_literal: true

module EE
  module Gitlab
    module DataBuilder
      module Pipeline
        extend ::Gitlab::Utils::Override

        override :merge_request_attrs
        def merge_request_attrs(merge_request)
          preload_merge_request_associations(merge_request)

          super
        end

        private

        def preload_merge_request_associations(merge_request)
          ActiveRecord::Associations::Preloader.new(
            records: [merge_request],
            associations: [
              :approvals,
              {
                applicable_post_merge_approval_rules: [
                  :approved_approvers,
                  :group_users,
                  :users
                ],
                approval_rules: [
                  :group_users,
                  :users
                ]
              },
              :scan_result_policy_reads_through_approval_rules
            ]
          ).call
        end
      end
    end
  end
end
