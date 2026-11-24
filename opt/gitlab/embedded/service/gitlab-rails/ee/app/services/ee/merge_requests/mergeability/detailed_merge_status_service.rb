# frozen_string_literal: true

module EE
  module MergeRequests
    module Mergeability
      module DetailedMergeStatusService
        extend ::Gitlab::Utils::Override

        private

        override :check_params
        def check_params
          super.merge(skip_rebase_check: skip_rebase_check?)
        end

        def skip_rebase_check?
          ::MergeTrains::Train.project_using_ff?(merge_request.project)
        end
      end
    end
  end
end
