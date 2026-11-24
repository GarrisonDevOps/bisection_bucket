# frozen_string_literal: true

module EE
  module Gitlab
    module Ci
      module Status
        module Build
          module WaitingForApproval
            extend ActiveSupport::Concern

            prepended do
              prepend EE::Gitlab::Ci::Status::WaitingForApproval # rubocop: disable Cop/InjectEnterpriseEditionModule
            end
          end
        end
      end
    end
  end
end
