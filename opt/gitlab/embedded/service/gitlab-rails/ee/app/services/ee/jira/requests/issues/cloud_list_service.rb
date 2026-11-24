# frozen_string_literal: true

# rubocop:disable Gitlab/BoundedContexts -- Parent class CloudListService already excluded
module EE
  module Jira
    module Requests
      module Issues
        module CloudListService
          extend ::Gitlab::Utils::Override

          override :initialize
          def initialize(jira_integration, params = {})
            super

            @reconcile_issue_ids = params[:reconcile_issue_ids]
          end

          private

          attr_reader :reconcile_issue_ids

          def reconcile_params
            reconcile_issue_ids.map { |id| "&reconcileIssues=#{id}" }.join
          end

          override :url
          def url
            reconcile_issue_ids.present? ? super + reconcile_params : super
          end
        end
      end
    end
  end
end
# rubocop:enable Gitlab/BoundedContexts
