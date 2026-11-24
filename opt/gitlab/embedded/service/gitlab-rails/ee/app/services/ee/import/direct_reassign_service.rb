# frozen_string_literal: true

module EE
  module Import
    module DirectReassignService
      extend ActiveSupport::Concern

      EE_MODEL_LIST = {
        "ApprovalProjectRulesUser" => ["user_id"],
        "BoardAssignee" => ["assignee_id"],
        "ProtectedBranch::UnprotectAccessLevel" => ["user_id"],
        "ProtectedEnvironments::DeployAccessLevel" => ["user_id"],
        "ResourceIterationEvent" => ["user_id"]
      }.freeze

      class_methods do
        extend ::Gitlab::Utils::Override

        override :model_list
        def model_list
          super.merge(EE_MODEL_LIST)
        end
      end

      private

      # Vulnerability class currently enforced a DB trigger feature flag. This handling will be removed
      # with the feature flag turn_off_vulnerability_read_create_db_trigger_function
      #
      # There is no need to do anything else as the columns being reassigned are not denormalized
      # to vulnerability_reads
      def transaction(model_class, contributions)
        if model_class == ::Vulnerability
          projects = if contributions.is_a?(Vulnerability)
                       [contributions.project]
                     else
                       ::Project.by_ids(contributions.pluck_distinct_project_ids)
                     end

          model_class.feature_flagged_transaction_for(projects) do
            yield
          end
        else
          model_class.transaction do
            yield
          end
        end
      end
    end
  end
end
