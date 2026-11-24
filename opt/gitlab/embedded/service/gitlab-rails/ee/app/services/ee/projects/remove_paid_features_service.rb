# frozen_string_literal: true

module EE
  module Projects
    class RemovePaidFeaturesService < BaseService
      include EachBatch

      BATCH_SIZE = 500

      def execute(new_namespace)
        @new_namespace = new_namespace

        revoke_project_access_tokens
        delete_pipeline_subscriptions
        delete_test_cases
      end

      private

      attr_reader :new_namespace

      def revoke_project_access_tokens
        return if new_namespace&.feature_available_non_trial?(:resource_access_token)

        ::PersonalAccessTokensFinder
          .new(user: project.bots, impersonation: false)
          .execute
          .each_batch(of: BATCH_SIZE) do |personal_access_token_batch|
            personal_access_token_batch.update_all(revoked: true)
          end
      end

      def delete_pipeline_subscriptions
        return if new_namespace&.licensed_feature_available?(:ci_project_subscriptions)

        ::Ci::UpstreamProjectsSubscriptionsCleanupWorker.perform_async(project.id)
      end

      def delete_test_cases
        return if new_namespace&.licensed_feature_available?(:quality_management)

        loop do
          delete_count = project
            .issues
            .with_issue_type(:test_case)
            .limit(BATCH_SIZE)
            .delete_all

          break if delete_count == 0
        end
      end
    end
  end
end
