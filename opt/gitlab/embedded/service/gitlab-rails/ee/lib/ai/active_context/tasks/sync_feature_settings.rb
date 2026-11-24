# frozen_string_literal: true

module Ai
  module ActiveContext
    module Tasks
      class SyncFeatureSettings < ::ActiveContext::Task[1.0]
        include Gitlab::Loggable

        def required_params
          %w[collection metadata user_id]
        end

        def execute!
          unless user.present?
            log_sync_skipped
            return
          end

          service_result = Ai::ModelSelection::UpdateSelfManagedModelSelectionService.new(
            user,
            feature_setting_params
          ).execute

          raise TaskError, service_result.message if service_result.error?
        end

        private

        def user
          @user ||= User.find_by_id(params['user_id'])
        end

        def feature_setting
          Ai::ActiveContext::Embedding.mapped_feature_setting(params['collection'])
        end

        def metadata
          params['metadata']
        end

        def model_type
          metadata['model_type']
        end

        def model_ref
          metadata['model_ref']
        end

        def feature_setting_params
          if Ai::ActiveContext::Embedding.self_hosted?(model_type)
            {
              feature: feature_setting,
              provider: 'self_hosted',
              ai_self_hosted_model_id: model_ref.to_i
            }
          else
            {
              feature: feature_setting,
              provider: 'vendored',
              offered_model_ref: model_ref
            }
          end
        end

        def log_sync_skipped
          logger.info(build_structured_payload(
            message: 'Skipping feature settings sync',
            reason: 'user not found',
            user_id: params['user_id'],
            collection: params['collection']
          ))
        end

        def logger
          @logger ||= ::ActiveContext::Config.logger
        end
      end
    end
  end
end
