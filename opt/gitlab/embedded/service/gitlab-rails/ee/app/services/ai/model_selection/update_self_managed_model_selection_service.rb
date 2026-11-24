# frozen_string_literal: true

module Ai
  module ModelSelection
    class UpdateSelfManagedModelSelectionService
      def initialize(user, params, catalog: nil)
        @user = user
        @params = params
        @catalog = catalog
      end

      def execute
        if params[:provider] == "vendored"
          # Since feature_setting (Duo self-hosted) takes precedence when resolving which feature setting to use, we
          # must set ai_self_hosted_model_id to nil so that it is properly defined as vendored and should be handled
          # at the instance level model selection
          params[:ai_self_hosted_model_id] = nil
          service_result = upsert_instance_feature_setting
          return service_result if service_result.error?
        end

        upsert_feature_setting
      end

      private

      attr_reader :user, :params, :catalog

      def upsert_feature_setting
        feature_setting = ::Ai::FeatureSetting.find_or_initialize_by_feature(params[:feature])

        ::Ai::FeatureSettings::UpdateService.new(
          feature_setting, user, params.except(:offered_model_ref)
        ).execute
      end

      def upsert_instance_feature_setting
        ::Ai::ModelSelection::UpsertInstanceFeatureSettingService.new(
          user,
          params[:feature],
          params[:offered_model_ref],
          catalog: catalog
        ).execute
      end
    end
  end
end
