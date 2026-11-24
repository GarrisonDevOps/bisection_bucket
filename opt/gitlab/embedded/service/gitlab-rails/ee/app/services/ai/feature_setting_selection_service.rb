# frozen_string_literal: true

module Ai
  class FeatureSettingSelectionService
    include ::Ai::ModelSelection::SelectionApplicable

    MISSING_DEFAULT_NAMESPACE = "missing_default_namespace"

    def initialize(current_user, feature, root_namespace)
      @current_user = current_user
      @feature = feature
      @root_namespace = root_namespace
    end

    def execute
      return success(payload: nil) if ::Ai::AmazonQ.connected?
      return select_for_saas if ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)

      select_for_self_managed
    end

    private

    attr_reader :current_user, :feature, :root_namespace

    def select_for_saas
      feature_setting = model_selection_namespace_setting

      return success(payload: feature_setting) if feature_setting
      return error_missing_default_namespace if default_duo_namespace_required?

      success(payload: nil)
    end

    def select_for_self_managed
      # First check if a self-hosted model is defined for the feature
      feature_setting = self_hosted_feature_setting

      return success(payload: feature_setting) if prefer_self_hosted_feature_setting?(feature_setting)

      return success(payload: nil) if suppress_default_vendored_setting?

      # Instance level is fetched either when we don't have a feature_setting, or when it is set to vendored
      success(payload: instance_level_setting)
    end

    # An offline (air-gapped) cloud license has no connection to the cloud-connected AI Gateway, so the
    # vendored GitLab-managed default model cannot be served. Every other license state keeps the instance
    # setting, which routes the default model to the cloud-connected AI Gateway - even on a hybrid instance
    # that also runs a self-hosted AI Gateway.
    def suppress_default_vendored_setting?
      !!::License.current&.offline_cloud_license?
    end

    def prefer_self_hosted_feature_setting?(feature_setting)
      feature_setting && !feature_setting.vendored?
    end

    def model_selection_namespace_setting
      namespace = model_selection_namespace

      return if namespace.nil?

      ::Ai::ModelSelection::NamespaceFeatureSetting.find_or_initialize_by_feature(namespace, feature)
    end

    def model_selection_namespace
      current_user.governing_namespace(root_namespace)
    end

    def instance_level_setting
      ::Ai::ModelSelection::InstanceModelSelectionFeatureSetting.find_or_initialize_by_feature(feature)
    end

    def self_hosted_feature_setting
      ::Ai::FeatureSetting.find_by_feature(feature)
    end

    def success(payload:)
      ServiceResponse.success(payload: payload)
    end

    def error_missing_default_namespace
      ServiceResponse.error(payload: nil, message: MISSING_DEFAULT_NAMESPACE)
    end
  end
end
