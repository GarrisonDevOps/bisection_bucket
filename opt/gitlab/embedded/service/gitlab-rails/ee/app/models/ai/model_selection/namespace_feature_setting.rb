# frozen_string_literal: true

module Ai
  module ModelSelection
    class NamespaceFeatureSetting < ApplicationRecord
      include ::Ai::ModelSelection::FeaturesConfigurable
      include ::Ai::ModelSelection::ModelAllowlist
      include CascadingNamespaceSettingAttribute

      LEVEL_EXCLUDED_FEATURES = {
        # glab_ask_git_command context does not have a namespace
        # For more context see https://gitlab.com/groups/gitlab-org/-/epics/17570#note_2487671188
        glab_ask_git_command: 13,
        # embeddings_code for Semantic Code Search cannot be configured on the namespace level
        embeddings_code: 22
      }.freeze

      self.table_name = "ai_namespace_feature_settings"

      belongs_to :namespace, class_name: '::Group', inverse_of: :ai_feature_settings

      validates :feature, uniqueness: { scope: :namespace_id }

      validate :validate_root_namespace

      scope :for_namespace, ->(namespace_id) { where(namespace_id: namespace_id) }

      def self.find_or_initialize_by_feature(namespace, feature)
        return unless ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)
        return unless namespace.present?
        return unless namespace.root?

        feature_name = get_feature_name(feature)
        find_or_initialize_by(namespace_id: namespace.id, feature: feature_name)
      end

      def self.with_non_default_code_completions(namespace_ids)
        for_namespace(namespace_ids)
          .non_default
          .where(feature: :code_completions)
      end

      def self.any_non_default_for_duo_chat?(namespace_id)
        for_namespace(namespace_id).non_default.where(feature: DUO_CHAT_FEATURES).exists?
      end

      def build_with_offered_model_ref(offered_model_ref)
        self.class.build(namespace: namespace, feature: feature, offered_model_ref: offered_model_ref)
      end

      private

      def validate_root_namespace
        return if namespace&.root?

        errors.add(:namespace,
          'Model selection is only available for top-level namespaces.')
      end
    end
  end
end
