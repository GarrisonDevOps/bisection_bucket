# frozen_string_literal: true

module EE
  module ProjectStatistics
    extend ActiveSupport::Concern
    extend ::Gitlab::Utils::Override

    prepended do
      after_commit :notify_storage_usage, on: :update, if: -> { repository_storage_size_components_changed? }
    end

    REPOSITORY_STORAGE_SIZE_COMPONENTS = [
      :repository_size,
      :lfs_objects_size
    ].freeze

    def cost_factored_storage_size
      (storage_size * cost_factor).round
    end

    def cost_factored_repository_size
      (repository_size * cost_factor).round
    end

    def cost_factored_build_artifacts_size
      (build_artifacts_size * cost_factor).round
    end

    def cost_factored_lfs_objects_size
      (lfs_objects_size * cost_factor).round
    end

    def cost_factored_packages_size
      (packages_size * cost_factor).round
    end

    def cost_factored_snippets_size
      (snippets_size * cost_factor).round
    end

    def cost_factored_wiki_size
      (wiki_size * cost_factor).round
    end

    private

    def repository_storage_size_components_changed?
      (previous_changes.keys & REPOSITORY_STORAGE_SIZE_COMPONENTS.map(&:to_s)).any?
    end

    def notify_storage_usage
      ::Namespaces::Storage::RepositoryLimit::EmailNotificationService.execute(project)
    end

    def cost_factor
      ::Namespaces::Storage::CostFactor.cost_factor_for(project)
    end

    override :storage_size_components
    def storage_size_components
      if ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)
        self.class::STORAGE_SIZE_COMPONENTS - [:uploads_size]
      else
        super
      end
    end
  end
end
