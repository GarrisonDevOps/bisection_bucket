# frozen_string_literal: true

module Elastic
  class NamespaceUpdateWorker # rubocop:disable Scalability/IdempotentWorker
    include ApplicationWorker
    include Search::Worker
    prepend ::Geo::SkipSecondary

    data_consistency :sticky

    def perform(id)
      return unless Gitlab::CurrentSettings.elasticsearch_indexing?

      namespace = Namespace.find(id)
      update_users_through_membership(namespace)
      update_namespace_associations(namespace)
    end

    def update_users_through_membership(namespace)
      user_ids = case namespace.type
                 when 'Group'
                   group_and_descendants_user_ids(namespace)
                 when 'Project'
                   project_user_ids(namespace)
                 end

      return unless user_ids

      User.id_in(user_ids).find_in_batches do |batch_of_users|
        Elastic::ProcessBookkeepingService.track!(*batch_of_users)
      end
    end

    def update_namespace_associations(namespace)
      Elastic::ProcessBookkeepingService.maintain_indexed_namespace_associations!(namespace)
    end

    def group_and_descendants_user_ids(namespace)
      ::Gitlab::Database.allow_cross_joins_across_databases(url:
        "https://gitlab.com/gitlab-org/gitlab/-/issues/422405") do
        namespace.self_and_descendants.flat_map(&:user_ids)
      end
    end

    def project_user_ids(namespace)
      project = namespace.project
      project.user_ids
    end
  end
end
