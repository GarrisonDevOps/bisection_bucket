# frozen_string_literal: true

module Gitlab
  module Usage
    module Metrics
      module Instrumentations
        class OrphanedNamespacesMetric < GenericMetric
          # Detects legacy self-managed data. GitLab.com's orphans were deleted and the NOT VALID parent_id FK
          # blocks new ones (validation: https://gitlab.com/gitlab-org/gitlab/-/work_items/515806).
          # The anti-join times out there: https://gitlab.com/gitlab-org/gitlab/-/work_items/638182
          available? { !Gitlab.com? } # rubocop:disable Gitlab/AvoidGitlabInstanceChecks -- About GitLab.com's data, not a SaaS feature

          value do
            ::Namespace
              .where.not(parent_id: nil)
              .where('NOT EXISTS(SELECT 1 FROM namespaces p WHERE p.id = namespaces.parent_id)')
              .exists?
          end
        end
      end
    end
  end
end
