# frozen_string_literal: true

module EE
  module Gitlab
    module GithubImport
      module Importer
        module IssueImporter
          extend ::Gitlab::Utils::Override
          include ProvisioningSyncRepository

          private

          # The mapping shares the issue's transaction because ObjectImporter does not retry
          # a failed issue, so an issue committed without its mapping would stay unmapped.
          override :create_issue
          def create_issue
            repository = provisioning_sync_repository
            return super unless repository && issue.provider_id

            ::Issue.transaction do
              super.tap do |new_issue|
                ::Import::Sync::ExternalObject.record!(
                  repository: repository,
                  kind: :issue,
                  provider_object_xid: issue.provider_id,
                  local_record: new_issue,
                  provider_updated_at: issue.updated_at&.in_time_zone
                )
              end
            end
          end
        end
      end
    end
  end
end
