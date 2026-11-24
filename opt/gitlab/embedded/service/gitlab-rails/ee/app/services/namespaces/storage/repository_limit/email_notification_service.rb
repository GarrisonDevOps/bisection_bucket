# frozen_string_literal: true

module Namespaces
  module Storage
    module RepositoryLimit
      class EmailNotificationService
        include Gitlab::Utils::StrongMemoize

        def self.execute(project)
          new(project).execute
        end

        def initialize(project)
          @project = project
          @root_ancestor = project.root_ancestor
        end

        def execute
          return if ::Namespaces::Storage::NamespaceLimit::Enforcement.enforce_limit?(root_ancestor)
          return unless root_ancestor.root_storage_size.subject_to_high_limit?

          if notification_level == :error
            RepositoryLimitMailer.notify_out_of_storage(
              project_name: project.name,
              recipients: root_ancestor.owners_emails
            ).deliver_later
          elsif notification_level == :warning
            RepositoryLimitMailer.notify_limit_warning(
              project_name: project.name,
              recipients: root_ancestor.owners_emails
            ).deliver_later
          end
        end

        private

        attr_reader :project, :root_ancestor

        def notification_level
          if purchased_storage_usage_ratio == 0 || purchased_storage_usage_ratio >= 1
            case included_storage_usage_ratio
            when 0...0.9 then :none
            when 0.9...1 then :warning
            when 1..Float::INFINITY then :error
            end
          elsif purchased_storage_usage_ratio >= 0.9
            included_storage_usage_ratio >= 1 ? :warning : :none
          else
            :none
          end
        end

        def storage_usage_towards_limit
          project.statistics.repository_size + project.statistics.lfs_objects_size
        end

        def included_storage_usage_ratio
          limit = root_ancestor.actual_size_limit

          return 0 if limit == 0

          BigDecimal(storage_usage_towards_limit) / BigDecimal(limit)
        end
        strong_memoize_attr :included_storage_usage_ratio

        def purchased_storage_usage_ratio
          purchased_storage_available = root_ancestor.additional_purchased_storage_size.megabytes
          purchased_storage_used = root_ancestor.total_repository_size_excess

          return 0 if purchased_storage_available == 0

          BigDecimal(purchased_storage_used) / BigDecimal(purchased_storage_available)
        end
        strong_memoize_attr :purchased_storage_usage_ratio
      end
    end
  end
end
