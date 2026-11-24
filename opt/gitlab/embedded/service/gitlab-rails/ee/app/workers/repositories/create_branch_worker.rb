# frozen_string_literal: true

module Repositories
  class CreateBranchWorker # rubocop:disable Scalability/IdempotentWorker -- orchestrated by JobWaiter
    include ApplicationWorker

    data_consistency :delayed
    feature_category :source_code_management
    urgency :low
    defer_on_database_health_signal :gitlab_main, []
    deduplicate :until_executed

    sidekiq_retries_exhausted do |msg|
      args = msg['args']
      jid = msg['jid']

      # notify_key is always at index 4, not args.last, because skip_ci may be
      # present as the 6th argument (index 5).
      #
      key = args[4]
      branch_name = args[2]

      add_error(key, branch_name, msg['error_message'].to_s)

      Gitlab::JobWaiter.notify(key, jid, ttl: Gitlab::Import::JOB_WAITER_TTL)
    end

    def self.add_error(key, branch_name, message)
      Repositories::CreateBranchesFinishWorker.add_error(key, branch_name, message)
    end

    def perform(project_id, user_id, branch_name, ref, notify_key, skip_ci = false)
      project = Project.find_by_id(project_id)
      user = User.find_by_id(user_id)

      unless project.present? && user.present?
        ::Gitlab::JobWaiter.notify(notify_key, jid, ttl: Gitlab::Import::JOB_WAITER_TTL)
        return
      end

      authentication_error_message = if !Ability.allowed?(user, :access_git)
                                       'The mirror user is not allowed to perform any git operations.'
                                     elsif !Ability.allowed?(user, :push_code_to_protected_branches, project)
                                       'The mirror user is not allowed to push code to all branches on this project.'
                                     end

      if authentication_error_message.present?
        self.class.add_error(notify_key, branch_name, authentication_error_message)
      else
        gitaly_context = { Projects::UpdateMirrorService::GITALY_CONTEXT_KEY => true }
        gitaly_context['skip-ci'] = true if skip_ci

        result = ::Gitlab::GitalyClient.with_context(**gitaly_context) do
          ::Branches::CreateService.new(project, user).execute(branch_name, ref)
        end

        self.class.add_error(notify_key, branch_name, result[:message]) if result[:status] == :error
      end

      ::Gitlab::JobWaiter.notify(notify_key, jid, ttl: Gitlab::Import::JOB_WAITER_TTL)
    end
  end
end
