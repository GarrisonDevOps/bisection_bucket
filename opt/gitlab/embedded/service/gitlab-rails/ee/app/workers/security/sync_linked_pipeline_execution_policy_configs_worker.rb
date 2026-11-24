# frozen_string_literal: true

module Security
  class SyncLinkedPipelineExecutionPolicyConfigsWorker
    include ApplicationWorker

    data_consistency :sticky

    deduplicate :until_executing, including_scheduled: true
    idempotent!

    feature_category :security_policy_management

    def perform(project_id, _current_user_id, oldrev, newrev, ref)
      project = Project.find_by_id(project_id) || return

      modified_paths = modified_paths_by_push(project, oldrev, newrev, ref)
      return if modified_paths.blank?

      affected_policies = policies_affected_by_push(project, ref, modified_paths)
      analyze_affected_configs(project, affected_policies)
    end

    private

    def analyze_affected_configs(project, affected_policies)
      # The result is stored on the author's policy, so analyze as the author: it only reflects what they can read.
      # Policies sharing content and configuration are analyzed once.
      affected_policy_configs = affected_policies.group_by do |policy|
        [policy.content['content'], policy.security_orchestration_policy_configuration]
      end

      affected_policy_configs.each do |(content, configuration), policies|
        author = configuration.policy_last_updated_by
        next unless author&.active?

        Security::SyncPipelineExecutionPolicyMetadataWorker
          .perform_async(project.id, author.id, content, policies.map(&:id))
      end
    end

    def policies_affected_by_push(project, ref, modified_paths)
      links = Security::PipelineExecutionPolicyConfigLink.for_project(project).including_policies
      # `security_policy` can be nil if the policy was deleted between the link being
      # loaded and this worker executing; skip such orphaned links.
      links.filter_map(&:security_policy).select do |policy|
        policy_affected?(project, policy.pipeline_execution_ci_config, ref, modified_paths)
      end
    end

    def policy_affected?(project, policy_config, branch_name, modified_paths)
      policy_applies_to_branch?(project, policy_config, branch_name) &&
        policy_file_modified?(policy_config, modified_paths)
    end

    def policy_applies_to_branch?(project, policy_config, ref)
      branch_name = Gitlab::Git.ref_name(ref)
      policy_config_ref = policy_config['ref'].presence || project.default_branch
      branch_name == policy_config_ref
    end

    def policy_file_modified?(policy_config, modified_paths)
      modified_paths.include?(policy_config['file'])
    end

    def modified_paths_by_push(project, oldrev, newrev, ref)
      # If branch is added or removed, modified paths cannot be calculated. Return empty array in that case.
      push = ::Gitlab::Git::Push.new(project, oldrev, newrev, ref)
      push.branch_updated? ? push.modified_paths : []
    end
  end
end
