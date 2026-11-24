# frozen_string_literal: true

module EE
  module Gitlab
    module UserAccess
      extend ::Gitlab::Utils::Override

      override :can_run_pipeline_on_branch?
      def can_run_pipeline_on_branch?(ref)
        result = super
        return result if result
        return false unless user
        return true if Ability.allowed?(user, :create_bot_pipeline, container)

        can_run_pipeline_on_synced_branch?(ref)
      end

      override :can_manage_pipeline_on_branch?
      def can_manage_pipeline_on_branch?(ref)
        result = super
        return result if result

        can_run_pipeline_on_synced_branch?(ref)
      end

      override :can_run_pipeline_on_tag?
      def can_run_pipeline_on_tag?(ref)
        result = super
        return result if result

        can_run_pipeline_on_synced_tag?(ref)
      end

      private

      # While GitHub updates are on, the project is read-only and the push and tag creation
      # abilities are prevented. Starting a pipeline does not change the repository, so it only
      # needs the pipeline permission plus the protected ref rules, as it would without sync.
      def can_run_pipeline_on_synced_branch?(ref)
        return false unless pipeline_allowed_on_synced_project?
        return true unless protected?(::ProtectedBranch, ref)

        # Same as #can_update_branch?: being able to push or merge is enough.
        %i[push merge].any? do |action|
          synced_protected_ref_accessible?(::ProtectedBranch, ref, action, project.all_protected_branches)
        end
      end

      def can_run_pipeline_on_synced_tag?(ref)
        return false unless pipeline_allowed_on_synced_project?
        return true unless protected?(::ProtectedTag, ref)

        synced_protected_ref_accessible?(::ProtectedTag, ref, :create, project.protected_tags)
      end

      def pipeline_allowed_on_synced_project?
        return false unless user && can_access_git?
        return false unless ::Import::Sync::Projects::WritePolicy.read_only?(container)

        Ability.allowed?(user, :create_pipeline, container)
      end

      # Role based access levels check `can?(:push_code)`, which sync prevents, so they would never
      # match. Evaluate them by role only. Other types (user, group, deploy key, custom role) do not
      # depend on that ability, so they keep using ProtectedRefAccess#check_access.
      def synced_protected_ref_accessible?(protected_ref_class, ref, action, protected_refs)
        protected_ref_class.access_levels_for_ref(ref, action: action, protected_refs: protected_refs)
          .any? { |access_level| synced_access_level_allows_user?(access_level) }
      end

      def synced_access_level_allows_user?(access_level)
        return access_level.check_access(user, project) unless access_level.role?

        case access_level.access_level
        when ::Gitlab::Access::NO_ACCESS then false
        when ::Gitlab::Access::ADMIN then user.can_admin_all_resources?
        else project.team.max_member_access(user.id) >= access_level.access_level
        end
      end
    end
  end
end
