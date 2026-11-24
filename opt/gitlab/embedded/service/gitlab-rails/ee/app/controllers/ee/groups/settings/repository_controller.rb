# frozen_string_literal: true

module EE
  module Groups
    module Settings
      module RepositoryController
        extend ::Gitlab::Utils::Override
        extend ActiveSupport::Concern

        prepended do
          before_action :define_push_rule_variable, if: -> { can?(current_user, :change_push_rules, group) }
          before_action :define_protected_branches, only: [:show]
        end

        private

        override :authorize_access!
        def authorize_access!
          render_404 unless can?(current_user, :admin_group, group) || can?(current_user, :change_push_rules, group) ||
            can?(current_user, :manage_deploy_tokens, group)
        end

        def define_push_rule_variable
          strong_memoize(:push_rule) do
            GroupPushRuleFinder.new(group).execute || GroupPushRule.build_from_predefined(group)
          end
        end

        # rubocop:disable CodeReuse/ActiveRecord
        def define_protected_branches
          @protected_branches = group.protected_branches.order(:name).page(pagination_params[:page])
          @protected_branch = group.protected_branches.new
          gon.push(helpers.protected_access_levels_for_dropdowns)
          gon.push(current_group_id: group.id)
          gon.push(custom_roles_licensed: group.licensed_feature_available?(:custom_roles))

          protected_from_deletion =
            ::Security::SecurityOrchestrationPolicies::GroupProtectedBranchesDeletionCheckService
              .new(group: group, current_user: current_user)
              .execute

          return unless protected_from_deletion

          @protected_branches.each do |protected_branch|
            protected_branch.protected_from_deletion = true
          end
        end
        # rubocop:enable CodeReuse/ActiveRecord
      end
    end
  end
end
