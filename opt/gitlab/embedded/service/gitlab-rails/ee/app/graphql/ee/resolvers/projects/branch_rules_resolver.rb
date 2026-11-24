# frozen_string_literal: true

module EE
  module Resolvers
    module Projects
      module BranchRulesResolver
        extend ActiveSupport::Concern
        extend ::Gitlab::Utils::Override
        include ::Gitlab::Utils::StrongMemoize

        prepended do
          argument :build_missing, GraphQL::Types::Boolean,
            required: false,
            default_value: false,
            replace_null_with_default: true,
            description: 'Return unpersisted custom branch rules.'
        end

        private

        def custom_branch_rules(args)
          super.tap do |rules|
            # Custom rules have different permission requirements to regular branch
            # rules. GraphQL's after_resolve logic silently filters out unauthorized
            # objects but pagination is built during resolution, so we pre-filter
            # here to keep page sizes correct.
            rules.append(all_protected_branches_rule) if include_all_protected_branches_rule?(args[:build_missing])
          end
        end

        def include_all_protected_branches_rule?(build_missing)
          return false unless Ability.allowed?(current_user, :read_branch_rule, all_protected_branches_rule)

          all_protected_branches_rule.persisted? || build_missing
        end

        def all_protected_branches_rule
          ::Projects::AllProtectedBranchesRule.new(project)
        end
        strong_memoize_attr :all_protected_branches_rule

        override :preloads
        def preloads
          super.merge(
            approval_rules: { approval_project_rules_with_unique_policies: [:users, :group_users] },
            external_status_checks: :external_status_checks,
            squash_option: :squash_option,
            [:branch_protection, :merge_access_levels] => access_levels_preloads_for(:merge),
            [:branch_protection, :push_access_levels] => access_levels_preloads_for(:push),
            [:branch_protection, :unprotect_access_levels] => access_levels_preloads_for(:unprotect)
          )
        end

        def access_levels_preloads_for(access_type)
          access_level_name = :"#{access_type}_access_levels"
          access_levels_lookahead = access_levels_node_selection(access_level_name)

          preloads = []
          preloads << { group: group_preloads(access_levels_lookahead) } if access_levels_lookahead.selects?(:group)
          preloads << { user: user_preloads(access_levels_lookahead) } if access_levels_lookahead.selects?(:user)
          preloads << :member_role if access_levels_lookahead.selects?(:member_role)

          { access_level_name => preloads }
        end

        def group_preloads(access_levels_lookahead)
          preloads = [:saml_provider, :route]
          return preloads unless access_levels_lookahead.selection(:group).selects?(:parent)

          preloads << { parent: preloads.dup }
        end

        def user_preloads(access_levels_lookahead)
          # groups and projects are accessed in HasUserType#redacted_name
          return [] unless access_levels_lookahead.selection(:user).selects?(:name)

          %i[groups projects]
        end

        def access_levels_node_selection(access_level_name)
          access_levels_selection = node_selection
            .selection(:branch_protection)
            .selection(access_level_name)

          node_selection(access_levels_selection)
        end
      end
    end
  end
end
