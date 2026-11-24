# frozen_string_literal: true

# @params target [MergeRequest, Project]
# @params params [Hash] for updating or creating target
# @params user [User] current user
#
# Returns a copy of `params` with rules modified,
# filtering rule users and groups based on accessibility from user
module ApprovalRules
  class ParamsFilteringService
    include Gitlab::Utils::StrongMemoize
    include ::ApprovalRules::OrganizationIsolationFilter

    attr_reader :target, :params, :current_user, :rules, :visible_group_ids, :visible_user_ids

    def initialize(target, user, params)
      @target = target
      @current_user = user
      @params = params.to_h.with_indifferent_access

      batch_load_visible_user_and_group_ids
    end

    def execute
      params.delete(:approval_rules_attributes) unless Ability.allowed?(current_user, :update_approvers, target)

      filter_non_user_defined_rules if updating?

      params.delete(:reset_approval_rules_to_defaults) unless updating?

      return params unless params.key?(:approval_rules_attributes)

      source_rule_ids = []

      params[:approval_rules_attributes].each do |rule_attributes|
        source_rule_ids << rule_attributes[:approval_project_rule_id].presence
        handle_rule(rule_attributes)
      end

      append_user_defined_inapplicable_rules(source_rule_ids.compact)

      params
    end

    private

    ## Revisit this when v2_approval_rules are ready,
    ## We might need to explicitly filter out non_user_defined rules
    ## under the :v2_approval_rules_attributes key
    ## TODO: https://gitlab.com/gitlab-org/gitlab/-/issues/558236
    def filter_non_user_defined_rules
      return if params[:approval_rules_attributes].blank?

      non_user_defined_ids = target.approval_rules.reject(&:user_defined?).map(&:id)
      return if non_user_defined_ids.blank?

      params[:approval_rules_attributes].reject! do |param|
        non_user_defined_ids.include?(param[:id].to_i)
      end
    end

    def handle_rule(rule_attributes)
      if rule_attributes.key?(:group_ids)
        provided_group_ids = rule_attributes[:group_ids].map(&:to_i)
        rule_attributes[:group_ids] = provided_group_ids & visible_group_ids

        append_hidden_groups(rule_attributes)
      end

      if rule_attributes.key?(:user_ids)
        provided_user_ids = rule_attributes[:user_ids].map(&:to_i)
        rule_attributes[:user_ids] = provided_user_ids & visible_user_ids
      end

      if rule_attributes[:group_ids].blank? && rule_attributes[:user_ids].blank? && rule_attributes[:name].blank?
        rule_attributes[:rule_type] = :any_approver
        rule_attributes[:name] = ApprovalRuleLike::ALL_MEMBERS
      end
    end

    # Append hidden groups to params to prevent them from being removed,
    # as hidden group ids are never passed to/back from clients for security reasons.
    def append_hidden_groups(rule_attributes)
      keep_hidden_groups = !Gitlab::Utils.to_boolean(rule_attributes.delete(:remove_hidden_groups))

      return unless keep_hidden_groups
      return unless rule_attributes.key?(:group_ids)

      hidden_group_sourcing_rule = find_hidden_group_sourcing_rule(rule_attributes)

      return unless hidden_group_sourcing_rule

      rule_attributes[:group_ids].concat(
        ::ApprovalRules::GroupFinder.new(hidden_group_sourcing_rule, current_user).hidden_groups.map(&:id)
      )
    end

    # Allow ruby-level filtering with only 2 queries
    def batch_load_visible_user_and_group_ids
      return unless params.key?(:approval_rules_attributes)

      # rubocop: disable CodeReuse/ActiveRecord
      @visible_group_ids = params[:approval_rules_attributes].flat_map { |hash| hash[:group_ids] }

      if @visible_group_ids.present?
        org = ::Organizations::Organization.find_by_id_with_isolation_record(project.organization_id)
        groups = filter_cross_organization_groups(::Group.id_in(@visible_group_ids), organization: org)
        @visible_group_ids = groups.accessible_to_user(current_user).pluck(:id)
      end

      @visible_user_ids = params[:approval_rules_attributes].flat_map { |hash| hash[:user_ids] }
      if @visible_user_ids.present?
        @visible_user_ids = project.members_among(::User.id_in(@visible_user_ids)).pluck(:id)
      end
      # rubocop: enable CodeReuse/ActiveRecord
    end

    def project
      if target.is_a?(Project)
        target
      else
        target.target_project
      end
    end

    def updating?
      strong_memoize(:updating) { @target.persisted? }
    end

    def find_hidden_group_sourcing_rule(rule_attributes)
      rule_id = updating? ? rule_attributes[:id] : rule_attributes[:approval_project_rule_id]

      return if rule_id.blank?

      hidden_group_sourcing_rules[rule_id.to_i]
    end

    def hidden_group_sourcing_rules
      strong_memoize(:hidden_group_sourcing_rules) do
        source = updating? ? target : project
        source.approval_rules.includes(:groups).index_by(&:id) # rubocop: disable CodeReuse/ActiveRecord
      end
    end

    # Append inapplicable rules on create or reset so they're still associated
    # to the MR and will be available when the MR's target branch changes.
    #
    # Inapplicable rules are approval rules scoped to protected branches that
    # does not match the specified `target_branch`.
    #
    # For example, there are 2 rules, one scoped to `master`, one scoped to `dev`.
    # The MR's `target_branch` is set to `dev`, so the rule for `master` is
    # inapplicable. But in case the MR's `target_branch` changes to `master`, the
    # `master` rule should be available.
    def append_user_defined_inapplicable_rules(source_rule_ids)
      return if updating? && !params[:reset_approval_rules_to_defaults]
      return unless project.multiple_approval_rules_available?

      project
        .visible_user_defined_inapplicable_rules(params[:target_branch])
        .each do |rule|
          # Check if rule is already set as a source rule in one of the rules
          # from params to prevent duplicates
          next if source_rule_ids.include?(rule.id)

          params[:approval_rules_attributes] << rule.to_nested_attributes
        end
    end
  end
end
