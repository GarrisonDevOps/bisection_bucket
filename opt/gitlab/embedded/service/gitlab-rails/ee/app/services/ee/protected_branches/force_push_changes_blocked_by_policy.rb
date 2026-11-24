# frozen_string_literal: true

module EE
  module ProtectedBranches # rubocop:disable Gitlab/BoundedContexts -- TODO: Namespacing
    module ForcePushChangesBlockedByPolicy
      class ForcePushCheck < BasePolicyCheck
        def violated?
          forbidden_params?(protected_branch) && blocked?(protected_branch)
        end

        private

        def forbidden_params?(protected_branch)
          alters_allow_force_push?(protected_branch) || alters_push_access_levels?(protected_branch)
        end

        def alters_allow_force_push?(protected_branch)
          return false unless params.key?(:allow_force_push)

          protected_branch.allow_force_push != params[:allow_force_push]
        end

        # Only a genuine change to the push access levels should be blocked, not
        # the mere presence of `push_access_levels_attributes`. Callers that are
        # not the branch-rules GraphQL mutation (the REST API and the settings
        # form) resubmit the full push-access state on every save, so a
        # merge-only edit still echoes the current push levels back unchanged;
        # blocking on presence alone would falsely reject that edit.
        #
        # We apply the incoming nested-attributes to the currently stored levels
        # and block only if the resulting set differs.
        def alters_push_access_levels?(protected_branch)
          attributes = params[:push_access_levels_attributes]
          return false if attributes.blank?

          current_levels = protected_branch.push_access_levels
          current_keys = current_levels.map { |level| stored_access_key(level) }.to_set

          current_keys != desired_access_keys(current_levels, attributes)
        end

        def desired_access_keys(current_levels, attributes)
          keys_by_id = current_levels.index_by(&:id).transform_values { |level| stored_access_key(level) }
          additions = []

          attributes.each do |attribute|
            id = read_attribute(attribute, :id)
            existing = id.present? && keys_by_id.key?(id.to_i)

            if destroy?(attribute)
              keys_by_id.delete(id.to_i) if existing
            elsif existing
              keys_by_id[id.to_i] = attribute_access_key(attribute)
            else
              additions << attribute_access_key(attribute)
            end
          end

          (keys_by_id.values + additions).to_set
        end

        def stored_access_key(level)
          case level.type
          when :user then [:user, level.user_id]
          when :group then [:group, level.group_id]
          when :deploy_key then [:deploy_key, level.deploy_key_id]
          else [:role, level.access_level]
          end
        end

        def attribute_access_key(attribute)
          return [:user, read_attribute(attribute, :user_id).to_i] if read_attribute(attribute, :user_id).present?
          return [:group, read_attribute(attribute, :group_id).to_i] if read_attribute(attribute, :group_id).present?

          if read_attribute(attribute, :deploy_key_id).present?
            return [:deploy_key, read_attribute(attribute, :deploy_key_id).to_i]
          end

          [:role, read_attribute(attribute, :access_level).to_i]
        end

        def destroy?(attribute)
          ::Gitlab::Utils.to_boolean(read_attribute(attribute, :_destroy), default: false)
        end

        # Attributes may arrive as a Hash (symbol or string keys) or as
        # ActionController::Parameters depending on the caller, so read both.
        def read_attribute(attribute, key)
          attribute[key] || attribute[key.to_s]
        end

        def violation_message
          _('This change is blocked by a security policy that prevents pushing ' \
            'and force pushing. Only changes to push access levels or the force ' \
            'push setting are blocked; other branch rule settings can still be updated.')
        end

        def blocked?(protected_branch)
          return false unless protected_branch.project_level?

          project = protected_branch.project
          return false unless policies_enforceable?(project)

          blocking_policies = project
            .security_policies
            .type_approval_policy
            .enabled
            .prevent_pushing_and_force_pushing
            .preload_approval_policy_rules

          blocking_policies = blocking_policies.without_warn_mode

          blocking_policies.any? { |policy| policy_rules_apply?(policy) }
        end
      end

      def execute(protected_branch, skip_authorization: false)
        ForcePushCheck.check!(protected_branch, params, current_user)

        super
      end
    end
  end
end
