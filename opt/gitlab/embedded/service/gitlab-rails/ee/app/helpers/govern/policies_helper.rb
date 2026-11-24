# frozen_string_literal: true

module Govern
  module PoliciesHelper
    # Caps the policy author's own text before it goes into a flash: `actions` has
    # no JSON schema or size limit yet (see Govern::Policy), so the message is
    # unbounded author-controlled input stored in the session.
    AUTHORED_MESSAGE_LIMIT = 500

    # The message a user sees when a settings policy refuses their change. It
    # names the enforcing policy and links to it, so the reason for the failed
    # save is one click away instead of a guess.
    #
    # `settings` is an array of setting names. `authored_message` is the policy
    # author's own block message alone, not a message that already carries the
    # attribution, which would print the policy name twice.
    def govern_settings_locked_message(policy, settings, authored_message: nil)
      attribution = safe_format(
        ns_(
          'PolicyStore|The setting %{settings} is locked by the policy %{link_start}%{name}%{link_end}.',
          'PolicyStore|The settings %{settings} are locked by the policy %{link_start}%{name}%{link_end}.',
          settings.size
        ),
        govern_policy_link_tags(policy),
        settings: settings.to_sentence,
        name: policy.name
      )

      # The author's own block message leads and the attribution follows it,
      # rather than replacing it, so a policy with a custom message still says
      # which policy it is.
      return attribution if authored_message.blank?

      safe_join([authored_message.to_s.truncate(AUTHORED_MESSAGE_LIMIT), attribution], ' ')
    end

    # Returns nil when the user cannot read the policy, so the name renders
    # unlinked rather than as a link into a 404.
    def govern_policy_store_path_for(policy)
      scope = govern_policy_scope(policy)
      return unless can?(current_user, :read_govern_policy, scope)

      if scope.is_a?(::Group)
        group_security_policy_store_path(scope, policy.id)
      else
        security_policy_store_policy_organization_path(scope, policy.id)
      end
    end

    private

    # A policy is owned by a group, or by its organization when it has no
    # namespace. There is no project-level policy store, so a refusal raised on
    # a project page always links up to the owner.
    def govern_policy_scope(policy)
      namespace = policy.namespace
      return namespace if namespace.is_a?(::Group)

      policy.organization
    end

    def govern_policy_link_tags(policy)
      path = govern_policy_store_path_for(policy)
      return { link_start: '', link_end: '' } unless path

      tag_pair(link_to('', path), :link_start, :link_end)
    end
  end
end
