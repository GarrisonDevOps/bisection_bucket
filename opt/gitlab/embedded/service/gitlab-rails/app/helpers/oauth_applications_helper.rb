# frozen_string_literal: true

module OauthApplicationsHelper
  # Returns the displayable scope string for a row in the Authorized
  # Applications table, which can be either an OauthAccessToken (#scopes
  # is a Doorkeeper::OAuth::Scopes) or an Authn::OauthConsent (#granted_scopes
  # is an Array).
  def authorized_record_scopes(record)
    return record.granted_scopes.join(' ') if record.respond_to?(:granted_scopes)

    record.scopes.to_s
  end

  def granular_scopes_for_display(scopes)
    scopes.sort_by do |scope|
      [Authz::GranularScope.accesses.fetch(scope.access), scope.namespace&.full_path.to_s]
    end
  end

  def granular_scope_access_text(scope)
    case scope.access.to_sym
    when Authz::GranularScope::Access::SELECTED_MEMBERSHIPS
      s_('AccessTokens|Only specific groups or projects I have access to')
    when Authz::GranularScope::Access::USER
      s_('AccessTokens|User permissions')
    else
      # A blank heading would hide what the scope reaches, so fail until the level has a label
      raise ArgumentError, "Unsupported granular scope access: #{scope.access}"
    end
  end

  def granular_scope_namespace_label(namespace)
    namespace.project_namespace? ? _('Project') : _('Group')
  end

  def granular_permission_description(name)
    Authz::PermissionGroups::Assignable.get(name)&.description
  end

  def oauth_application_granular_scopes_picker_data(owner, scope_inputs)
    return unless owner.is_a?(Group) && Feature.enabled?(:granular_oauth_tokens, current_user)

    {
      allowed_access_levels: allowed_access_levels_for_picker,
      group_full_path: owner.full_path,
      group_name: owner.name,
      initial_scopes: Gitlab::Json.dump(granular_scopes_for_picker(owner, scope_inputs))
    }
  end

  # Only a consent for an application on another cell carries one.
  def authorized_record_remote_application(record)
    record.remote_application if record.respond_to?(:remote_application)
  end

  def remote_oauth_application_description(application)
    return s_('AuthorizedApplication|Application details are temporarily unavailable.') if application.placeholder?

    oauth_application_added_description(
      owner_label: application.owner_label, created_at: application.created_at, dynamic: application.dynamic?
    )
  end

  # Shared with the IAM consent screen. IAM always sends created_at, but a
  # missing one must not take the whole page down.
  def oauth_application_added_description(owner_label:, created_at:, dynamic:)
    return if created_at.nil?

    created_date = time_ago_in_words(created_at)

    if dynamic
      safe_format(_('An anonymous service added this dynamically created OAuth application %{created_date} ago.'),
        created_date: created_date)
    elsif owner_label.present?
      safe_format(_('%{owner} added this OAuth application %{created_date} ago.'),
        owner: owner_label, created_date: created_date)
    else
      safe_format(_('An administrator added this OAuth application %{created_date} ago.'), created_date: created_date)
    end
  end

  private

  def granular_scopes_for_picker(group, inputs)
    Array(inputs).map do |input|
      namespaces = picker_namespaces(group.self_and_descendants, input[:group_ids], 'Group') +
        picker_namespaces(Project.in_namespace(group.self_and_descendant_ids), input[:project_ids], 'Project')

      { access: input[:access].to_s.upcase, permissions: Array(input[:permissions]), namespaces: namespaces }
    end
  end

  def allowed_access_levels_for_picker
    Gitlab::Json.dump(Authz::GranularScopes::GroupBoundaryRule::ALLOWED_ACCESS.map { |access| access.to_s.upcase })
  end

  # Posted IDs are untrusted: resolving one outside the owning group would expose its name and path
  def picker_namespaces(relation, ids, typename)
    return [] if ids.blank?

    relation.id_in(ids).with_route.map do |record|
      { id: record.to_global_id.to_s, __typename: typename, name: record.name, fullPath: record.full_path }
    end
  end
end
