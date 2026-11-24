# frozen_string_literal: true

module SecretsHelper
  def project_secrets_app_data(project)
    root_namespace = project.root_ancestor

    {
      base_path: project_secrets_path(project),
      can_enable_add_on: can_enable_secrets_manager_add_on?(root_namespace).to_s,
      can_provision: can?(current_user, :provision_secrets_manager, project).to_s,
      can_start_trial: can_start_secrets_manager_trial?(root_namespace).to_s,
      enrollment_settings_path: enrollment_settings_path(root_namespace),
      is_offline_license: ::SecretsManagement::InstanceEnrollment.offline_license?.to_s,
      manage_permissions_path: edit_project_path(project, anchor: 'js-shared-permissions'),
      project_path: project.full_path,
      top_level_group_full_path: root_namespace.is_a?(Group) ? root_namespace.full_path : ''
    }
  end

  def group_secrets_app_data(group)
    root_namespace = group.root_ancestor

    {
      base_path: group_secrets_path(group),
      can_enable_add_on: can_enable_secrets_manager_add_on?(root_namespace).to_s,
      can_provision: can?(current_user, :provision_secrets_manager, group).to_s,
      can_start_trial: can_start_secrets_manager_trial?(root_namespace).to_s,
      enrollment_settings_path: enrollment_settings_path(root_namespace),
      group_path: group.full_path,
      is_offline_license: ::SecretsManagement::InstanceEnrollment.offline_license?.to_s,
      manage_permissions_path: group_manage_permissions_path(group),
      top_level_group_full_path: root_namespace.full_path
    }
  end

  def namespace_enrollment_data(namespace, user)
    {
      can_manage_secrets_manager: can?(user, :admin_group, namespace).to_s, # rubocop:disable Gitlab/Authz/PermissionCheck -- will iterate on this. provision_secrets_manager is a good fit but it needs to be fetched/updated dynamically on enrollment
      can_enroll_namespace: can?(user, :create_secrets_manager_enrollment, namespace).to_s,
      can_start_trial: can?(user, :start_secrets_manager_trial, namespace).to_s,
      full_path: namespace.full_path,
      is_namespace_enrollable: (namespace.root? && Gitlab.com?).to_s, # rubocop:disable Gitlab/AvoidGitlabInstanceChecks -- testing SaaS behavior directly (feature is also available for self-managed, but enrollment behavior is different)
      top_level_group_full_path: namespace.root_ancestor.full_path
    }
  end

  def secrets_manager_vulnerability_cta_data(project, report_type)
    return {} unless report_type == 'secret_detection'

    secrets_manager_cta_data(project)
  end

  # `entity` is a Project, a Group, or nil for the instance (admin area). An empty payload hides the card.
  def secrets_manager_variables_cta_data(entity)
    return {} unless current_user

    secrets_manager_cta_data(entity)
  end

  private

  # Shared by the CTAs. `entity` is a Project, a Group, or nil for the instance.
  def secrets_manager_cta_data(entity)
    root_namespace = entity&.root_ancestor
    # The instance ability is self-managed-only, the group ability is
    # SaaS-only, so together they cover both realms without a realm check.
    instance_trial = can?(current_user, :start_secrets_manager_trial)
    start_trial_path = secrets_manager_cta_start_trial_path(root_namespace, instance_trial)

    # Withhold Try when the trial ability has no actionable destination.
    can_start_trial = start_trial_path.present? &&
      (instance_trial || can_start_secrets_manager_trial?(root_namespace))

    # The destination page's own gate, so View never links to a 404. The instance has no secrets page.
    can_view_secrets =
      case entity
      when ::Project then can?(current_user, :read_project_secrets, entity)
      when ::Group then can?(current_user, :read_secret, entity)
      else ::SecretsManagement::Availability.for_instance?
      end

    # Empty payload hides the card. The request fallback asks an owner for
    # access, which is only honest while the feature is offered to the group.
    return {} unless can_view_secrets || can_start_trial ||
      secrets_manager_offered_to_group?(root_namespace)

    # The instance has no secrets page, so that card never has a button.
    secrets_path =
      case entity
      when ::Project then project_secrets_path(entity)
      when ::Group then group_secrets_path(entity)
      end

    {
      secrets_manager_available: can_view_secrets,
      can_start_trial: can_start_trial,
      secrets_path: secrets_path,
      start_trial_path: (start_trial_path if can_start_trial)
    }.compact
  end

  # Same ability as the SecretsManagerStartTrial mutation, so the button and
  # the mutation agree. Personal namespaces have no trial concept.
  def can_start_secrets_manager_trial?(root_namespace)
    return false unless root_namespace.is_a?(Group)

    can?(current_user, :start_secrets_manager_trial, root_namespace)
  end

  # Same ability as SecretsManagerEnableAddOn. On self-managed the add-on is
  # instance-wide (admin only), so this is false for every group there.
  def can_enable_secrets_manager_add_on?(root_namespace)
    return false unless root_namespace.is_a?(Group)

    can?(current_user, :enable_secrets_manager_add_on, root_namespace)
  end

  # Deliberately ignores enrollment and the user's abilities: an owner could
  # still enable the feature, which is what the request variant asks for.
  # Only unlicensed groups and personal namespaces are offered nothing.
  def secrets_manager_offered_to_group?(root_namespace)
    return false unless root_namespace.is_a?(Group)

    ::SecretsManagement::Availability.licensed?(root_namespace)
  end

  # Try lands on the trial surface: Admin settings for instance admins,
  # otherwise the group secrets page, except an opted-out group, where that
  # page 404s and re-enabling lives in Settings > Secure. No path, no Try.
  def secrets_manager_cta_start_trial_path(root_namespace, instance_trial)
    return instance_enrollment_settings_path if instance_trial
    return unless root_namespace.is_a?(Group)

    if ::SecretsManagement::Availability.for_group?(root_namespace)
      group_secrets_path(root_namespace)
    elsif ::SecretsManagement::Availability.licensed?(root_namespace) &&
        ::SecretsManagement::NamespaceEnrollment.opted_out?(root_namespace)
      group_settings_secure_path(root_namespace, anchor: 'js-secrets-manager-settings')
    end
  end

  def instance_enrollment_settings_path
    general_admin_application_settings_path(anchor: 'js-secrets-manager-instance-enrollment-settings')
  end

  def enrollment_settings_path(root_group)
    if allow_secrets_manager_instance_enrollment?
      instance_enrollment_settings_path
    else
      # The top-level group's Secrets Manager settings live under the Secure tab.
      group_settings_secure_path(root_group, anchor: 'js-secrets-manager-settings')
    end
  end

  # Subgroups keep their Secrets Manager settings under General; only the
  # top-level group moves to the Secure tab.
  def group_manage_permissions_path(group)
    if group.root?
      group_settings_secure_path(group, anchor: 'js-secrets-manager-settings')
    else
      edit_group_path(group, anchor: 'js-permissions-settings')
    end
  end
end
