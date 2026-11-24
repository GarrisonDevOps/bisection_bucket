# frozen_string_literal: true

module EE
  module MirrorHelper
    extend ::Gitlab::Utils::Override

    override :mirrors_form_data_attributes
    def mirrors_form_data_attributes
      super.merge(mirror_only_branches_match_regex_enabled: @project.licensed_feature_available?(:repository_mirrors))
    end

    override :repository_mirrors_available?
    def repository_mirrors_available?
      @project.licensed_feature_available?(:repository_mirrors)
    end

    override :mirror_settings_unavailable_message
    def mirror_settings_unavailable_message
      return super unless ::Import::Sync::Projects::WritePolicy.read_only?(@project)

      s_("GithubUpdatesReadOnly|Mirroring isn't available while GitHub updates are on.")
    end

    def mirror_update_state(project)
      return :read_only if project.repository_read_only?

      project.import_state.last_update_status
    end

    def render_mirror_failed_message(raw_message:)
      mirror_last_update_at = @project.import_state.last_update_at
      message = "Pull mirroring failed #{time_ago_with_tooltip(mirror_last_update_at)}.".html_safe

      return message if raw_message

      message = sprite_icon('warning-solid') + ' ' + message

      if can?(current_user, :admin_project, @project)
        link_to message, project_mirror_path(@project)
      else
        message
      end
    end

    def branch_diverged_tooltip_message
      message = [s_('Branches|The branch could not be updated automatically because it has diverged from its upstream counterpart.')]

      if can?(current_user, :push_code, @project)
        message << '<br>'
        message << s_("Branches|To discard the local changes and overwrite the branch with the upstream version, delete it here and choose 'Update now' above.")
      end

      message.join
    end

    def mirror_branches_text(record)
      case record.mirror_branches_setting
      when 'all'
        _('All branches')
      when 'protected'
        _('All protected branches')
      when 'regex'
        _('Specific branches')
      end
    end

    override :pull_mirror_table_data
    def pull_mirror_table_data(project)
      return unless project.mirror?

      import_state = project.import_state
      return unless import_state

      import_data = project.import_data

      update_status = if import_state.mirror_update_due? || import_state.updating_mirror?
                        'started'
                      else
                        import_state.status
                      end

      row = serialize_mirror_row(
        id: import_state.id,
        enabled: true,
        url: project.safe_import_url,
        direction: ::MirrorHelper::PULL_DIRECTION,
        last_update_started_at: import_state.last_update_started_at,
        last_update_at: import_state.last_successful_update_at,
        last_error: import_state.last_error,
        update_status: update_status,
        ssh_key_auth: import_data&.ssh_key_auth? || false,
        ssh_public_key: import_data&.ssh_public_key,
        archived: project.self_or_ancestors_archived?
      ).merge(
        mirror_branches_setting: project.mirror_branches_setting,
        mirror_branch_regex: project.mirror_branch_regex
      )

      ::Gitlab::Json.dump(row)
    end

    private

    # EE override: adds mirror branch configuration keys
    # to push mirror rows. In EE, RemoteMirror includes
    # MirrorConfiguration which provides these methods.
    override :serialize_remote_mirror_row
    def serialize_remote_mirror_row(mirror)
      super.merge(
        mirror_branches_setting: mirror.mirror_branches_setting,
        mirror_branch_regex: mirror.mirror_branch_regex
      )
    end
  end
end
