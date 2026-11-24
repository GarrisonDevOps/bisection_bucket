# frozen_string_literal: true

module DuoChatPanel
  class Container
    include ::Gitlab::Utils::StrongMemoize

    attr_reader :source

    def initialize(project:, group:, user:, controller_name: nil)
      @project = project
      @group = group
      @user = user
      @controller_name = controller_name
      @source = project || group
    end

    def record
      duo_scope[:project] || duo_scope[:namespace]
    end

    def type
      duo_scope[:project] ? 'project' : 'group'
    end

    def project?
      type == 'project'
    end

    def persisted?
      !!record&.persisted?
    end

    def to_global_id
      record&.to_global_id
    end

    def root_ancestor
      record&.root_ancestor
    end

    def duo_features_enabled
      record&.duo_features_enabled
    end

    def admin_permission
      project? ? :admin_project : :admin_group
    end

    def user_can_admin?(user)
      Ability.allowed?(user, admin_permission, record)
    end

    def duo_settings_path
      if project?
        ::Gitlab::Routing.url_helpers.edit_project_path(record, anchor: 'js-gitlab-duo-settings')
      else
        record.duo_settings_path
      end
    end

    # Only offer settings for a container the current page is actually scoped to. A record
    # that fell back to the user's default Duo namespace would link somewhere unrelated.
    def admin_duo_settings_path(user)
      return if default_namespace_applied?
      return unless persisted? && user_can_admin?(user)
      return unless project? || record.is_a?(Group)

      duo_settings_path
    end

    def project_id
      to_global_id.to_s if project? && persisted?
    end

    def namespace_id
      to_global_id.to_s if !project? && persisted?
    end

    def project_path
      record.full_path if project? && persisted?
    end

    def project
      record if project? && persisted?
    end

    def group
      record if !project? && persisted?
    end

    def root_namespace_id
      root_ancestor.to_global_id.to_s if persisted?
    end

    def default_namespace_applied?
      duo_scope[:default_namespace_applied]
    end

    private

    def duo_scope
      ::Gitlab::Llm::DuoChat.duo_scope_hash(@user, @project, @group, @controller_name)
    end
    strong_memoize_attr :duo_scope
  end
end
