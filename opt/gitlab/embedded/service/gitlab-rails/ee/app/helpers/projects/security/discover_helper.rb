# frozen_string_literal: true

module Projects::Security::DiscoverHelper
  def project_security_discover_data(project)
    content = 'discover-project-security'
    link_upgrade = project.personal? ? profile_billings_path(project.group, source: content) : group_billings_path(project.root_ancestor, source: content)

    {
      project: {
        id: project.id,
        name: project.name,
        personal: project.personal?.to_s
      },
      link: {
        main: new_trial_registration_path(glm_source: 'gitlab.com', glm_content: content),
        secondary: link_upgrade
      }
    }
  end
end
