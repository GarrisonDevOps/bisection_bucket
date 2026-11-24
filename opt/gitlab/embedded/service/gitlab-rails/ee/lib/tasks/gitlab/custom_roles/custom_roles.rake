# frozen_string_literal: true

return if Rails.env.production?

namespace :gitlab do
  namespace :custom_roles do
    custom_roles_dir = Rails.root.join("doc/user/custom_roles")
    custom_roles_doc_file = Rails.root.join(custom_roles_dir, 'abilities.md')
    template_directory = 'tooling/custom_roles/docs/templates/'
    template_erb_file_path = Rails.root.join(template_directory, 'custom_abilities.md.erb')

    desc 'GitLab | Custom Roles | Compile custom abilities documentation'
    task compile_docs: :environment do
      require_relative './compile_docs_task'

      Tasks::Gitlab::CustomRoles::CompileDocsTask
        .new(custom_roles_dir, custom_roles_doc_file, template_erb_file_path).run
    end

    desc 'GitLab | Custom Roles | Check if custom abilities documentation is up to date'
    task check_docs: :environment do
      require_relative './check_docs_task'

      Tasks::Gitlab::CustomRoles::CheckDocsTask
        .new(custom_roles_dir, custom_roles_doc_file, template_erb_file_path).run
    end
  end
end
