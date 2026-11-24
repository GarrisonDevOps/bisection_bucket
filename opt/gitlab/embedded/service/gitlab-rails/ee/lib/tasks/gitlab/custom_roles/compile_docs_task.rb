# frozen_string_literal: true

module Tasks
  module Gitlab
    module CustomRoles
      class CompileDocsTask
        def initialize(docs_dir, docs_path, template_erb_path)
          @custom_roles_dir = docs_dir
          @custom_roles_doc_file = docs_path
          @custom_roles_template = ERB.new(File.read(template_erb_path), trim_mode: '<>')
        end

        def run
          FileUtils.mkdir_p(@custom_roles_dir)
          File.write(@custom_roles_doc_file, @custom_roles_template.result)

          puts "Documentation compiled."
        end
      end
    end
  end
end
