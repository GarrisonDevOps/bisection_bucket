# frozen_string_literal: true

module Tasks
  module Gitlab
    module CustomRoles
      class CheckDocsTask
        def initialize(docs_dir, docs_path, template_erb_path)
          @custom_roles_dir = docs_dir
          @custom_roles_doc_file = docs_path
          @custom_roles_erb_template = ERB.new(File.read(template_erb_path), trim_mode: '<>')
        end

        def run
          doc = File.read(@custom_roles_doc_file)

          if doc == @custom_roles_erb_template.result
            puts "Custom roles documentation is up to date."
          else
            error_message = "Custom roles documentation is outdated! Please update it by running " \
                            "`bundle exec rake gitlab:custom_roles:compile_docs`."
            heading = '#' * 10
            puts heading
            puts '#'
            puts "# #{error_message}"
            puts '#'
            puts heading

            abort
          end
        end
      end
    end
  end
end
