# frozen_string_literal: true

module Gitlab
  module Duo
    module Developments
      class SetupGroupsForModelEvaluation
        STRUCTURE = {
          'gitlab_com' => { projects: ['www-gitlab-com'], name: 'gitlab-com' },
          'gitlab_org' => { projects: ['gitlab'], name: 'gitlab-org' }
        }.freeze
        DOWNLOAD_FOLDER = 'tmp'
        SAMPLES_FOLDER = 'duo_chat_samples'
        GROUP_FILE_NAME = '01_group.tar.gz'
        FILE_NAME = 'duo_chat_samples.tar.gz'
        DOWNLOAD_URL = 'https://gitlab.com/gitlab-org/ai-powered/datasets/-/package_files/135727282/download'
        GROUP_IMPORT_URL = '/api/v4/groups/import'
        PROJECT_IMPORT_URL = '/api/v4/projects/import'
        TIME_LIMIT = 360

        def initialize(args)
          @main_group = ensure_group(args[:root_group_path])
          @current_user = User.find_by(username: 'root') # rubocop:disable CodeReuse/ActiveRecord -- we need admin user
          @errors = []
          @project_ids = []
        end

        def execute
          ensure_dev_mode!
          set_token!
          ensure_server_running!
          ensure_instance_setting!
          download_and_unpack_file
          create_subgroups
          create_subprojects
          check_import_status
          delete_temporary_directory!
          clean_up_token!

          print_output
        end

        private

        attr_reader :main_group, :current_user, :token_value, :token
        attr_accessor :errors, :project_ids

        def ensure_group(namespace)
          puts "Checking the specified group exists...."

          raise "You must specify :root_group_path" if namespace.blank?
          raise "Provided group name must be a root group" if namespace.include?('/')

          group = Group.find_by_full_path(namespace)

          if group
            puts "Found the group: #{group.name}"

            return group
          end

          puts "The specified group is not found. Creating a new one..."

          current_user = User.find_by_username('root')
          org = create_org(current_user, namespace)
          group_params = {
            name: namespace,
            path: namespace,
            organization: org,
            visibility_level: org.visibility_level
          }
          response = Groups::CreateService.new(current_user, group_params).execute
          group = response[:group]

          raise "Failed to create a group: #{group.errors.full_messages}" if response.error?

          response[:group]
        end

        def create_org(current_user, namespace)
          response = ::Organizations::CreateService.new(
            current_user: current_user,
            params: { name: namespace, path: namespace, visibility_level: ::Gitlab::VisibilityLevel::PUBLIC }
          ).execute

          raise "Failed to create an org: #{response.errors}" if response.error?

          response[:organization]
        end

        # rubocop:disable Style/GuardClause -- Keep it explicit
        def ensure_dev_mode!
          unless ::Gitlab.dev_or_test_env?
            raise <<~MSG
              Setup can only be performed in development or test environment, however, the current environment is #{ENV['RAILS_ENV']}.
            MSG
          end
        end
        # rubocop:enable Style/GuardClause

        def set_token!
          @token = current_user.personal_access_tokens.create(scopes: ['api'], name: 'Automation token',
            expires_at: 1.day.from_now, organization: main_group.organization)
          @token_value = "token-string-#{SecureRandom.hex(10)}"
          @token.set_token(token_value)
          @token.save!
        end

        def clean_up_token!
          token.destroy!
        end

        def ensure_server_running!
          return true if Gitlab::HTTP.get(instance_url).success?

          raise 'Server is not running, please start your GitLab server'
        end

        def ensure_instance_setting!
          settings = Gitlab::CurrentSettings
          settings.import_sources << 'gitlab_project'
          settings.save!
        end

        def download_and_unpack_file
          download_path = Rails.root.join(DOWNLOAD_FOLDER, FILE_NAME)

          download_file(DOWNLOAD_URL, download_path)
          unzip_file(DOWNLOAD_FOLDER, FILE_NAME)

          FileUtils.rm(download_path)
        end

        def download_file(url, path)
          File.open(path, 'wb') do |file|
            file.write(Gitlab::HTTP.get(url).parsed_response)
          end
        end

        def unzip_file(download_folder, file_name)
          Dir.chdir(Rails.root.join(download_folder)) do
            `tar -xzvf #{file_name}`
          end
        end

        def create_subprojects
          STRUCTURE.each do |name, structure|
            structure[:projects].each do |project|
              project_file_name = "02_#{project.tr('-', '_')}.tar.gz"
              file = Rails.root.join(DOWNLOAD_FOLDER, SAMPLES_FOLDER, name, project_file_name)
              namespace = main_group.children.find_by(name: structure[:name]) # rubocop:disable CodeReuse/ActiveRecord -- we need to find a group by name
              create_subproject(name: project, file: file, namespace_id: namespace.id)
            end
          end
        end

        def create_subgroups
          STRUCTURE.each do |name, structure|
            file = Rails.root.join(DOWNLOAD_FOLDER, SAMPLES_FOLDER, name, GROUP_FILE_NAME)
            create_subgroup(name: structure[:name], file: file)
          end
        end

        def create_subgroup(params)
          url = "#{instance_url}#{GROUP_IMPORT_URL}"

          body = {
            name: params[:name],
            path: params[:name],
            file: File.new(params[:file]),
            parent_id: main_group.id,
            organization_id: main_group.organization_id
          }

          response = Gitlab::HTTP.post(url, headers: headers, body: body)

          errors << { group: params[:name] } unless response.success?

          puts "API response for #{params[:name]} import"
          puts response.parsed_response
        end

        def create_subproject(params)
          url = "#{instance_url}#{PROJECT_IMPORT_URL}"

          body = {
            name: params[:name],
            path: params[:name],
            file: File.new(params[:file]),
            namespace: params[:namespace_id]
          }

          response = Gitlab::HTTP.post(url, headers: headers, body: body)

          errors << { project: params[:name] } unless response.success?

          project_ids << response.parsed_response.fetch('id')
          puts "API response for #{params[:name]} import"
          puts response.parsed_response
        end

        def instance_url
          "#{Gitlab.config.gitlab.protocol}://#{Gitlab.config.gitlab.host}:#{Gitlab.config.gitlab.port}"
        end

        def delete_temporary_directory!
          FileUtils.rm_rf(Rails.root.join(DOWNLOAD_FOLDER, SAMPLES_FOLDER))
        end

        def headers
          {
            'PRIVATE-TOKEN' => token_value
          }
        end

        def check_import_status
          time_counter = 0
          imported_projects = project_ids.index_with { |_id| false }
          until imported_projects.values.all?
            break if time_counter > TIME_LIMIT

            imported_projects.each do |id, _status|
              puts "Checking import status for #{id}"

              check_status = Gitlab::HTTP.get("#{instance_url}/api/v4/projects/#{id}/import",
                headers: headers)

              if check_status.success? &&
                  check_status.parsed_response.fetch('import_status') == 'finished'
                imported_projects[id] = true
              end
            end
            time_counter += 5
            sleep 5
          end

          return if imported_projects.values.all?

          errors << { time_limit: "exceeded" }
        end

        def print_output
          puts <<~MSG
            ----------------------------------------
            Setup for evaluation Performed!
            ----------------------------------------

            Visit "#{Gitlab.config.gitlab.protocol}://#{Gitlab.config.gitlab.host}:#{Gitlab.config.gitlab.port}/#{main_group.full_path}"
            and please see if the subgroups structure looks like:
            |
            - gitlab-com
            |   - www-gitlab-com
            |
            - gitlab-org
            |   - gitlab

            #{if errors.empty?
                'The import has been successfully completed! You can start interacting with your evaluation datasets.'
              end}

            #{if errors.any?
                "The import has finished with errors for those resources: #{errors}. Please review the logs for more details."
              end}

          MSG
        end
      end
    end
  end
end
