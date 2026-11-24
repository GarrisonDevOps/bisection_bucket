# frozen_string_literal: true

require 'net/http'
require 'json'
require 'ruby-progressbar'
require 'yaml'

module Gitlab
  module Duo
    module Developments
      class FixPipelineSeeder
        GROUP_PATH = 'gitlab-duo'
        PROJECT_PATH = 'fix_pipeline_evaluation'
        PAUSE_FOR_UPDATES_IN_SECONDS = 10

        def self.seed_pipelines(output_file: 'fix_pipeline_evaluation_pipelines.yml')
          import_url = "gitlab-org/duo-workflow/test-project-playground/roman-fix-pipeline-examples/ai-gateway"

          evaluation_seed_data = fetch_dataset_from_langsmith

          gdk_url = Gitlab.config.gitlab.url

          puts "Checking environment variables for Personal Access Tokens..."

          abort "Error: You must set the GDK_PAT environment variable." unless ENV['GDK_PAT']
          gdk_token = ENV['GDK_PAT']

          abort "Error: You must set the GITLAB_COM_PAT environment variable." unless ENV['GITLAB_COM_PAT']
          gitlab_token = ENV['GITLAB_COM_PAT']

          puts "Seeding fix_pipeline evaluations..."

          user = find_root_user

          namespace = Namespace.find_by_full_path(GROUP_PATH)
          abort "Error: Namespace '#{GROUP_PATH}' not found" unless namespace

          delete_project_if_exists "#{GROUP_PATH}/#{PROJECT_PATH}", user

          puts "Importing project '#{PROJECT_PATH}' from #{import_url}..."
          puts "Into Namespace: #{namespace.full_path}"

          import_gitlab_project(gdk_url, gdk_token, gitlab_token, import_url)

          created_project = Project.find_by_full_path("#{GROUP_PATH}/#{PROJECT_PATH}")
          if created_project
            puts "Project created successfully: #{created_project.full_path}"
          else
            abort "Error: Could not load project: #{PROJECT_PATH}"
          end

          evaluation_data = create_evaluation_data(evaluation_seed_data, created_project)

          puts "Successfully loaded #{evaluation_seed_data.size} log traces."

          create_evaluation_yaml(evaluation_data, output_file)

          puts "Successfully saved evaluation data to #{output_file}"
          puts "Seeding task complete."
        end

        def self.create_evaluation_data(evaluation_seed_data, created_project)
          evaluation_data = []
          evaluation_seed_data.each do |data_row|
            merge_request_path = data_row["merge_request_path"]
            fix_type = data_row["type"]
            job_name = data_row["job_name"]
            job_trace = data_row["job_trace"]

            puts "    Importing example: #{fix_type}"

            unless job_name
              puts "       ...Skipping..."
              next
            end

            merge_request_iid = merge_request_path.split("/").last

            merge_request = created_project.merge_requests.find_by_iid(merge_request_iid)

            pipeline = merge_request.pipelines_for_merge_request.last
            abort "Pipeline not found!" unless pipeline

            job = pipeline.all_jobs.find_by_name(job_name)
            abort "Job not found: #{job_name}" unless job

            job.trace.set(job_trace)

            pipeline_url = Rails.application.routes.url_helpers.project_pipeline_url(created_project, pipeline)
            data_row["pipeline_url"] = pipeline_url
            data_row.delete("job_trace")
            evaluation_data << data_row
          end

          evaluation_data
        end
        private_class_method :create_evaluation_data

        def self.fetch_dataset_from_langsmith
          langchain_endpoint = ENV['LANGCHAIN_ENDPOINT'] || 'https://api.smith.langchain.com'
          dataset_id = ENV['DATASET_ID'] || '9e2ce43a-307e-4a02-bf19-4cca6571e893'
          langchain_api_key = ENV['LANGCHAIN_API_KEY']

          abort "Missing LANGCHAIN_API_KEY environment variable!" unless langchain_api_key

          uri = URI("#{langchain_endpoint}/api/v1/datasets/#{dataset_id}/jsonl")
          request = Net::HTTP::Get.new(uri)
          request['X-API-Key'] = langchain_api_key
          request['Content-Type'] = 'application/json'

          response = Net::HTTP.start(uri.hostname, uri.port, use_ssl: true) { |http| http.request(request) }

          unless response.is_a?(Net::HTTPSuccess)
            puts "Failed to fetch dataset: #{response.code} #{response.message}"
            abort "Response body: #{response.body}"
          end

          dataset = []
          response.body.each_line do |line|
            json_line = ::Gitlab::Json.safe_parse(line)

            data_row = json_line['inputs'].merge(json_line['outputs'])
            dataset << data_row
          rescue JSON::ParserError => e
            abort "Error parsing JSONL line: #{e.message}"
          end

          dataset
        rescue StandardError => e
          abort "Error fetching dataset from LangSmith: #{e.message}"
        end
        private_class_method :fetch_dataset_from_langsmith

        def self.import_gitlab_project(gdk_url, gdk_token, gitlab_token, import_url)
          uri = URI("#{gdk_url}/api/v4/bulk_imports")

          request_body = {
            configuration: {
              url: "https://gitlab.com",
              access_token: gitlab_token
            },
            entities: [
              {
                source_full_path: import_url,
                source_type: "project_entity",
                destination_slug: PROJECT_PATH,
                destination_namespace: GROUP_PATH,
                migrate_projects: true
              }
            ]
          }

          request = Net::HTTP::Post.new(uri)
          request['Content-Type'] = 'application/json'
          request['PRIVATE-TOKEN'] = gdk_token
          request.body = request_body.to_json

          response = Net::HTTP.start(uri.hostname, uri.port, use_ssl: uri.scheme == 'https') do |http|
            http.request(request)
          end

          unless response.is_a?(Net::HTTPSuccess)
            abort "Error importing project: #{response.code} #{response.message}\nResponse: #{response.body}"
          end

          response_data = ::Gitlab::Json.safe_parse(response.body)
          puts response.body
          puts "Import initiated. Please be patient, this can take up to 15 min in your GDK...\n\n\n"

          bulk_import_id = response_data['id']
          bulk_import = BulkImport.find bulk_import_id
          wait_for_import_completion bulk_import
        end
        private_class_method :import_gitlab_project

        def self.find_root_user
          user = User.find_by_username('root')
          abort "Error: Root user not found. Please ensure the development environment is properly set up." unless user

          user
        end
        private_class_method :find_root_user

        def self.delete_project_if_exists(full_project_path, user)
          existing_project = Project.find_by_full_path(full_project_path)

          return unless existing_project

          puts "Project '#{existing_project.full_path}' already exists. Deleting..."
          Projects::MarkForDeletionService.new(existing_project, user).execute
          sleep PAUSE_FOR_UPDATES_IN_SECONDS
          puts "Existing project deleted."
        end
        private_class_method :delete_project_if_exists

        def self.create_evaluation_yaml(job_trace_data, output_file)
          safe_path = File.expand_path(File.basename(output_file))
          File.write(safe_path, job_trace_data.to_yaml)
        end
        private_class_method :create_evaluation_yaml

        def self.wait_for_import_completion(bulk_import, timeout: 1000)
          progressbar = ProgressBar.create(
            title: "Importing Project",
            total: 4, # initiated, created, started, finished
            format: "%t: |%B| %c/%C (%P%%) %E"
          )
          progressbar.log("Status: initiated")
          progressbar.increment

          start_time = Time.current
          last_status = nil
          loop do
            bulk_import.reset

            status = bulk_import.status_name
            if status != last_status
              progressbar.log("Status: #{status}")
              progressbar.increment
              last_status = status
            end

            if bulk_import.completed?
              if status != :finished
                progressbar.log "Import Error"
                abort "Import completed without finished status. Status: #{status}" unless status == :finished
              end

              progressbar.log "Finished Import"
              progressbar.finish

              return
            end

            abort "Import timed out after #{timeout} seconds" if Time.current - start_time > timeout
            sleep PAUSE_FOR_UPDATES_IN_SECONDS

            progressbar.progress = progressbar.progress # rubocop:disable Lint/SelfAssignment -- This refreshes the display and ETA without incrementing the bar
          end
        end
        private_class_method :wait_for_import_completion
      end
    end
  end
end
