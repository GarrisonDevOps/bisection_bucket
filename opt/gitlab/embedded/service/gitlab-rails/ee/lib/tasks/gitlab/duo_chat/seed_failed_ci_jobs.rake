# frozen_string_literal: true

desc 'Seed failed CI jobs for /troubleshoot inside the evaluation structure using FactoryBot'
namespace :gitlab do
  namespace :duo_chat do
    namespace :seed do
      task failed_ci_jobs: :environment do
        def fetch_dataset_from_langsmith
          langchain_endpoint = ENV['LANGCHAIN_ENDPOINT'] || 'https://api.smith.langchain.com'
          dataset_version = ENV['RCA_DATASET_VERSION'] || '1'
          langchain_api_key = ENV['LANGCHAIN_API_KEY']

          unless langchain_api_key
            puts "Missing LANGCHAIN_API_KEY environment variable!"
            return []
          end

          version_to_id_mapping = {
            '1' => 'cdba1bb8-8234-4a70-8524-c33dee5a1570'
          }

          dataset_id = version_to_id_mapping[dataset_version]

          unless dataset_id
            available_versions = version_to_id_mapping.keys.join(', ')
            puts "Unknown dataset version: #{dataset_version}. Available versions: #{available_versions}"
            return []
          end

          uri = URI("#{langchain_endpoint}/api/v1/datasets/#{dataset_id}/jsonl")
          request = Net::HTTP::Get.new(uri)
          request['X-API-Key'] = langchain_api_key
          request['Content-Type'] = 'application/json'

          response = Net::HTTP.start(uri.hostname, uri.port, use_ssl: true) { |http| http.request(request) }

          unless response.is_a?(Net::HTTPSuccess)
            puts "Failed to fetch dataset: #{response.code} #{response.message}"
            puts "Response body: #{response.body}"
            return []
          end

          dataset = []
          response.body.each_line do |line|
            json_line = ::Gitlab::Json::SafeParser.parse(line)
            job_id = json_line.dig('inputs', 'job_id')
            trace = json_line.dig('inputs', 'trace')

            dataset << { 'input_job_id' => job_id, 'input_trace' => trace } if job_id && trace
          rescue JSON::ParserError => e
            puts "Error parsing JSONL line: #{e.message}"
          end

          dataset
        rescue StandardError => e
          puts "Error fetching dataset from LangSmith: #{e.message}"
          []
        end

        def ensure_group_and_project(username, group_path, project_path, project_clone_url)
          puts "Ensuring group: #{group_path} and project: #{project_path} exist..."

          user = User.find_by(username: username)
          organization = user&.organizations&.first

          group = Group.find_by(path: group_path) ||
            FactoryBot.create(:group, :public, path: group_path,
              name: group_path.humanize, organization: organization)

          group.add_owner(user) unless group.owners.include?(user)

          project = Project.find_by(path: project_path, namespace: group) ||
            FactoryBot.create(:project, :public, path: project_path,
              name: project_path.humanize, creator: user, namespace: group)

          project.add_owner(user) unless project.owners.include?(user)

          ensure_repository(project, project_clone_url)

          project
        end

        def ensure_repository(project, project_clone_url)
          repo = project.repository
          return if repo.exists?

          puts "Creating repository for #{project.full_path}..."
          create_git_bundle(project_clone_url) do |bundle_path|
            repo.create_from_bundle(bundle_path)
          end
        end

        def create_git_bundle(project_clone_url)
          Dir.mktmpdir('git_bundle') do |dir|
            repo_path = "#{dir}/ai-evaluation/rca"
            repo_bundle_path = "#{repo_path}.bundle"

            system(*%W[#{Gitlab.config.git.bin_path} clone --mirror #{project_clone_url} #{repo_path}])
            system(*%W[#{Gitlab.config.git.bin_path} -C #{repo_path} bundle create #{repo_bundle_path} --all])

            yield repo_bundle_path
          end
        end

        def create_failed_job(entry, project, user)
          return if project.nil?

          job_id = entry['input_job_id'].to_i
          trace_data = entry['input_trace']
          partition_id = Ci::Pipeline.current_partition_value

          puts "Seeding failed job ID: #{job_id} in #{project.full_path}..."

          sha = project.repository&.commit&.sha

          FactoryBot.create(:ci_pipeline, status: :failed, project: project,
            ref: 'main', sha: sha, partition_id: partition_id, user: user).tap do |pipeline|
            FactoryBot.create(:ci_stage, :failed, pipeline: pipeline, name: 'test').tap do |stage|
              FactoryBot.create(:ci_build, :failed, pipeline: pipeline, ci_stage: stage,
                stage_idx: 1, project: project, user: user, partition_id: partition_id).tap do |build|
                build.update_column(:id, job_id)
                build.trace.set(trace_data)
              end
            end
          end
          puts "Created failed job ID: #{job_id}"
        end

        username = 'root'
        group_path = 'ai-evaluation'
        project_path = 'rca'
        project_clone_url = "https://gitlab.com/gitlab-org/modelops/ai-model-validation-and-research/ai-evaluation/test-repo.git"

        dataset = fetch_dataset_from_langsmith
        project = ensure_group_and_project(username, group_path, project_path, project_clone_url)
        dataset.each { |entry| create_failed_job(entry, project, User.find_by(username: username)) }

        puts "Seeding complete! Created #{dataset.size} failed jobs."
      end
    end
  end
end
