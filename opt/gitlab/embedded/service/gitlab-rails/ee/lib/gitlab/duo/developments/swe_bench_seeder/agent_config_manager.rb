# frozen_string_literal: true

module Gitlab
  module Duo
    module Developments
      class SweBenchSeeder
        class AgentConfigManager
          AGENT_CONFIG_PATH = File.join(__dir__, 'agent_configs.yml')
          IMAGE_NAMESPACE = 'registry.gitlab.com/gitlab-org/modelops/ai-model-validation-and-research/' \
            'ai-evaluation/swebench-images/prebaked'
          IMAGE_ARCH = 'x86_64'
          IMAGE_TAG = 'prebaked-v1'

          def self.swebench_image_for(instance_id)
            return unless instance_id.to_s.include?('__')

            key = "sweb.eval.#{IMAGE_ARCH}.#{instance_id.downcase}:#{IMAGE_TAG}"
            "#{IMAGE_NAMESPACE}/#{key}".gsub('__', '_1776_')
          end

          def self.commit_agent_config(project, user, instance_id:)
            image = swebench_image_for(instance_id)
            config = agent_config(image: image)
            return unless config

            puts "  Adding agent-config.yml"

            project.reset
            content = YAML.dump(config).delete_prefix("---\n")
            default_branch = project.repository.root_ref || project.default_branch_or_main

            config_path = '.gitlab/duo/agent-config.yml'
            head_commit = project.repository.commit(default_branch)
            file_exists = head_commit && project.repository.blob_at(head_commit.sha, config_path)

            if file_exists
              project.repository.update_file(
                user,
                config_path,
                content,
                message: 'Update SWE-bench environment configuration for Duo flows',
                branch_name: default_branch
              )
            else
              project.repository.create_file(
                user,
                config_path,
                content,
                message: 'Add SWE-bench environment configuration for Duo flows',
                branch_name: default_branch
              )
            end

            action = file_exists ? 'Updated' : 'Committed'
            puts "  #{action} .gitlab/duo/agent-config.yml to #{default_branch}"
          end

          def self.agent_config(image: nil)
            base = YAML.safe_load(File.read(AGENT_CONFIG_PATH)) || {}
            base['image'] = image if image.present?
            base
          end
        end
      end
    end
  end
end
