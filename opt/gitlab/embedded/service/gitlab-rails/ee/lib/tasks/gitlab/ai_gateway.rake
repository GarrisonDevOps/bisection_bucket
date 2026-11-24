# frozen_string_literal: true

namespace :gitlab do
  namespace :ai_gateway do
    desc 'GitLab | AI Gateway | Install'
    task :install, [:path] => :gitlab_environment do |_, args|
      ::Tasks::Gitlab::AiGateway::Utils.install_with_retry(**args)
    end
  end
end
