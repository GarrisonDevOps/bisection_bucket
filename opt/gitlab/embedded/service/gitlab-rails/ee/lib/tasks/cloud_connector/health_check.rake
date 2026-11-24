# frozen_string_literal: true

namespace :cloud_connector do
  desc 'GitLab | Cloud Connector | Health check'
  task :health_check, [:username, :filename, :include_details] => :environment do |_, args|
    user = Tasks::CloudConnector::TaskHelper.find_user(args.username)

    probe_results = CloudConnector::StatusChecks::StatusService.new(user: user).execute[:probe_results]
    include_details = Gitlab::Utils.to_boolean(args.include_details, default: true)
    Tasks::CloudConnector::TaskHelper.process_probe_results(probe_results, include_details: include_details)

    Tasks::CloudConnector::TaskHelper.save_report(args.filename, probe_results)
  end
end
