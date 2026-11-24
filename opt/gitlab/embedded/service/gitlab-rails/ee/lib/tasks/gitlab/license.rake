# frozen_string_literal: true

module Tasks
  class GitlabLicenseTasks
    include Rake::DSL

    def initialize
      namespace :gitlab do
        namespace :license do
          desc 'GitLab | License | Gather license related information'
          task info: :gitlab_environment do
            info
          end

          task :load, [:mode] => :environment do |_, args|
            args.with_defaults(mode: 'default')

            activation_code = ENV['GITLAB_ACTIVATION_CODE']

            if activation_code.present?
              activate(activation_code)
            else
              seed_license(args)
            end
          end
        end
      end
    end

    private

    def info
      license = ::License.current
      abort("No license has been applied.") unless license&.plan

      puts "Today's Date: #{Date.today}"
      puts "Current User Count: #{::Gitlab::Utils::UsageData.count(User.active)}"
      puts "Max Historical Count: #{license.historical_max}"
      puts "Max Users in License: #{license.seats}"
      puts "License valid from: #{license.starts_at} to #{license.expires_at}"
      puts "Email associated with license: #{license.licensee_email}"
    end

    # TODO: Alter explanation text in verbose mode, after
    # https://gitlab.com/gitlab-org/customers-gitlab-com/-/issues/5904 is enabled in production
    def activate(activation_code)
      result = ::GitlabSubscriptions::ActivateService.new.execute(activation_code, automated: true)
      if result[:success]
        puts Rainbow('Activation successful').green
      else
        puts Rainbow('Activation unsuccessful').red
        puts Rainbow(Array(result[:errors]).join(' ')).red
        raise 'Activation unsuccessful'
      end
    end

    def seed_license(args)
      flag = 'GITLAB_LICENSE_FILE'
      default_license_file = Settings.source.dirname + 'Gitlab.gitlab-license'
      license_file = ENV.fetch(flag, default_license_file)

      if File.file?(license_file)
        begin
          license = ::License.create!(data: File.read(license_file))
          puts Rainbow("License Added:\n\nFilePath: #{license_file}").green
        rescue ::Gitlab::License::Error, ActiveRecord::RecordInvalid
          puts Rainbow("License Invalid:\n\nFilePath: #{license_file}").red
          raise "License Invalid"
        end

        license.schedule_add_on_purchases_provisioning
      elsif ENV[flag].present?
        puts Rainbow("License File Missing:\n\nFilePath: #{license_file}").red
        raise "License File Missing"
      elsif args[:mode] == 'verbose'
        puts "Skipped. Use the `#{flag}` environment variable to seed the License file of the given path."
      end
    end
  end
end

Tasks::GitlabLicenseTasks.new
