# frozen_string_literal: true

namespace :gitlab_subscriptions do
  namespace :duo do
    desc 'Bulk user assignment for Duo'
    task :bulk_user_assignment, [:duo_bulk_user_file_path, :namespace_id] => :environment do |_t, args|
      file_path = args[:duo_bulk_user_file_path] || ENV['DUO_BULK_USER_FILE_PATH']
      namespace_id = args[:namespace_id] || ENV['NAMESPACE_ID']

      unless file_path.present? && File.exist?(file_path)
        raise <<~ERROR_MESSAGE.strip
        =================================================================================
        ## ERROR ##
        File path is invalid.
        Please specify a valid file path by setting the DUO_BULK_USER_FILE_PATH
        environment variable or by providing it as an argument.
        ================================================================================
        ERROR_MESSAGE
      end

      user_names = CSV.read(file_path, headers: true).pluck('username')

      add_on_purchase = if ::GitlabSubscriptions::SubscriptionHelper.gitlab_com_subscription?
                          unless namespace_id.present?
                            raise <<~ERROR_MESSAGE.strip
                            ================================================================================
                            ## ERROR ##
                            Namespace ID is not provided.
                            Please set the NAMESPACE_ID environment variable
                            or provide it as an argument.
                            ================================================================================
                            ERROR_MESSAGE
                          end

                          namespace = Namespace.find_by(id: namespace_id)

                          unless namespace.present?
                            raise <<~ERROR_MESSAGE.strip
                            ================================================================================
                            ## ERROR ##
                            Namespace not found.
                            Please provide a valid NAMESPACE_ID for an existing namespace.
                            ================================================================================
                            ERROR_MESSAGE
                          end

                          puts "\nNamespace found: #{namespace.full_path}"

                          ::GitlabSubscriptions::AddOnPurchase.by_namespace(namespace)
                            .for_duo_pro_or_duo_enterprise.active.first
                        else
                          ::GitlabSubscriptions::AddOnPurchase.for_self_managed
                            .for_duo_pro_or_duo_enterprise.active.first
                        end

      unless add_on_purchase.present?
        raise <<~ERROR_MESSAGE.strip
        ================================================================================
        ## ERROR ##
        Unable to find Duo add-on purchase.
        Please ensure the necessary add-on is already purchased and exists.
        ================================================================================
        ERROR_MESSAGE
      end

      result = ::GitlabSubscriptions::Duo::BulkUserAssignment.new(user_names, add_on_purchase).execute

      puts "\nSuccessful Assignments:"
      puts result[:successful_assignments].join("\n")

      puts "\nFailed Assignments:"
      puts result[:failed_assignments].join("\n")
    end
  end
end
