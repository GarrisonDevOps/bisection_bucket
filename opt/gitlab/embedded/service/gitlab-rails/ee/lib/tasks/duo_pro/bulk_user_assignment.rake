# frozen_string_literal: true

namespace :duo_pro do
  desc 'Bulk user assignment for Code Suggestions'
  task :bulk_user_assignment, [:duo_pro_bulk_user_file_path] => :environment do |_t, args|
    file_path = args[:duo_pro_bulk_user_file_path] || ENV['DUO_PRO_BULK_USER_FILE_PATH']

    unless file_path
      raise <<~ERROR_MESSAGE.strip
      ================================================================================
      ## ERROR ##
      File path is not provided.#{' '}
      Please set the DUO_PRO_BULK_USER_FILE_PATH environment variable#{' '}
      or provide it as an argument.
      ================================================================================
      ERROR_MESSAGE
    end

    user_names = read_usernames_from_file(file_path)
    add_on_purchase = find_add_on_purchase

    unless add_on_purchase
      raise <<~ERROR_MESSAGE.strip
      ================================================================================
      ## ERROR ##
      Unable to find Duo Pro AddOn purchase.#{' '}
      Please ensure the necessary AddOn is already purchased and exists.
      ================================================================================
      ERROR_MESSAGE
    end

    result = GitlabSubscriptions::Duo::BulkUserAssignment.new(user_names, add_on_purchase).execute
    display_results(result)
  end

  private

  def read_usernames_from_file(file_path)
    CSV.read(file_path, headers: true).pluck('username')
  end

  def find_add_on_purchase
    GitlabSubscriptions::AddOnPurchase.for_gitlab_duo_pro.active.first
  end

  def display_results(result)
    puts "\nSuccessful Assignments:"
    puts result[:successful_assignments].join("\n")

    puts "\nFailed Assignments:"
    puts result[:failed_assignments].join("\n")
  end
end
