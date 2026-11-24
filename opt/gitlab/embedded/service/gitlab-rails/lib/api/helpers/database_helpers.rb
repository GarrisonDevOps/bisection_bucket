# frozen_string_literal: true

module API
  module Helpers
    module DatabaseHelpers
      def base_model
        database = params[:database] || Gitlab::Database::MAIN_DATABASE_NAME
        model = Gitlab::Database.database_base_models[database]

        not_found!("Database '#{database}' is not configured") unless model

        model
      end
    end
  end
end
